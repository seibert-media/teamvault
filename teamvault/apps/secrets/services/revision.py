from hashlib import sha256
from json import dumps
from typing import Any

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from teamvault.apps.audit.auditlog import log
from teamvault.apps.audit.models import AuditLogCategoryChoices
from teamvault.apps.secrets.enums import ContentType, SecretStatus
from teamvault.apps.secrets.models import (
    AccessPermissionTypes,
    Secret,
    SecretMetaSnapshot,
    SecretRevision,
)
from teamvault.apps.secrets.utils import apply_meta_to_secret, copy_meta_from_secret, meta_changed


class RevisionService:
    """Central orchestration logic for Secret revisions & metadata snapshots."""

    @staticmethod
    def _fernet():
        """Return a Fernet instance built from the *current* settings key.
        This plays nicely with Django’s `override_settings()` in tests."""
        return Fernet(settings.TEAMVAULT_SECRET_KEY)

    @classmethod
    @transaction.atomic
    def save_payload(
        cls,
        *,
        secret: Secret,
        actor,  # settings.AUTH_USER_MODEL
        payload: dict[str, Any],
        skip_acl: bool = False,
    ) -> SecretRevision:
        """Create or reuse a payload revision, make it current & snapshot metadata
        if necessary.
        """
        if not skip_acl and secret.permission_checker(actor).is_readable() == AccessPermissionTypes.NOT_ALLOWED:
            raise PermissionDenied('User has no write access to secret payload')

        # 1. Build (or fetch) the revision representing _payload_
        revision = cls._build_revision(secret=secret, actor=actor, payload=payload)
        payload_changed = cls._payload_changed(secret=secret, payload=payload)

        # 2. Update Secret pointers/flags
        previous_id = secret.current_revision_id or 'none'
        secret.current_revision = revision
        secret.last_changed = now()
        secret.last_read = now()
        secret.status = SecretStatus.OK if secret.status == SecretStatus.NEEDS_CHANGING else secret.status
        secret.save(update_fields=['current_revision', 'last_changed', 'last_read', 'status'])

        # 3. Ensure we have an up‑to‑date metadata snapshot
        baseline_missing = not SecretMetaSnapshot.objects.filter(secret=secret).exists()
        if baseline_missing or (meta_changed(secret) and not payload_changed):
            cls.snapshot(secret=secret, actor=actor, revision=revision)

        # 4. Audit log
        log(
            _("{user} set a new secret for '{name}' ({oldrev}->{newrev})").format(
                user=actor.username,
                name=secret.name,
                oldrev=previous_id,
                newrev=revision.id,
            ),
            actor=actor,
            category=AuditLogCategoryChoices.SECRET_CHANGED,
            level='info',
            secret=secret,
            secret_revision=revision,
        )
        return revision

    @classmethod
    def snapshot(
        cls,
        *,
        secret: Secret,
        actor,
        revision: SecretRevision | None = None,
    ) -> SecretMetaSnapshot:
        """Freeze the current metadata of secret into an immutable
        :class:`SecretMetaSnapshot`.
        """
        revision = revision or secret.current_revision
        if revision is None:
            raise ValueError('Secret has no current revision to snapshot')

        snap = SecretMetaSnapshot.objects.create(
            secret=secret,
            revision=revision,
            set_by=actor,
            **copy_meta_from_secret(secret),
        )
        return snap

    @classmethod
    @transaction.atomic
    def restore(
        cls,
        *,
        secret: Secret,
        actor,
        old_revision: SecretRevision,
        meta_snap: SecretMetaSnapshot | None = None,
    ) -> SecretRevision:
        """Turn old_revision (and optional meta_snap) into the new current
        revision. Only superusers may call this.
        """
        if secret.pk != old_revision.secret_id:
            raise ValueError('Revision does not belong to secret')

        chk = secret.permission_checker(actor)
        if chk.is_readable() != AccessPermissionTypes.SUPERUSER_ALLOWED:
            raise PermissionDenied('User may not restore revisions')

        # create or reuse revision w/ identical payload
        new_rev = SecretRevision._create_from_revision(
            old_revision=old_revision,
            set_by=actor,
            meta_snapshot=meta_snap,
            skip_access_check=True,
        )

        # sync metadata from chosen snapshot (or latest)
        snapshot = meta_snap or new_rev.latest_meta
        apply_meta_to_secret(secret, snapshot)

        secret.current_revision = new_rev
        secret.last_changed = now()
        secret.save(update_fields=['current_revision', 'last_changed'])

        return new_rev

    @classmethod
    def _payload_changed(cls, *, secret: Secret, payload: dict[str, Any]) -> bool:
        """Compare payload hash to secret.current_revision."""
        if secret.current_revision is None:
            return True
        sha_src = (
            payload['password']
            if secret.content_type == ContentType.PASSWORD and 'password' in payload
            else dumps(payload, sort_keys=True)
        )
        return sha256(sha_src.encode()).hexdigest() != secret.current_revision.plaintext_data_sha256

    @classmethod
    def _build_revision(
        cls,
        *,
        secret: Secret,
        actor,
        payload: dict[str, Any],
    ) -> SecretRevision:
        """Return an existing revision for payload or create a new one."""
        content_type = secret.content_type

        # merge missing fields for PASSWORD type
        if content_type == ContentType.PASSWORD and secret.current_revision:
            prev = secret.current_revision.get_data(actor)
            payload.setdefault('password', prev.get('password'))
            if 'otp_key' in prev:
                for fld in ('otp_key', 'digits', 'algorithm'):
                    payload.setdefault(fld, prev.get(fld))

        sha_src = (
            payload['password']
            if content_type == ContentType.PASSWORD and 'password' in payload
            else dumps(payload, sort_keys=True)
        )
        sha_sum = sha256(sha_src.encode()).hexdigest()

        revision, created = SecretRevision.objects.get_or_create(
            secret=secret,
            plaintext_data_sha256=sha_sum,
            defaults={'set_by': actor},
        )

        if created:
            revision.length = (
                len(payload['password'])
                if content_type == ContentType.PASSWORD and 'password' in payload
                else len(payload)
            )
            revision.encrypted_data = cls._fernet().encrypt(dumps(payload).encode())
            revision.otp_key_set = 'otp_key' in payload
            # copy current secret meta
            for fld in (
                'description',
                'username',
                'url',
                'filename',
                'access_policy',
                'needs_changing_on_leave',
                'status',
            ):
                setattr(revision, fld, getattr(secret, fld))
            revision.save()

        revision.accessed_by.add(actor)
        return revision
