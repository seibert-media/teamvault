from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from json import dumps
from typing import Any, Literal

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from teamvault.apps.audit.auditlog import log
from teamvault.apps.audit.models import AuditLogCategoryChoices
from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.models import (
    AccessPermissionTypes,
    Secret,
    SecretMetaSnapshot,
    SecretRevision,
    SecretChange,
)
from teamvault.apps.secrets.utils import apply_meta_to_secret, copy_meta_from_secret, meta_changed


@dataclass
class HistoryEntry:
    ts: datetime
    kind: Literal['payload', 'meta', 'restore']
    user: str
    name: str
    changes: list[dict[str, str]]
    link: str
    current: bool
    snapshot: SecretMetaSnapshot | None
    needs_changing: bool = False
    restored_from: str | None = None


class RevisionService:
    """Central orchestration logic for revisions, metadata snapshots and
    the SecretChange graph.

    Invariants:
    - Every save_payload/restore produces a SecretChange node.
    - Each SecretRevision referenced by a change has at least one snapshot
      representing metadata at that moment (baseline per revision).
    - History and UI derive exclusively from SecretChange; we no longer infer
      chronology from mixed audit logs or snapshot timing.
    """

    @staticmethod
    def _fernet():
        """Return a Fernet instance built from the *current* settings key.
        This plays nicely with Django's `override_settings()` in tests."""
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
        """Create or reuse a payload revision, set it current, ensure a revision
        snapshot exists for current metadata, and record a SecretChange.
        """
        if not skip_acl and secret.permission_checker(actor).is_readable() == AccessPermissionTypes.NOT_ALLOWED:
            raise PermissionDenied('User has no write access to secret payload')

        # 1. Build (or fetch) the revision representing _payload_
        revision = cls._build_revision(secret=secret, actor=actor, payload=payload)
        payload_changed = revision.plaintext_data_sha256 != (
            secret.current_revision.plaintext_data_sha256 if secret.current_revision_id else None
        )

        # 2. Update Secret pointers/flags
        previous_id = secret.current_revision_id or 'none'
        secret.current_revision = revision
        secret.last_changed = now()
        secret.last_read = now()
        # Only clear NEEDS_CHANGING when payload actually changes
        if payload_changed and secret.status == SecretStatus.NEEDS_CHANGING:
            secret.status = SecretStatus.OK
        secret.save(update_fields=['current_revision', 'last_changed', 'last_read', 'status'])

        # 3. Ensure we have a snapshot for THIS revision at this time
        baseline_missing_for_rev = not SecretMetaSnapshot.objects.filter(revision=revision).exists()
        if baseline_missing_for_rev or meta_changed(secret):
            cls.snapshot(secret=secret, actor=actor, revision=revision)
        if not SecretMetaSnapshot.objects.filter(revision=revision).exists():
            cls.snapshot(secret=secret, actor=actor, revision=revision)

        # 4. Audit log
        log_category = AuditLogCategoryChoices.SECRET_CHANGED if payload_changed else AuditLogCategoryChoices.SECRET_METADATA_CHANGED
        log(
            _("{user} set a new {type} for '{name}' ({oldrev}->{newrev})").format(
                user=actor.username,
                name=secret.name,
                type='secret' if payload_changed else 'metadata',
                oldrev=previous_id,
                newrev=revision.id,
            ),
            actor=actor,
            category=log_category,
            level='info',
            secret=secret,
            secret_revision=revision,
        )
        # 5. Record a SecretChange node
        snap_for_change = SecretMetaSnapshot.objects.filter(revision=revision).latest('created')
        parent = SecretChange.objects.filter(secret=secret).order_by('-created').first()
        change = SecretChange.objects.create(
            secret=secret,
            revision=revision,
            snapshot=snap_for_change,
            actor=actor,
        )
        if parent:
            change.parents.add(parent)

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

        raw = dumps(copy_meta_from_secret(secret), sort_keys=True, default=str)
        meta_sha256 = sha256(raw.encode()).hexdigest()
        snap, _ = SecretMetaSnapshot.objects.get_or_create(
            revision=revision,
            meta_sha256=meta_sha256,
            defaults={'set_by': actor, **copy_meta_from_secret(secret)},
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
        """Make old_revision (and optional meta_snap) the new current revision,
        apply metadata, and record a SecretChange with restored_from linking to
        the source change. Allowed for users who can edit the secret.
        """
        if secret.pk != old_revision.secret_id:
            raise ValueError('Revision does not belong to secret')

        chk = secret.permission_checker(actor)
        # Permit restore to anyone who can edit (same gate as save_payload)
        if chk.is_readable() == AccessPermissionTypes.NOT_ALLOWED:
            raise PermissionDenied('User may not restore revisions')

        # create or reuse revision w/ identical payload
        new_rev = SecretRevision._create_from_revision(
            old_revision=old_revision,
            set_by=actor,
            meta_snapshot=meta_snap,
            skip_access_check=True,
        )
        # Chronology is modeled via SecretChange.restored_from; do not mutate
        # SecretRevision rows when restoring.

        # sync metadata from chosen snapshot (or latest)
        snapshot = meta_snap or new_rev.latest_meta

        changed_fields = apply_meta_to_secret(secret, snapshot)
        if snapshot and snapshot.status == SecretStatus.NEEDS_CHANGING:
            if 'status' not in changed_fields:
                changed_fields.append('status')
            secret.status = SecretStatus.NEEDS_CHANGING

        # restored revisions don't have a snapshot yet
        if snapshot is None:
            snapshot = cls.snapshot(secret=secret, actor=actor, revision=new_rev)

        secret.current_revision = new_rev
        secret.last_changed = now()
        secret.save(update_fields=['current_revision', 'last_changed', *changed_fields])

        log(
            _("{user} restored '{name}' from revision {rev} to create revision {new_rev}").format(
                user=actor.username,
                name=secret.name,
                rev=old_revision.id,
                new_rev=new_rev.id,
            ),
            actor=actor,
            category=AuditLogCategoryChoices.SECRET_RESTORED,
            level='warning',
            secret=secret,
            secret_revision=new_rev,
            reason=f'Restored from revision {old_revision.id}',
        )
        # Record SecretChange for restore
        snap_for_change = SecretMetaSnapshot.objects.filter(revision=new_rev).latest('created')
        parent = SecretChange.objects.filter(secret=secret).order_by('-created').first()
        restored_from_change = (
            SecretChange.objects.filter(secret=secret, revision=old_revision)
            .order_by('-created')
            .first()
        )
        change = SecretChange.objects.create(
            secret=secret,
            revision=new_rev,
            snapshot=snap_for_change,
            actor=actor,
            restored_from=restored_from_change,
        )
        if parent:
            change.parents.add(parent)

        return new_rev

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
            prev = secret.current_revision.peek_data(actor)
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
            revision.save()

        revision.accessed_by.add(actor)
        return revision

    @classmethod
    def get_revision_history(cls, secret: Secret, user) -> list[HistoryEntry]:
        """History built from SecretChange graph."""
        changes = list(
            SecretChange.objects.filter(secret=secret)
            .select_related('actor', 'revision', 'snapshot')
            .order_by('created')
        )
        rows: list[HistoryEntry] = []
        prev = None

        for ch in changes:
            payload_changes = cls._get_payload_diff(ch.revision, prev.revision if prev else None, user)
            meta_changes = cls._get_meta_diff(ch.snapshot, prev.snapshot if prev else None)

            # Determine kind
            kind = 'restore' if ch.restored_from_id else ('payload' if payload_changes else 'meta')
            # Merge changes: payload first for readability
            merged = []
            merged.extend(payload_changes)
            merged.extend(meta_changes)

            # Determine link + current flags
            if kind == 'meta' and ch.snapshot and secret.current_revision and ch.snapshot.hashid == getattr(secret.current_revision.latest_meta, 'hashid', None):
                link = secret.get_absolute_url()
                current = True
            else:
                base_link = reverse('secrets.revision-detail', args=[ch.revision.hashid])
                if kind == 'meta' and ch.revision_id != secret.current_revision_id:
                    link = f"{base_link}?meta_snap={ch.snapshot.id}&change={ch.id}"
                else:
                    link = f"{base_link}?change={ch.id}"
                current = (kind != 'meta' and ch.revision_id == secret.current_revision_id)

            rows.append(
                HistoryEntry(
                    ts=ch.created,
                    kind=kind,  # type: ignore
                    user=ch.actor.username,
                    name=secret.name,
                    changes=merged,
                    link=link,
                    current=current,
                    snapshot=ch.snapshot,
                    needs_changing=(ch.snapshot.status == SecretStatus.NEEDS_CHANGING),
                    restored_from=(
                        ch.restored_from.revision.hashid if ch.restored_from_id else None
                    ),
                )
            )
            prev = ch

        return sorted(rows, key=lambda e: e.ts, reverse=True)


    @staticmethod
    def _render_field_label(field_name: str) -> str:
        """Convert field names to human-readable labels."""
        mapping = {
            'access_policy': 'AccessPolicy',
            'status': 'SecretStatus',
            'needs_changing_on_leave': 'NeedsChanging',
        }
        return mapping.get(field_name, field_name.capitalize())

    @staticmethod
    def _render_field_value(value, field_name: str) -> str:
        """Convert field values to human-readable format."""
        if value in ('', None):
            return '∅'
        if field_name == 'access_policy':
            return AccessPolicy(value).name
        if field_name == 'status':
            return SecretStatus(value).name
        return str(value)

    @classmethod
    def _get_meta_diff(cls, new_obj, prev_obj) -> list[dict]:
        """Compare metadata between two objects and return differences."""
        fields = (
            'name',
            'description',
            'username',
            'url',
            'filename',
            'access_policy',
            'status',
            'needs_changing_on_leave',
        )

        diffs = []
        for field in fields:
            old_val = getattr(prev_obj, field, None) if prev_obj else None
            new_val = getattr(new_obj, field, None)

            if old_val != new_val:
                diffs.append(
                    {
                        'label': cls._render_field_label(field),
                        'old': cls._render_field_value(old_val, field),
                        'new': cls._render_field_value(new_val, field),
                    }
                )

        return diffs

    @classmethod
    def _get_payload_diff(cls, new_rev: SecretRevision, prev_rev: SecretRevision | None, user) -> list[dict]:
        """Compare payload between two revisions and return differences."""
        if not prev_rev:
            return [{'label': 'Payload', 'old': '∅', 'new': 'Created'}]

        if new_rev.plaintext_data_sha256 == prev_rev.plaintext_data_sha256:
            return []  # Identical payload

        content_type = new_rev.secret.content_type

        if content_type == ContentType.PASSWORD:
            return [{'label': 'Password', 'old': '••••', 'new': '••••'}]

        if content_type == ContentType.FILE:
            return [{'label': 'File', 'old': 'binary', 'new': 'binary'}]

        # Credit card diff (mask sensitive fields)
        if content_type == ContentType.CC:
            try:
                new_data = new_rev.peek_data(user)
                old_data = prev_rev.peek_data(user)
            except Exception:
                # Permission or other issue → return masked generic change
                return [{'label': 'Payload', 'old': '••••', 'new': '••••'}]

            fields = ('holder', 'number', 'expiration_month', 'expiration_year', 'security_code', 'password')
            sensitive_fields = {'number', 'security_code', 'password'}

            diffs = []
            for field in fields:
                if new_data.get(field) != old_data.get(field):
                    display_name = field.replace('_', ' ').title()
                    if field in sensitive_fields:
                        diffs.append({'label': display_name, 'old': '••••', 'new': '••••'})
                    else:
                        diffs.append(
                            {'label': display_name, 'old': old_data.get(field, '∅'), 'new': new_data.get(field, '∅')}
                        )

            return diffs or [{'label': 'Payload', 'old': '∅', 'new': 'Changed'}]

    @staticmethod
    def _is_current_payload(revision: SecretRevision, secret: Secret) -> bool:
        """Check if this revision is the current payload."""
        return revision.id == secret.current_revision_id
