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
    SecretRevision,
    SecretChange,
)
from teamvault.apps.secrets.utils import META_FIELDS, apply_snapshot_to_secret, copy_meta_from_secret


@dataclass
class HistoryEntry:
    ts: datetime
    kind: Literal['payload', 'meta', 'restore']
    user: str
    name: str
    changes: list[dict[str, str]]
    link: str
    current: bool
    change_hash: str
    needs_changing: bool = False
    restored_from: str | None = None
    scrubbed_by: str | None = None
    scrubbed_at: datetime | None = None


class RevisionService:
    """Orchestrates payload saves, restores, and history snapshots.

    Invariants:
    - Every save_payload/restore produces a SecretChange node.
    - SecretChange rows carry a snapshot of the metadata.
    - History and UI derive exclusively from SecretChange.
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
        """Create or reuse a payload revision, set it current, and record
        a SecretChange with a metadata snapshot.
        """
        if not skip_acl and secret.permission_checker(actor).is_readable() == AccessPermissionTypes.NOT_ALLOWED:
            raise PermissionDenied('User has no write access to secret payload')

        # 1. Build (or fetch) the revision representing _payload_
        revision = cls._build_revision(secret=secret, actor=actor, payload=payload)
        payload_changed = revision.plaintext_data_sha256 != (
            secret.current_revision.plaintext_data_sha256 if secret.current_revision_id else None
        )

        previous_change = SecretChange.objects.filter(secret=secret).order_by('-created').first()
        incoming_snapshot = copy_meta_from_secret(secret)
        meta_changed = cls._snapshot_differs(incoming_snapshot, previous_change)

        if not payload_changed and not meta_changed:
            return revision

        # 2. Update Secret pointers/flags
        previous_id = secret.current_revision_id or 'none'
        secret.current_revision = revision
        secret.last_changed = now()
        secret.last_read = now()
        # Only clear NEEDS_CHANGING when payload actually changes
        if payload_changed and secret.status == SecretStatus.NEEDS_CHANGING:
            secret.status = SecretStatus.OK
        secret.save(update_fields=['current_revision', 'last_changed', 'last_read', 'status'])

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
        # 5. Record a SecretChange node with snapshot
        parent = (
            SecretChange.objects.select_for_update()
            .filter(secret=secret)
            .order_by('-created')
            .first()
        )
        snapshot = copy_meta_from_secret(secret)
        SecretChange.objects.create(
            secret=secret,
            revision=revision,
            actor=actor,
            parent=parent,
            **snapshot,
        )

        return revision

    @classmethod
    @classmethod
    @transaction.atomic
    def restore_to_change(
        cls,
        *,
        secret: Secret,
        actor,
        change: SecretChange,
    ) -> SecretRevision:
        """Restore the secret to the exact state captured by `change`:
        payload and metadata snapshot.
        """
        if secret.pk != change.secret_id:
            raise ValueError('Change does not belong to secret')

        chk = secret.permission_checker(actor)
        # Permit restore to anyone who can edit (same gate as save_payload)
        if chk.is_readable() == AccessPermissionTypes.NOT_ALLOWED:
            raise PermissionDenied('User may not restore revisions')

        # create or reuse revision w/ identical payload
        new_rev = SecretRevision._create_from_revision(
            old_revision=change.revision,
            set_by=actor,
            skip_access_check=True,
        )
        # Chronology is modeled via SecretChange.restored_from; do not mutate
        # SecretRevision rows when restoring.

        changed_fields = apply_snapshot_to_secret(secret, change)
        secret.current_revision = new_rev
        secret.last_changed = now()
        secret.save(update_fields=['current_revision', 'last_changed', *changed_fields])

        log(
            _("{user} restored '{name}' to change {change}").format(
                user=actor.username,
                name=secret.name,
                change=change.hashid,
            ),
            actor=actor,
            category=AuditLogCategoryChoices.SECRET_RESTORED,
            level='warning',
            secret=secret,
            secret_revision=new_rev,
            reason=f'Restored to change {change.hashid}',
        )
        # Record SecretChange for restore
        parent = SecretChange.objects.filter(secret=secret).order_by('-created').first()
        SecretChange.objects.create(
            secret=secret,
            revision=new_rev,
            actor=actor,
            restored_from=change,
            parent=parent,
            **copy_meta_from_secret(secret),
        )

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
            if 'password' not in payload and 'password' in prev:
                payload['password'] = prev['password']

            # Preserve OTP fields only when the previous revision actually had them.
            if 'otp_key' not in payload and 'otp_key' in prev:
                payload['otp_key'] = prev['otp_key']
                for fld in ('digits', 'algorithm'):
                    if fld in prev:
                        payload[fld] = prev[fld]

        sha_src = dumps(payload, sort_keys=True)
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
        """History built from SecretChange graph using parent→child edges for diffs.

        Display ordering remains chronological (created desc) for readability.
        """
        changes = list(
            SecretChange.objects.filter(secret=secret)
            .select_related('actor', 'scrubbed_by', 'revision', 'parent', 'parent__revision')
            .order_by('created')
        )

        rows: list[HistoryEntry] = []

        # Identify the latest change (represents the current state)
        latest_change_id = changes[-1].id if changes else None

        for ch in changes:
            parent = ch.parent

            prev_rev = parent.revision if parent else None

            payload_changes = cls._get_payload_diff(ch.revision, prev_rev, user)
            meta_changes = cls._get_meta_diff(ch, parent)

            # Determine kind
            kind = 'restore' if ch.restored_from_id else ('payload' if payload_changes else 'meta')

            # Merge changes: payload first for readability
            merged = []
            merged.extend(payload_changes)
            merged.extend(meta_changes)

            # Determine link + current flags
            is_latest = (ch.id == latest_change_id)
            if is_latest:
                # Current state: link to canonical secret detail view
                link = secret.get_absolute_url()
            else:
                base_link = reverse('secrets.revision-detail', args=[ch.revision.hashid])
                link = f"{base_link}?change={ch.hashid}"
            current = (ch.revision_id == secret.current_revision_id)

            rows.append(
                HistoryEntry(
                    ts=ch.created,
                    kind=kind,  # type: ignore
                    user=ch.actor.username,
                    name=secret.name,
                    changes=merged,
                    link=link,
                    current=current,
                    change_hash=ch.hashid,
                    needs_changing=(ch.status == SecretStatus.NEEDS_CHANGING),
                    restored_from=(ch.restored_from.revision.hashid if ch.restored_from_id else None),
                    scrubbed_by=(ch.scrubbed_by.username if ch.scrubbed_by_id else None),
                    scrubbed_at=ch.scrubbed_at,
                )
            )

        return sorted(rows, key=lambda e: e.ts, reverse=True)

    @classmethod
    @transaction.atomic
    def delete_change(cls, *, change: SecretChange, actor) -> int:
        """Scrub metadata for a SecretChange while keeping the revision reachable.

        We replace the change's metadata snapshot with its parent's snapshot
        (if available) so that the history no longer exposes the edited metadata,
        but the payload revision and chronology remain intact. When there is no
        parent (first change), we blank optional text fields to purge sensitive
        content while leaving non-text fields unchanged.

        Returns the number of rows updated (1 when the target change exists).
        """
        if not actor.is_superuser:
            raise PermissionDenied('Only superusers may delete secret history checkpoints')

        secret = change.secret
        parent = change.parent

        if parent:
            replacement = {field: getattr(parent, field) for field in META_FIELDS}
        else:
            replacement = {
                'name': change.name,
                'description': '',
                'username': '',
                'url': '',
                'filename': '',
                'access_policy': change.access_policy,
                'needs_changing_on_leave': change.needs_changing_on_leave,
                'status': change.status,
            }

        replacement['scrubbed_at'] = now()
        replacement['scrubbed_by'] = actor

        updated = SecretChange.objects.filter(pk=change.pk).update(**replacement)

        log(
            _("{user} scrubbed metadata for change {change_hash} on '{name}'").format(
                user=actor.username,
                change_hash=change.hashid,
                name=secret.name,
            ),
            actor=actor,
            category=AuditLogCategoryChoices.SECRET_METADATA_CHANGED,
            level='warning',
            secret=secret,
            secret_revision=change.revision,
            reason=f'Scrubbed metadata for change {change.hashid}',
        )

        return updated


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

    @staticmethod
    def _snapshot_differs(snapshot: dict[str, Any], previous: SecretChange | None) -> bool:
        """Return True when metadata snapshot differs from the previous change."""
        if previous is None:
            return True

        for field, value in snapshot.items():
            if getattr(previous, field) != value:
                return True
        return False

    @classmethod
    def _get_meta_diff(cls, new_obj: SecretChange, prev_obj: SecretChange | None) -> list[dict]:
        """Compare metadata snapshot between two SecretChange rows."""
        diffs = []
        for field in META_FIELDS:
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

        if new_obj.scrubbed_by_id:
            scrubbed_at = new_obj.scrubbed_at.isoformat() if new_obj.scrubbed_at else '—'
            diffs.append(
                {
                    'label': 'Scrubbed',
                    'old': '∅',
                    'new': f"by {new_obj.scrubbed_by.username} at {scrubbed_at}",
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
