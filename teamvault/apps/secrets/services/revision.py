import re
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
from teamvault.apps.audit.models import AuditLogCategoryChoices, LogEntry
from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.models import (
    AccessPermissionTypes,
    Secret,
    SecretMetaSnapshot,
    SecretRevision,
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


class RevisionService:
    """Central orchestration logic for Secret revisions & metadata snapshots."""

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
        """Create or reuse a payload revision, make it current & snapshot metadata
        if necessary.
        """
        if not skip_acl and secret.permission_checker(actor).is_readable() == AccessPermissionTypes.NOT_ALLOWED:
            raise PermissionDenied('User has no write access to secret payload')

        # 1. Build (or fetch) the revision representing _payload_
        revision = cls._build_revision(secret=secret, actor=actor, payload=payload)

        # 2. Update Secret pointers/flags
        previous_id = secret.current_revision_id or 'none'
        secret.current_revision = revision
        secret.last_changed = now()
        secret.last_read = now()
        secret.status = SecretStatus.OK if secret.status == SecretStatus.NEEDS_CHANGING else secret.status
        secret.save(update_fields=['current_revision', 'last_changed', 'last_read', 'status'])

        # 3. Ensure we have an up‑to‑date metadata snapshot
        baseline_missing = not SecretMetaSnapshot.objects.filter(secret=secret).exists()
        if baseline_missing or meta_changed(secret):
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

        changed_fields = apply_meta_to_secret(secret, snapshot)

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

    @classmethod
    def get_revision_history(cls, secret: Secret, user) -> list[HistoryEntry]:
        """Build a complete history of all changes (payload + metadata) for a secret."""
        events = cls._collect_all_events(secret)
        history_entries = cls._process_events_to_history(events, secret, user)
        return sorted(history_entries, key=lambda e: e.ts, reverse=True)

    @classmethod
    def _collect_all_events(cls, secret: Secret) -> list[dict]:
        """Collect all timeline events for a secret."""
        events = []

        # Add revision events
        revisions = (
            secret.secretrevision_set.select_related('set_by').prefetch_related('meta_snaps').order_by('created')
        )
        for rev in revisions:
            events.append(
                {
                    'type': 'revision',
                    'ts': rev.created,
                    'obj': rev,
                    'user': rev.set_by,
                }
            )

        # Add snapshot events
        snapshots = (
            SecretMetaSnapshot.objects.filter(revision__secret=secret)
            .select_related('revision', 'set_by')
            .order_by('created')
        )
        for snap in snapshots:
            events.append(
                {
                    'type': 'snapshot',
                    'ts': snap.created,
                    'obj': snap,
                    'user': snap.set_by,
                }
            )

        # Add restore events
        restores = LogEntry.objects.filter(
            secret=secret, category=AuditLogCategoryChoices.SECRET_RESTORED
        ).select_related('actor')
        for restore in restores:
            events.append(
                {
                    'type': 'restore',
                    'ts': restore.time,
                    'obj': restore,
                    'user': restore.actor,
                }
            )

        return sorted(events, key=lambda e: e['ts'])

    @classmethod
    def _process_events_to_history(cls, events: list[dict], secret: Secret, user) -> list[HistoryEntry]:
        """Convert timeline events into history entries."""
        rows = []
        prev_revision = None
        prev_snapshot = None
        seen_revisions = set()
        seen_snapshots = set()

        for event in events:
            if event['type'] == 'revision' and event['obj'].id not in seen_revisions:
                row = cls._create_revision_history_entry(
                    event, prev_revision, prev_snapshot, secret, user, seen_snapshots
                )
                if row:
                    rows.append(row)
                    prev_revision = event['obj']
                    if row.snapshot:
                        prev_snapshot = row.snapshot
                seen_revisions.add(event['obj'].id)

            elif event['type'] == 'snapshot' and event['obj'].id not in seen_snapshots:
                row = cls._create_snapshot_history_entry(event, prev_snapshot, secret)
                if row:
                    rows.append(row)
                    prev_snapshot = event['obj']
                seen_snapshots.add(event['obj'].id)

            elif event['type'] == 'restore':
                row = cls._create_restore_history_entry(event, prev_revision, secret)
                if row:
                    rows.append(row)
                    # After a restore, update prev_revision to the restored revision
                    # This ensures the next diff compares against the restored state

                    to_match = re.search(r'create revision (\w+)', event['obj'].message or '')
                    if to_match:
                        try:
                            prev_revision = SecretRevision.objects.get(id=to_match.group(1))
                            # Also update prev_snapshot to the restored revision's snapshot
                            if prev_revision.latest_meta:
                                prev_snapshot = prev_revision.latest_meta
                        except SecretRevision.DoesNotExist:
                            pass

        return rows

    @classmethod
    def _create_revision_history_entry(
        cls, event: dict, prev_revision, prev_snapshot, secret: Secret, user, seen_snapshots: set
    ) -> HistoryEntry:
        """Create a history entry for a revision event."""
        rev = event['obj']
        changes = []

        # Get payload changes
        if prev_revision:
            payload_changes = cls._get_payload_diff(rev, prev_revision, user)
            changes.extend(payload_changes)
        else:
            changes.append({'label': 'Payload', 'old': '∅', 'new': 'Created'})

        # Check for associated snapshot created at same time
        associated_snap = cls._find_associated_snapshot(rev, seen_snapshots)
        if associated_snap:
            meta_changes = cls._get_meta_diff(associated_snap, prev_snapshot)
            changes.extend(meta_changes)
            seen_snapshots.add(associated_snap.id)

        return HistoryEntry(
            ts=rev.created,
            kind='payload',
            user=rev.set_by.username,
            name=secret.name,
            changes=changes,
            link=reverse('secrets.revision-detail', args=[rev.hashid]),
            current=cls._is_current_payload(rev, secret),
            snapshot=associated_snap,
        )

    @classmethod
    def _create_snapshot_history_entry(cls, event: dict, prev_snapshot, secret: Secret) -> HistoryEntry | None:
        """Create a history entry for a metadata-only snapshot event."""
        snap = event['obj']
        changes = cls._get_meta_diff(snap, prev_snapshot)

        if not changes:
            return None

        return HistoryEntry(
            ts=snap.created,
            kind='meta',
            user=snap.set_by.username,
            name=secret.name,
            changes=changes,
            link=(
                secret.get_absolute_url()
                if cls._is_current_meta(snap, secret)
                else reverse('secrets.revision-detail', args=[snap.revision.hashid]) + f'?meta_snap={snap.id}'
            ),
            current=cls._is_current_meta(snap, secret),
            snapshot=snap,
        )

    @classmethod
    def _create_restore_history_entry(cls, event: dict, prev_revision, secret: Secret) -> HistoryEntry:
        """Create a history entry for a restore event."""
        restore = event['obj']
        changes = []

        # Extract restored revision info from log message
        message = restore.message or ''
        from_match = re.search(r'from revision (\w+)', message)
        to_match = re.search(r'create revision (\w+)', message)

        if from_match and to_match:
            source_rev_id = from_match.group(1)
            target_rev_id = to_match.group(1)

            try:
                # Get the newly created revision (result of the restore)
                restored_revision = SecretRevision.objects.get(id=target_rev_id)

                # Get payload changes between previous state and restored state
                if prev_revision:
                    payload_changes = cls._get_payload_diff(restored_revision, prev_revision, restore.actor)
                    changes.extend(payload_changes)
                else:
                    changes.append({'label': 'Payload', 'old': '∅', 'new': 'Created'})

                # Get metadata changes
                restored_snap = cls._find_associated_snapshot(restored_revision, set())
                if restored_snap and prev_revision and prev_revision.latest_meta:
                    meta_changes = cls._get_meta_diff(restored_snap, prev_revision.latest_meta)
                    changes.extend(meta_changes)

                # Add a note about which revision was restored
                if changes:
                    changes.insert(0, {'label': _('Source'), 'old': '—', 'new': f'Revision {source_rev_id}'})

                link = reverse('secrets.revision-detail', args=[restored_revision.hashid])

            except SecretRevision.DoesNotExist:
                # Fallback
                changes.append(
                    {'label': _('Restored from'), 'old': '—', 'new': f'Revision {source_rev_id if from_match else "?"}'}
                )
                link = secret.get_absolute_url()
        else:
            # Fallback if we can't parse the message
            changes.append({'label': _('Action'), 'old': '—', 'new': _('Restored to previous version')})
            link = secret.get_absolute_url()

        return HistoryEntry(
            ts=restore.time,
            kind='restore',
            user=restore.actor.username,
            name=secret.name,
            changes=changes,
            link=link,
            current=False,
            snapshot=None,
        )

    @classmethod
    def _find_associated_snapshot(cls, revision: SecretRevision, seen_snapshots: set):
        """Find a snapshot associated with this revision created at approximately the same time."""
        for snap in revision.meta_snaps.all():
            if snap.id not in seen_snapshots and abs((snap.created - revision.created).total_seconds()) < 2:
                return snap
        return None

    @staticmethod
    def _is_current_meta(snapshot: SecretMetaSnapshot, secret: Secret) -> bool:
        """Check if this snapshot represents the current metadata state."""
        if not snapshot or not secret.current_revision:
            return False

        # The current metadata is the latest snapshot of the current revision
        current_meta = secret.current_revision.latest_meta
        return snapshot.id == getattr(current_meta, 'id', None)

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
        fields = ('description', 'username', 'url', 'filename', 'access_policy', 'status', 'needs_changing_on_leave')

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
            new_data = new_rev.get_data(user)
            old_data = prev_rev.get_data(user)

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
