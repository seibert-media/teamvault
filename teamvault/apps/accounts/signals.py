import logging
import uuid
from dataclasses import dataclass, field

import ldap
from django.conf import settings
from django.contrib.auth.models import Group
from django.db import transaction
from django_auth_ldap.config import LDAPSearch

from teamvault.apps.accounts.ldap_uuid import canonicalize_ldap_uuid, ldap_uuid_filter_term
from teamvault.apps.accounts.models import GroupUUIDMapping, UserProfile
from teamvault.apps.audit.auditlog import log
from teamvault.apps.audit.models import AuditLogCategoryChoices
from teamvault.apps.secrets.models import SharedSecretData

logger = logging.getLogger(__name__)


@dataclass
class _SyncPlan:
    """DB changes to apply in one transaction, computed without holding one open."""

    merges: list = field(default_factory=list)  # (collider, target, new_name)
    renames: list = field(default_factory=list)  # (group, new_name)
    rebinds: list = field(default_factory=list)  # (mapping, new_ldap_uuid)
    mappings: list = field(default_factory=list)  # (group_name, ldap_uuid)

    def __bool__(self):
        return bool(self.merges or self.renames or self.rebinds or self.mappings)


def _collect_ldap_groups(ldap_user, *, ldap_uuid_attr):
    """Return {ldap_uuid: name} from the raw LDAP group infos cached on the ldap_user."""
    # django-auth-ldap exposes group infos only via the underscore API:
    # `group_names` / `group_dns` drop attribute payloads, so we reach for the cached raw
    # infos. If a future upgrade renames these, the import-time error will be loud.
    groups = ldap_user._get_groups()
    group_infos = groups._get_group_infos()
    group_type = groups._group_type

    ldap_groups = {}
    for group_info in group_infos:
        _dn, attrs = group_info
        name = group_type.group_name_from_info(group_info)
        raw = attrs.get(ldap_uuid_attr) or attrs.get(ldap_uuid_attr.encode())
        if not (name and raw):
            continue
        ldap_uuid = canonicalize_ldap_uuid(raw[0])
        if ldap_uuid is None:
            logger.error(
                'LDAP group "%s" has an unusable %s value (%r); skipping it for this sync',
                name,
                ldap_uuid_attr,
                raw[0],
            )
            continue
        ldap_groups[ldap_uuid] = name

    return ldap_groups


def _merge_unmapped_collider(*, collider, target, new_name):
    """
    The collider is a name-based duplicate of the same logical LDAP group (left over from
    name-based mirroring before UUID mappings existed, or created manually), so fold its
    members and references into the UUID-mapped group. The emptied collider is kept and
    later stale-renamed instead of being deleted: audit LogEntry rows reference groups
    with on_delete=PROTECT, so deleting any collider with audit history would abort the
    login.
    """
    target.user_set.add(*collider.user_set.all())
    target.permissions.add(*collider.permissions.all())
    SharedSecretData.objects.filter(group=collider).exclude(
        # skip secrets the target already has a share for (unique per group/secret)
        secret__in=SharedSecretData.objects.filter(group=target).values('secret'),
    ).update(group=target)
    default_sharing_groups = UserProfile.default_sharing_groups.through.objects
    default_sharing_groups.filter(group=collider).exclude(
        userprofile__in=default_sharing_groups.filter(group=target).values('userprofile'),
    ).update(group=target)
    # strip everything left on the husk (duplicate shares, memberships, permissions,
    # default-sharing references) so it cannot keep granting access
    SharedSecretData.objects.filter(group=collider).delete()
    default_sharing_groups.filter(group=collider).delete()
    collider.user_set.clear()
    collider.permissions.clear()
    log(
        f'Merged duplicate group "{collider.name}" (id {collider.pk}) into UUID-mapped group '
        f'"{target.name}" (id {target.pk}) to rename it to "{new_name}"',
        category=AuditLogCategoryChoices.MISCELLANEOUS,
        group=target,
    )


def _current_ldap_name(ldap_user, *, ldap_uuid, ldap_uuid_attr):
    """Return the group's current name in LDAP, or None if the UUID no longer exists there."""
    base = settings.AUTH_LDAP_GROUP_SEARCH
    term = ldap_uuid_filter_term(ldap_uuid_attr, ldap_uuid)
    search = LDAPSearch(base.base_dn, base.scope, f'(&{base.filterstr}{term})', base.attrlist)
    results = search.execute(ldap_user.connection)
    if not results:
        return None
    return settings.AUTH_LDAP_GROUP_TYPE.group_name_from_info(results[0])


def _resolve_collisions(planned_renames, *, ldap_user, ldap_uuid_attr, merges):
    """
    Make every planned rename applicable: schedule merges (into `merges`) for unmapped
    colliders (name-based duplicates of the same logical LDAP group) plus a stale-rename
    of the emptied husk, and rename mapped colliders to their current LDAP name or to a
    stale placeholder if their LDAP group no longer exists. Returns the (group, new_name)
    pairs to apply. Reads LDAP and the DB, but writes nothing.
    """
    planned = list(planned_renames)
    # Resolving a collider can surface new collisions (its current LDAP name may be
    # taken by yet another group), so iterate until none are left.
    while True:
        target_by_name = {new_name: group for group, new_name in planned}
        renaming_pks = {group.pk for group, _new_name in planned}
        colliders = list(Group.objects.filter(name__in=target_by_name).exclude(pk__in=renaming_pks))
        if not colliders:
            break
        mappings = {m.group_id: m for m in GroupUUIDMapping.objects.filter(group__in=colliders)}

        for collider in colliders:
            target = target_by_name[collider.name]
            mapping = mappings.get(collider.pk)
            if mapping is None:
                merges.append((collider, target, collider.name))
                # truncated to fit auth_group.name's max_length of 150
                planned.append((collider, f'{collider.name[:100]}_merged_{collider.pk}_stale'))
                continue

            # A mapped collider is a different logical group so we can never merge it.
            # Ask LDAP for its current name so both groups end up correct in the same pass.
            try:
                current_name = _current_ldap_name(ldap_user, ldap_uuid=mapping.ldap_uuid, ldap_uuid_attr=ldap_uuid_attr)
            except ldap.LDAPError:
                logger.warning(
                    'LDAP lookup for group UUID %s failed; skipping rename of group "%s" (id %s) to "%s"',
                    mapping.ldap_uuid,
                    target.name,
                    target.pk,
                    collider.name,
                )
                planned.remove((target, collider.name))
                continue

            if current_name is None:
                # truncated to fit auth_group.name's max_length of 150; ldap_uuid is at most 36 chars
                placeholder = f'{collider.name[:107]}_{mapping.ldap_uuid}_stale'
                logger.warning(
                    'Group "%s" (id %s) is mapped to LDAP UUID %s, which no longer exists in LDAP; '
                    'renaming it to "%s" to free the name',
                    collider.name,
                    collider.pk,
                    mapping.ldap_uuid,
                    placeholder,
                )
                planned.append((collider, placeholder))
            elif current_name != collider.name:
                planned.append((collider, current_name))
            else:
                # LDAP resolves two live groups to the same name (e.g. same cn in different
                # OUs); the collider legitimately owns it, so the planned rename loses.
                logger.warning(
                    'Skipping rename of group "%s" (id %s) to "%s": LDAP holds another live group with that name',
                    target.name,
                    target.pk,
                    collider.name,
                )
                planned.remove((target, collider.name))

    return planned


def _apply_renames(renames):
    # The same duplicate-name case can also appear within the batch itself:
    # auth_group.name can hold each name only once, so first claim wins.
    seen_names = set()
    unique = []
    for group, new_name in renames:
        if new_name in seen_names:
            logger.warning(
                'Skipping rename of group "%s" (id %s) to "%s": another group is being renamed to the same name',
                group.name,
                group.pk,
                new_name,
            )
            continue
        seen_names.add(new_name)
        unique.append((group, new_name))

    old_names = {group.pk: group.name for group, _new_name in unique}

    # Two-phase rename through unique temp names: auth_group.name is unique and Postgres
    # checks the constraint per row, so name swaps/chains between the renamed groups would
    # otherwise raise IntegrityError even within a single bulk_update statement. The random
    # suffix keeps a real group that happens to carry the placeholder name from colliding.
    groups = [group for group, _new_name in unique]
    for group in groups:
        group.name = f'_teamvault_rename_{group.pk}_{uuid.uuid4().hex[:8]}'
    Group.objects.bulk_update(groups, ['name'])
    for group, new_name in unique:
        group.name = new_name
    Group.objects.bulk_update(groups, ['name'])

    for group, new_name in unique:
        log(
            f'Renamed group "{old_names[group.pk]}" (id {group.pk}) to "{new_name}" during LDAP group sync',
            category=AuditLogCategoryChoices.MISCELLANEOUS,
            group=group,
        )


def _plan_group_sync(ldap_groups, *, ldap_user, ldap_uuid_attr):
    existing_mappings = {
        m.ldap_uuid: m for m in GroupUUIDMapping.objects.filter(ldap_uuid__in=ldap_groups).select_related('group')
    }

    plan = _SyncPlan()
    planned_renames = [
        (mapping.group, ldap_groups[ldap_uuid])
        for ldap_uuid, mapping in existing_mappings.items()
        if mapping.group.name != ldap_groups[ldap_uuid]
    ]
    if planned_renames:
        plan.renames = _resolve_collisions(
            planned_renames, ldap_user=ldap_user, ldap_uuid_attr=ldap_uuid_attr, merges=plan.merges
        )

    # groups whose current name will be free once the renames are applied
    repurposed_pks = {group.pk for group, _new_name in plan.renames}
    claimed_names = {new_name for _group, new_name in plan.renames}
    for ldap_uuid, name in ldap_groups.items():
        if ldap_uuid in existing_mappings:
            continue
        if name in claimed_names:
            logger.warning(
                'Skipping LDAP group with UUID %s: another group in this sync already claims the name "%s"',
                ldap_uuid,
                name,
            )
            continue
        claimed_names.add(name)

        group = Group.objects.filter(name=name).first()
        if group is None or group.pk in repurposed_pks:
            plan.mappings.append((name, ldap_uuid))
            continue

        mapping = GroupUUIDMapping.objects.filter(group=group).select_related('group').first()
        if mapping is None:
            # pre-existing group from name-based mirroring; adopt it
            plan.mappings.append((name, ldap_uuid))
            continue

        # the name is held by a group mapped to a different UUID
        try:
            current_name = _current_ldap_name(ldap_user, ldap_uuid=mapping.ldap_uuid, ldap_uuid_attr=ldap_uuid_attr)
        except ldap.LDAPError:
            logger.warning(
                'LDAP lookup for group UUID %s failed; skipping new LDAP group with UUID %s and name "%s"',
                mapping.ldap_uuid,
                ldap_uuid,
                name,
            )
            continue

        if current_name is None:
            # the same-named LDAP group was deleted and re-created: same logical group, new UUID
            plan.rebinds.append((mapping, ldap_uuid))
            continue

        if current_name == name:
            logger.warning(
                'Skipping new LDAP group with UUID %s: LDAP holds another live group (UUID %s) with the name "%s"',
                ldap_uuid,
                mapping.ldap_uuid,
                name,
            )
            continue

        # the mapped group was renamed in LDAP; move it to its current name to free this one
        freeing = _resolve_collisions(
            [(group, current_name)], ldap_user=ldap_user, ldap_uuid_attr=ldap_uuid_attr, merges=plan.merges
        )
        if (group, current_name) not in freeing:
            continue
        plan.renames.extend(freeing)
        repurposed_pks.update(freed_group.pk for freed_group, _new_name in freeing)
        claimed_names.update(new_name for _freed_group, new_name in freeing)
        plan.mappings.append((name, ldap_uuid))

    return plan


def _apply_group_sync(plan):
    for collider, target, new_name in plan.merges:
        _merge_unmapped_collider(collider=collider, target=target, new_name=new_name)
    if plan.renames:
        _apply_renames(plan.renames)

    for mapping, ldap_uuid in plan.rebinds:
        old_ldap_uuid = mapping.ldap_uuid
        mapping.ldap_uuid = ldap_uuid
        mapping.save(update_fields=['ldap_uuid'])
        log(
            f'Rebound group "{mapping.group.name}" (id {mapping.group.pk}) from LDAP UUID {old_ldap_uuid}, '
            f'which no longer exists in LDAP, to {ldap_uuid}',
            category=AuditLogCategoryChoices.MISCELLANEOUS,
            group=mapping.group,
        )

    # ignore_conflicts covers only the remaining race: two concurrent first-time logins
    # creating the same brand-new mapping. Name conflicts with existing mappings were
    # resolved explicitly during planning.
    new_mappings = []
    for name, ldap_uuid in plan.mappings:
        group, _created = Group.objects.get_or_create(name=name)
        new_mappings.append(GroupUUIDMapping(group=group, ldap_uuid=ldap_uuid))
    GroupUUIDMapping.objects.bulk_create(new_mappings, ignore_conflicts=True)


def sync_group_uuids_before_mirror(sender, user, ldap_user, **kwargs):  # noqa: ARG001
    """
    Runs before _mirror_groups via the populate_user signal.
    Pre-renames groups and creates mappings so that the default
    django-auth-ldap behavior finds correctly-named groups.

    Planning (LDAP lookups included) happens outside the transaction so no row locks
    are held during network I/O on the login path.

    Requires:
     - AUTH_LDAP_GROUP_UUID_ATTR set (opt-in toggle for this feature,
       checked here because the receiver is connected unconditionally)
     - AUTH_LDAP_GROUP_SEARCH attrlist includes that attr (configure_ldap_auth handles it)
     - AUTH_LDAP_ALWAYS_UPDATE_USER = True (so the signal always fires)
     - AUTH_LDAP_MIRROR_GROUPS = True
    """
    ldap_uuid_attr = getattr(settings, 'AUTH_LDAP_GROUP_UUID_ATTR', None)
    if not ldap_uuid_attr:
        return

    ldap_groups = _collect_ldap_groups(ldap_user, ldap_uuid_attr=ldap_uuid_attr)
    if not ldap_groups:
        return

    plan = _plan_group_sync(ldap_groups, ldap_user=ldap_user, ldap_uuid_attr=ldap_uuid_attr)
    if not plan:
        return

    with transaction.atomic():
        _apply_group_sync(plan)
