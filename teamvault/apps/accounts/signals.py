import logging

import ldap
from django.conf import settings
from django.contrib.auth.models import Group
from django.db import transaction

from teamvault.apps.accounts.models import GroupUUIDMapping, UserProfile
from teamvault.apps.audit.auditlog import log
from teamvault.apps.audit.models import AuditLogCategoryChoices
from teamvault.apps.secrets.models import SharedSecretData

logger = logging.getLogger(__name__)


def _collect_ldap_groups(ldap_user, *, entry_uuid_attr):
    """Return {entry_uuid: name} from the raw LDAP group infos cached on the ldap_user."""
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
        raw = attrs.get(entry_uuid_attr) or attrs.get(entry_uuid_attr.encode())
        if not (name and raw):
            continue
        value = raw[0]
        entry_uuid = value.decode() if isinstance(value, bytes) else value
        if entry_uuid:
            ldap_groups[entry_uuid] = name

    return ldap_groups


def _merge_unmapped_collider(*, collider, target, new_name):
    """
    The collider is a name-based duplicate of the same logical LDAP group (left over from
    name-based mirroring before UUID mappings existed, or created manually), so fold its
    members and references into the UUID-mapped group and delete it.
    """
    target.user_set.add(*collider.user_set.all())
    SharedSecretData.objects.filter(group=collider).exclude(
        # skip secrets the target already has a share for (unique per group/secret);
        # the collider's leftover shares die via CASCADE on delete below
        secret__in=SharedSecretData.objects.filter(group=target).values('secret'),
    ).update(group=target)
    default_sharing_groups = UserProfile.default_sharing_groups.through.objects
    default_sharing_groups.filter(group=collider).exclude(
        userprofile__in=default_sharing_groups.filter(group=target).values('userprofile'),
    ).update(group=target)
    log(
        f'Merged duplicate group "{collider.name}" (id {collider.pk}) into UUID-mapped group '
        f'"{target.name}" (id {target.pk}) to rename it to "{new_name}"',
        category=AuditLogCategoryChoices.MISCELLANEOUS,
        group=target,
    )
    collider.delete()


def _current_ldap_name(ldap_user, *, entry_uuid, entry_uuid_attr):
    """Return the group's current name in LDAP, or None if the UUID no longer exists there."""
    search = settings.AUTH_LDAP_GROUP_SEARCH.search_with_additional_terms({entry_uuid_attr: entry_uuid})
    results = search.execute(ldap_user.connection)
    if not results:
        return None
    return settings.AUTH_LDAP_GROUP_TYPE.group_name_from_info(results[0])


def _resolve_collisions(planned_renames, *, ldap_user, entry_uuid_attr):
    """
    Make every planned rename applicable: merge unmapped colliders (name-based duplicates
    of the same logical LDAP group) into their mapped counterpart, and rename mapped
    colliders to their current LDAP name or to a stale placeholder if their LDAP group
    no longer exists. Returns the (group, new_name) pairs to apply.
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
                _merge_unmapped_collider(collider=collider, target=target, new_name=collider.name)
                continue

            # A mapped collider is a different logical group so we can never merge it.
            # Ask LDAP for its current name so both groups end up correct in the same pass.
            try:
                current_name = _current_ldap_name(
                    ldap_user, entry_uuid=mapping.entry_uuid, entry_uuid_attr=entry_uuid_attr
                )
            except ldap.LDAPError:
                logger.warning(
                    'LDAP lookup for group UUID %s failed; skipping rename of group "%s" (id %s) to "%s"',
                    mapping.entry_uuid,
                    target.name,
                    target.pk,
                    collider.name,
                )
                planned.remove((target, collider.name))
                continue

            if current_name is None:
                # truncated to fit auth_group.name's max_length of 150; entry_uuid is at most 36 chars
                placeholder = f'{collider.name[:107]}_{mapping.entry_uuid}_stale'
                logger.warning(
                    'Group "%s" (id %s) is mapped to LDAP UUID %s, which no longer exists in LDAP; '
                    'renaming it to "%s" to free the name',
                    collider.name,
                    collider.pk,
                    mapping.entry_uuid,
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

    # The same duplicate-name case can also appear within the batch itself:
    # auth_group.name can hold each name only once, so first claim wins.
    seen_names = set()
    unique = []
    for group, new_name in planned:
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
    return unique


def _apply_renames(renames):
    # Two-phase rename through unique temp names: auth_group.name is unique and Postgres
    # checks the constraint per row, so name swaps/chains between the renamed groups would
    # otherwise raise IntegrityError even within a single bulk_update statement.
    groups = [group for group, _new_name in renames]
    for group in groups:
        group.name = f'_teamvault_rename_{group.pk}'
    Group.objects.bulk_update(groups, ['name'])
    for group, new_name in renames:
        group.name = new_name
    Group.objects.bulk_update(groups, ['name'])


def sync_group_uuids_before_mirror(sender, user, ldap_user, **kwargs):  # noqa: ARG001
    """
    Runs before _mirror_groups via the populate_user signal.
    Pre-renames groups and creates mappings so that the default
    django-auth-ldap behavior finds correctly-named groups.

    Requires:
     - AUTH_LDAP_GROUP_ENTRY_UUID_ATTR set (opt-in toggle for this feature,
       checked here because the receiver is connected unconditionally)
     - AUTH_LDAP_GROUP_SEARCH attrlist includes that attr (configure_ldap_auth handles it)
     - AUTH_LDAP_ALWAYS_UPDATE_USER = True (so the signal always fires)
     - AUTH_LDAP_MIRROR_GROUPS = True
    """
    entry_uuid_attr = getattr(settings, 'AUTH_LDAP_GROUP_ENTRY_UUID_ATTR', None)
    if not entry_uuid_attr:
        return

    ldap_groups = _collect_ldap_groups(ldap_user, entry_uuid_attr=entry_uuid_attr)
    if not ldap_groups:
        return

    with transaction.atomic():
        existing_mappings = {
            m.entry_uuid: m for m in GroupUUIDMapping.objects.filter(entry_uuid__in=ldap_groups).select_related('group')
        }

        planned_renames = [
            (mapping.group, ldap_groups[entry_uuid])
            for entry_uuid, mapping in existing_mappings.items()
            if mapping.group.name != ldap_groups[entry_uuid]
        ]
        if planned_renames:
            renames = _resolve_collisions(planned_renames, ldap_user=ldap_user, entry_uuid_attr=entry_uuid_attr)
            if renames:
                _apply_renames(renames)

        new_uuids: set[str] = set(ldap_groups) - set(existing_mappings)
        if not new_uuids:
            return

        # Per-group get_or_create + ignore_conflicts on the mapping bulk_create handle the
        # case of two concurrent first-time logins for the same brand-new LDAP group.
        new_mappings = []
        for entry_uuid in new_uuids:
            group, _created = Group.objects.get_or_create(name=ldap_groups[entry_uuid])
            new_mappings.append(GroupUUIDMapping(group=group, entry_uuid=entry_uuid))

        GroupUUIDMapping.objects.bulk_create(new_mappings, ignore_conflicts=True)
