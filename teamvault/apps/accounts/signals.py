from django.conf import settings
from django.contrib.auth.models import Group
from django.db import transaction

from teamvault.apps.accounts.models import GroupUUIDMapping


def _collect_ldap_groups(ldap_user):
    """Return {entry_uuid: name} from the raw LDAP group infos cached on the ldap_user."""
    # django-auth-ldap exposes group infos only via the underscore API:
    # `group_names` / `group_dns` drop attribute payloads, so we reach for the cached raw
    # infos. If a future upgrade renames these, the import-time error will be loud.
    # noinspection PyProtectedMember
    groups = ldap_user._get_groups()
    # noinspection PyProtectedMember
    group_infos = groups._get_group_infos()
    # noinspection PyProtectedMember
    group_type = groups._group_type
    entry_uuid_attr = getattr(settings, 'AUTH_LDAP_GROUP_ENTRY_UUID_ATTR', 'entryUUID')

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


def sync_group_uuids_before_mirror(sender, user, ldap_user, **kwargs):  # noqa: ARG001
    """
    Runs before _mirror_groups via the populate_user signal.
    Pre-renames groups and creates mappings so that the default
    django-auth-ldap behavior finds correctly-named groups.

    Requires:
     - AUTH_LDAP_GROUP_SEARCH attrlist includes the configured entryUUID attr
       (configure_ldap_auth sets it; AccountsConfig.ready() defensively tops it up)
     - AUTH_LDAP_ALWAYS_UPDATE_USER = True (so the signal always fires)
     - AUTH_LDAP_MIRROR_GROUPS = True
    """
    ldap_groups = _collect_ldap_groups(ldap_user)
    if not ldap_groups:
        return

    with transaction.atomic():
        existing_mappings = {
            m.entry_uuid: m
            for m in GroupUUIDMapping.objects.filter(entry_uuid__in=ldap_groups.keys()).select_related('group')
        }

        groups_to_rename = []
        for entry_uuid, mapping in existing_mappings.items():
            expected_name = ldap_groups[entry_uuid]
            if mapping.group.name != expected_name:
                mapping.group.name = expected_name
                groups_to_rename.append(mapping.group)

        if groups_to_rename:
            Group.objects.bulk_update(groups_to_rename, ['name'])

        new_uuids = set(ldap_groups.keys()) - set(existing_mappings.keys())
        if not new_uuids:
            return

        # Per-group get_or_create + ignore_conflicts on the mapping bulk_create handle the
        # case of two concurrent first-time logins for the same brand-new LDAP group.
        new_mappings = []
        for entry_uuid in new_uuids:
            group, _created = Group.objects.get_or_create(name=ldap_groups[entry_uuid])
            new_mappings.append(GroupUUIDMapping(group=group, entry_uuid=entry_uuid))

        GroupUUIDMapping.objects.bulk_create(new_mappings, ignore_conflicts=True)
