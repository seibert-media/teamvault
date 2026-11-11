import logging
from base64 import b64encode
from collections import Counter, defaultdict
from types import SimpleNamespace

import ldap
import requests
from django.conf import settings
from django.contrib.auth.models import Group
from django.db import transaction
from huey import crontab
from huey.contrib.djhuey import periodic_task, task
from ldap.ldapobject import LDAPObject

from teamvault.apps.audit.auditlog import log
from teamvault.apps.audit.models import AuditLogCategoryChoices
from .backends import _get_ldap_connection
from .ldap_uuid import canonicalize_ldap_uuid
from .models import GroupUUIDMapping, User, UserProfile

logger = logging.getLogger(__name__)

AVATAR_TIMEOUT = (5, 10)


@task(retries=2, retry_delay=60)
def store_avatar(user_id: int, url: str) -> None:
    """
    Download an avatar and store it on the user's profile.
    Runs outside the normal login pipeline so that we don't block the main thread.
    """
    try:
        response = requests.get(url, timeout=AVATAR_TIMEOUT)
    except requests.RequestException:
        logger.warning('Fetching avatar from %s failed for user id %s', url, user_id)
        return

    if not response.ok:
        logger.warning('Fetching avatar from %s failed for user id %s: HTTP %s', url, user_id, response.status_code)
        return

    profile = UserProfile.objects.get_or_create(user_id=user_id)[0]
    profile.avatar = b64encode(response.content)
    profile.save(update_fields=['avatar'])


class LDAPGroupSyncAborted(Exception):
    pass


@periodic_task(crontab(**settings.HUEY_TASKS['scheduler_frequency']))
def sync_ldap_group_members() -> None:
    if not (getattr(settings, 'LDAP_AUTH_ENABLED', False) and settings.HUEY_TASKS['sync_ldap_groups']):
        return
    try:
        sync_ldap_groups()
    except (ldap.LDAPError, LDAPGroupSyncAborted) as exc:
        logger.warning('LDAP group sync aborted, no memberships were changed: %r', exc)


def sync_ldap_groups() -> None:
    """
    Make the members of every LDAP-backed Django group match LDAP, without waiting for each user to log in.
    Groups without an LDAP counterpart are left alone. Users are never created, only existing active ones added.

    All LDAP reads happen before the first write, so an LDAP error leaves every group untouched.
    """
    connection = _get_ldap_connection()
    try:
        groups_by_dn = _ldap_backed_groups(connection)
        desired_groups = _desired_groups_by_user(connection, groups_by_dn)
    finally:
        connection.unbind_s()

    members_by_group: defaultdict[Group, set[User]] = defaultdict(set)
    for user, groups in desired_groups.items():
        for group in groups:
            members_by_group[group].add(user)

    with transaction.atomic():
        for group in set(groups_by_dn.values()):
            _apply_members(group, members_by_group[group])


def _ldap_backed_groups(connection: LDAPObject) -> dict[str, Group]:
    """Return {lowercased LDAP group DN: Django group} for every LDAP group with a Django counterpart."""
    group_infos = settings.AUTH_LDAP_GROUP_SEARCH.execute(connection)
    if not group_infos:
        raise LDAPGroupSyncAborted('the LDAP group search returned no groups')

    group_type = settings.AUTH_LDAP_GROUP_TYPE
    uuid_attr = getattr(settings, 'AUTH_LDAP_GROUP_UUID_ATTR', None)
    groups_by_uuid: dict[str, Group] = {}
    mapped_group_ids: set[int] = set()
    if uuid_attr:
        for mapping in GroupUUIDMapping.objects.select_related('group'):
            groups_by_uuid[mapping.ldap_uuid] = mapping.group
            mapped_group_ids.add(mapping.group_id)

    name_counts = Counter(group_type.group_name_from_info(info) for info in group_infos)
    unmapped_groups_by_name = {group.name: group for group in Group.objects.exclude(pk__in=mapped_group_ids)}

    groups_by_dn: dict[str, Group] = {}
    for info in group_infos:
        dn, attrs = info
        if uuid_attr:
            raw = attrs.get(uuid_attr) or attrs.get(uuid_attr.encode())
            group = groups_by_uuid.get(canonicalize_ldap_uuid(raw[0])) if raw else None
            if group is not None:
                groups_by_dn[dn.lower()] = group
                continue

        name = group_type.group_name_from_info(info)
        if not name or name not in unmapped_groups_by_name:
            continue
        if name_counts[name] > 1:
            logger.warning('Skipping LDAP group name "%s" during group sync: multiple LDAP groups share it', name)
            continue
        groups_by_dn[dn.lower()] = unmapped_groups_by_name[name]

    return groups_by_dn


def _desired_groups_by_user(connection: LDAPObject, groups_by_dn: dict[str, Group]) -> dict[User, set[Group]]:
    """
    Return {user: LDAP-backed groups the user belongs to} for every active user.
    Users missing from LDAP map to no groups. Inactive users are left out, so they end up in no group.
    """
    user_search = settings.AUTH_LDAP_USER_SEARCH
    group_search = settings.AUTH_LDAP_GROUP_SEARCH
    group_type = settings.AUTH_LDAP_GROUP_TYPE

    desired: dict[User, set[Group]] = {}
    found_in_ldap = 0
    for user in User.objects.filter(is_active=True):
        results = user_search.execute(connection, {'user': user.username})
        if len(results) != 1:
            desired[user] = set()
            continue
        found_in_ldap += 1
        dn = results[0][0]

        ldap_user = SimpleNamespace(dn=dn, connection=connection)  # only need these two
        group_dns = {group_dn.lower() for group_dn, _attrs in group_type.user_groups(ldap_user, group_search)}
        desired[user] = {groups_by_dn[group_dn] for group_dn in group_dns if group_dn in groups_by_dn}

    if desired and not found_in_ldap:
        raise LDAPGroupSyncAborted('no active user was found in LDAP')

    return desired


def _apply_members(group: Group, members: set[User]) -> None:
    current = set(group.user_set.all())
    added = members - current
    removed = current - members
    group.user_set.add(*added)
    group.user_set.remove(*removed)
    for user in sorted(added, key=lambda u: u.username):
        log(
            f'Added user "{user.username}" to group "{group.name}" during LDAP group sync',
            category=AuditLogCategoryChoices.GROUP_MEMBER_ADDED,
            group=group,
            user=user,
        )
    for user in sorted(removed, key=lambda u: u.username):
        log(
            f'Removed user "{user.username}" from group "{group.name}" during LDAP group sync',
            category=AuditLogCategoryChoices.GROUP_MEMBER_REMOVED,
            group=group,
            user=user,
        )
