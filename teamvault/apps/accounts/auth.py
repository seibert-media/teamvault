import logging

from django.conf import settings
from django_auth_ldap.backend import LDAPBackend, _LDAPUser
from django_auth_ldap.config import LDAPSearch


logger = logging.getLogger(__name__)


def find_ldap_username_for_social_auth(details, *_args, **kwargs):
    if not kwargs.get('is_new'):
        return {}

    connection = _LDAPUser(LDAPBackend(), username='').connection
    ldap_mail_attribute = settings.AUTH_LDAP_USER_ATTR_MAP['email']
    social_auth_mail_value = details['email']
    logger.info(f'Trying to find LDAP username for social auth user {social_auth_mail_value}...')
    search = LDAPSearch(
        settings.AUTH_LDAP_USER_SEARCH.base_dn,
        settings.AUTH_LDAP_USER_SEARCH.scope,
        f'({ldap_mail_attribute}={social_auth_mail_value})',
        ['uid']
    )
    results = search.execute(connection)
    if results is not None and len(results) > 0:
        uid = results[0][1]['uid'][0]
        logger.info(f'Found LDAP username for social auth user {social_auth_mail_value}: {uid}')
        return {'username': uid}
    logger.info(f'No LDAP username found for social auth user {social_auth_mail_value}')
    return {}


def populate_from_ldap(*_args, **kwargs):
    LDAPBackend().populate_user(kwargs['user'].username)
