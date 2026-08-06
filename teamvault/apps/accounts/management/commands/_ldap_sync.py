from django.conf import settings


def ldap_sync_enabled(command):
    """Shared precondition check for the LDAP sync commands; reports via the command's stderr."""
    if not getattr(settings, 'LDAP_AUTH_ENABLED', False):
        command.stderr.write('LDAP auth is not enabled.')
        return False
    if not getattr(settings, 'AUTH_LDAP_SERVER_URI', None):
        command.stderr.write('Missing AUTH_LDAP_SERVER_URI in settings.')
        return False
    return True
