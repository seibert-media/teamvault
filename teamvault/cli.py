import contextlib
import pathlib
import sys
from argparse import REMAINDER, ArgumentParser
from hashlib import sha1
from importlib import metadata
from os import environ, execvp
from shutil import rmtree

import django
from django.core.management import execute_from_command_line, get_commands

from teamvault.apps.settings.config import (
    UnconfiguredSettingsError,
    configure_gunicorn,
    create_default_config,
    get_config,
)


def build_parser():
    parser = ArgumentParser(prog='teamvault')
    parser.add_argument(
        '--version',
        action='version',
        version=metadata.version('teamvault'),
    )
    subparsers = parser.add_subparsers(
        title='subcommands',
        help="use 'teamvault <subcommand> --help' for more info",
    )

    environ['DJANGO_SETTINGS_MODULE'] = 'teamvault.settings'
    environ.setdefault('TEAMVAULT_CONFIG_FILE', '/etc/teamvault.cfg')

    # teamvault plumbing
    unconfigured_settings = False
    try:
        django.setup()
    except UnconfiguredSettingsError:
        unconfigured_settings = True

    commands = list(get_commands())
    plumbing_help = f'One of: {",".join(commands)}'
    if unconfigured_settings:
        plumbing_help += ' - To see all available commands, configure teamvault settings with "teamvault setup"'

    parser_plumbing = subparsers.add_parser('plumbing')
    parser_plumbing.add_argument('plumbing_command', nargs=REMAINDER, help=plumbing_help)
    parser_plumbing.set_defaults(func=plumbing)

    # teamvault run
    parser_run = subparsers.add_parser('run')
    parser_run.add_argument('--bind', nargs='?', help='define bind, default is 127.0.0.1:8000')
    parser_run.add_argument(
        'gunicorn_args',
        nargs=REMAINDER,
        help='extra arguments passed verbatim to gunicorn (use -- as separator, e.g. teamvault run -- --threads 4)',
    )
    parser_run.set_defaults(func=run)

    # teamvault run_huey
    parser_run = subparsers.add_parser('run_huey')
    parser_run.set_defaults(func=run_huey)

    # teamvault setup
    parser_setup = subparsers.add_parser('setup')
    parser_setup.set_defaults(func=setup)

    # teamvault upgrade
    parser_upgrade = subparsers.add_parser('upgrade')
    parser_upgrade.set_defaults(func=upgrade)
    return parser


def main(*args):
    """
    Entry point for the 'teamvault' command line utility.

    args:   used for integration tests
    """
    if not args:
        args = sys.argv[1:]

    parser = build_parser()
    pargs = parser.parse_args(args)
    if not hasattr(pargs, 'func'):
        parser.print_help()
        sys.exit(2)
    pargs.func(pargs)


def plumbing(pargs):
    execute_from_command_line([''] + pargs.plumbing_command)


def run(pargs):
    execute_from_command_line(['', 'check'])
    gunicorn_settings = configure_gunicorn(get_config())

    argv = [
        'gunicorn',
        '--preload',
        '--workers',
        str(gunicorn_settings['workers']),
        '--timeout',
        str(gunicorn_settings['timeout']),
        '--max-requests',
        str(gunicorn_settings['max_requests']),
        '--max-requests-jitter',
        str(gunicorn_settings['max_requests_jitter']),
    ]
    if pargs.bind:
        argv.extend(['-b', pargs.bind])

    extra = list(pargs.gunicorn_args or [])
    if extra and extra[0] == '--':
        extra = extra[1:]
    argv.extend(extra)

    argv.append('teamvault.wsgi:application')

    print('Now open http://localhost:8000')
    # Replace this process with gunicorn so signals (SIGTERM from systemd,
    # Docker, etc.) reach gunicorn directly and graceful shutdown works.
    execvp('gunicorn', argv)


def run_huey(_pargs):
    execute_from_command_line(['', 'run_huey'])


def setup(_pargs):
    environ.setdefault('TEAMVAULT_CONFIG_FILE', '/etc/teamvault.cfg')
    create_default_config(environ['TEAMVAULT_CONFIG_FILE'])


def upgrade(_pargs):
    environ['DJANGO_SETTINGS_MODULE'] = 'teamvault.settings'
    environ.setdefault('TEAMVAULT_CONFIG_FILE', '/etc/teamvault.cfg')

    print('\n### Running migrations...\n')
    execute_from_command_line(['', 'migrate', '--noinput', '-v', '3', '--traceback'])

    from django.conf import settings

    from .apps.settings.models import Setting

    if Setting.get('fernet_key_hash', default=None) is None:
        print('\n### Storing fernet_key hash in database...\n')
        key_hash = sha1(settings.TEAMVAULT_SECRET_KEY.encode('utf-8')).hexdigest()
        Setting.set('fernet_key_hash', key_hash)

    print('\n### Gathering static files...\n')
    with contextlib.suppress(FileNotFoundError):
        rmtree(settings.STATIC_ROOT)
    pathlib.Path(settings.STATIC_ROOT).mkdir()
    execute_from_command_line(['', 'collectstatic', '--noinput'])

    print('\n### Updating search index...\n')
    execute_from_command_line(['', 'update_search_index'])
