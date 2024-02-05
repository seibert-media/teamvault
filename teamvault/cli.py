from argparse import ArgumentParser, REMAINDER
from gettext import gettext as _
from hashlib import sha1
from os import environ, mkdir
from shutil import rmtree
from subprocess import Popen
from sys import argv

import django
from django.core.management import execute_from_command_line, get_commands

from teamvault.__version__ import __version__
from teamvault.apps.settings.config import create_default_config, UnconfiguredSettingsError


def build_parser():
    parser = ArgumentParser(prog="teamvault")
    parser.add_argument(
        "--version",
        action='version',
        version=__version__,
    )
    subparsers = parser.add_subparsers(
        title=_("subcommands"),
        help=_("use 'teamvault <subcommand> --help' for more info"),
    )

    environ['DJANGO_SETTINGS_MODULE'] = 'teamvault.settings'
    environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")

    # teamvault plumbing
    unconfigured_settings = False
    try:
        django.setup()
    except UnconfiguredSettingsError:
        unconfigured_settings = True

    commands = [k for k in get_commands()]
    plumbing_help = f'One of: {",".join(commands)}'
    if unconfigured_settings:
        plumbing_help += " - To see all available commands, configure teamvault settings with \"teamvault setup\""

    parser_plumbing = subparsers.add_parser("plumbing")
    parser_plumbing.add_argument('plumbing_command', nargs=REMAINDER, help=plumbing_help)
    parser_plumbing.set_defaults(func=plumbing)

    # teamvault run
    parser_run = subparsers.add_parser("run")
    parser_run.add_argument('--bind', nargs='?', help='define bind, default is 127.0.0.1:8000')
    parser_run.set_defaults(func=run)

    # teamvault run_huey
    parser_run = subparsers.add_parser("run_huey")
    parser_run.set_defaults(func=run_huey)

    # teamvault setup
    parser_setup = subparsers.add_parser("setup")
    parser_setup.set_defaults(func=setup)

    # teamvault upgrade
    parser_upgrade = subparsers.add_parser("upgrade")
    parser_upgrade.set_defaults(func=upgrade)
    return parser


def main(*args):
    """
    Entry point for the 'teamvault' command line utility.

    args:   used for integration tests
    """
    if not args:
        args = argv[1:]

    parser = build_parser()
    pargs = parser.parse_args(args)
    if not hasattr(pargs, 'func'):
        parser.print_help()
        exit(2)
    pargs.func(pargs)


def plumbing(pargs):
    execute_from_command_line([""] + pargs.plumbing_command)


def run(pargs):
    cmd = "gunicorn --preload teamvault.wsgi:application"
    if pargs.bind:
        cmd += ' -b ' + pargs.bind

    print("Now open http://localhost:8000")
    gunicorn = Popen(
        cmd,
        shell=True,
    )
    gunicorn.communicate()


def run_huey(pargs):
    execute_from_command_line(["", "run_huey"])


def setup(pargs):
    environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")
    create_default_config(environ['TEAMVAULT_CONFIG_FILE'])


def upgrade(pargs):
    environ['DJANGO_SETTINGS_MODULE'] = 'teamvault.settings'
    environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")

    print("\n### Running migrations...\n")
    execute_from_command_line(["", "migrate", "--noinput", "-v", "3", "--traceback"])

    from django.conf import settings
    from .apps.settings.models import Setting

    if Setting.get("fernet_key_hash", default=None) is None:
        print("\n### Storing fernet_key hash in database...\n")
        key_hash = sha1(settings.TEAMVAULT_SECRET_KEY.encode('utf-8')).hexdigest()
        Setting.set("fernet_key_hash", key_hash)

    print("\n### Gathering static files...\n")
    try:
        rmtree(settings.STATIC_ROOT)
    except FileNotFoundError:
        pass
    mkdir(settings.STATIC_ROOT)
    execute_from_command_line(["", "collectstatic", "--noinput"])

    print("\n### Updating search index...\n")
    execute_from_command_line(["", "update_search_index"])
