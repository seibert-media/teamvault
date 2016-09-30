from argparse import ArgumentParser
from gettext import gettext as _
from os import environ, mkdir
from shutil import rmtree
from subprocess import Popen
from sys import argv

from django.core.management import execute_from_command_line

from .apps.settings.config import create_default_config
from . import VERSION_STRING


def build_parser():
    parser = ArgumentParser(prog="teamvault")
    parser.add_argument(
        "--version",
        action='version',
        version=VERSION_STRING,
    )
    subparsers = parser.add_subparsers(
        title=_("subcommands"),
        help=_("use 'teamvault <subcommand> --help' for more info"),
    )

    # teamvault plumbing
    parser_plumbing = subparsers.add_parser("plumbing")
    parser_plumbing.add_argument('plumbing_command', nargs='+')
    parser_plumbing.set_defaults(func=plumbing)

    # teamvault run
    parser_run = subparsers.add_parser("run")
    parser_run.set_defaults(func=run)

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

    pargs.func(pargs)


def plumbing(pargs):
    environ['DJANGO_SETTINGS_MODULE'] = 'teamvault.settings'
    environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")
    execute_from_command_line([""] + pargs.plumbing_command[0].split(" "))


def run(pargs):
    gunicorn = Popen(
        "gunicorn --preload teamvault.wsgi:application",
        shell=True,
    )
    gunicorn.communicate()


def setup(pargs):
    environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")
    create_default_config(environ['TEAMVAULT_CONFIG_FILE'])


def upgrade(pargs):
    environ['DJANGO_SETTINGS_MODULE'] = 'teamvault.settings'
    environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")

    print("\n### Running migrations...\n")
    execute_from_command_line(["", "migrate", "--noinput", "-v", "3", "--traceback"])

    print("\n### Gathering static files...\n")
    from django.conf import settings
    try:
        rmtree(settings.STATIC_ROOT)
    except FileNotFoundError:
        pass
    mkdir(settings.STATIC_ROOT)
    execute_from_command_line(["", "collectstatic", "--noinput"])

    print("\n### Updating search index...\n")
    execute_from_command_line(["", "update_search_index"])
