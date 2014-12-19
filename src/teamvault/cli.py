from argparse import ArgumentParser
from gettext import gettext as _
from os import environ
from subprocess import Popen
from sys import argv

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

    # teamvault run
    parser_run = subparsers.add_parser("run")
    parser_run.set_defaults(func=run)

    # teamvault setup
    parser_setup = subparsers.add_parser("setup")
    parser_setup.set_defaults(func=setup)
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


def run(pargs):
    gunicorn = Popen(
        "gunicorn teamvault.wsgi:application",
        shell=True,
    )
    gunicorn.communicate()


def setup(pargs):
    create_default_config(environ['TEAMVAULT_CONFIG_FILE'])
