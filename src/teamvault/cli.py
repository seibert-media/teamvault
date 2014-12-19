from argparse import ArgumentParser
from gettext import gettext as _
from subprocess import Popen
from sys import argv

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
    parser_apply = subparsers.add_parser("run")
    parser_apply.set_defaults(func=run)
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
