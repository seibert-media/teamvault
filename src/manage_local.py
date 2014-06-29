#!/usr/bin/env python
from os import environ
from os.path import dirname, join
from sys import argv

if __name__ == "__main__":
    environ.setdefault("DJANGO_SETTINGS_MODULE", "sheldon.settings.local")
    environ.setdefault("SHELDON_CONFIG_FILE", join(dirname(dirname(__file__)), "sheldon.cfg"))

    from django.core.management import execute_from_command_line

    execute_from_command_line(argv)
