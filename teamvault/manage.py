#!/usr/bin/env python3
import os
import sys
from os.path import dirname, join, realpath

if __name__ == "__main__":
    sys.path.append(join(realpath(dirname(dirname(__file__)))))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "teamvault.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
