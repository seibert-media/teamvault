#!/usr/bin/env python3
import os
import sys
from pathlib import Path

if __name__ == '__main__':
    sys.path.append(str(Path(__file__).resolve().parents[1]))
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'teamvault.settings')

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
