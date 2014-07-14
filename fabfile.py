import os

from fabric.api import *
from fabric.colors import green, yellow

DEPLOYMENT = None

PROJECT_PATH = os.path.dirname(env.real_fabfile)
VENV_PATH = PROJECT_PATH + "/devenv"


def compile_translations():
    with lcd(PROJECT_PATH + "/src/teamvault"):
        local("../../devenv/bin/python ../manage_local.py compilemessages")


def devsetup():
    if os.path.exists(VENV_PATH):
        print(yellow("virtualenv dir already exists"))
    else:
        with cd(PROJECT_PATH):
            print(green("creating virtualenv..."))
            local("virtualenv " + VENV_PATH)
            print(green("installing dependencies..."))
            local(VENV_PATH + "/bin/pip install -r " + PROJECT_PATH + "/requirements.txt")
            print(green("linking teamvault into sys.path..."))
            local("ln -s {0} {1}".format(
                PROJECT_PATH + "/src/teamvault",
                VENV_PATH + "/lib/python2.7/site-packages",
            ))

    if os.path.exists(PROJECT_PATH + "/devdb.sqlite"):
        print(yellow("dev db already exists"))
    else:
        with cd(PROJECT_PATH):
            print(green("running initial schema migrations..."))
            local("./manage migrate")


def update_translations():
    with lcd(PROJECT_PATH + "/src/teamvault"):
        local("../../devenv/bin/python ../manage_local.py makemessages -a")
