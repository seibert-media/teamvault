pkg_apt = {
    "python3-setuptools": {},
    "mercurial": {},
    "libpq-dev": {},
    "libffi-dev": {},
    "python3.4-dev": {
        'triggers': [
            "action:teamvault_install",
        ],
    },
}

actions = {
    "teamvault_install": {
        'command': "cd /teamvault && python3.4 setup.py develop",
        'needs': [
            "pkg_apt:",
        ],
        'triggered': True,
        'triggers': [
            "action:teamvault_setup",
        ],
    },
    "teamvault_setup": {
        'command': "teamvault setup",
        'triggered': True,
        'triggers': [
            "action:teamvault_set_base_url",
        ],
    },
    "teamvault_set_base_url": {
        'command': "sed -i 's/^base_url = .*$/base_url = http:\\/\\/teamvault/' /etc/teamvault.cfg",
        'triggered': True,
    },
}
