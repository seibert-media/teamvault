pkg_apt = {
    "python3-setuptools": {},
    "mercurial": {},
    "libpq-dev": {},
    "libffi-dev": {},
    "python3-pip": {
        'triggers': [
            "action:teamvault_install",
        ],
    },
    "python3.4-dev": {},
}

actions = {
    "teamvault_install": {
        'command': "pip3 install -e /teamvault/",
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
        'triggers': [
            "action:teamvault_upgrade",
        ],
    },
    "teamvault_upgrade": {
        'command': "teamvault upgrade",
        'triggered': True,
    },
}
