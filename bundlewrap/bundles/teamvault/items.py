pkg_apt = {
    "build-essential": {},
    "libffi-dev": {},
    "libldap2-dev": {},
    "libpq-dev": {},
    "libsasl2-dev": {},
    "libssl-dev": {},
    #"mercurial": {},
    "python3-pip": {},
    "python3-setuptools": {},
    "python3.5-dev": {},
}

actions = {
    "teamvault_install": {
        'command': "pip3 install -U pip && pip3 install -e /teamvault/",
        'needs': [
            "pkg_apt:",
        ],
        #'triggered': True,
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
            "action:teamvault_enable_debugging",
        ],
    },
    "teamvault_enable_debugging": {
        'command': "sed -i 's/^insecure_debug_mode = .*$/insecure_debug_mode = enabled/' /etc/teamvault.cfg",
        'triggered': True,
        'triggers': [
            "action:teamvault_upgrade",
        ],
    },
    "teamvault_upgrade": {
        'command': "teamvault upgrade",
        'triggered': True,
    },
    "apt_update": {
        'command': "apt-get update",
        'needed_by': ["pkg_apt:"],
    }
}
