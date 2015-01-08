pkg_apt = {
    "postgresql": {
        'triggers': ["action:create_role"],
    },
}

actions = {
    "create_role": {
        'command': "sudo -u postgres createuser -D -A teamvault",
        'triggered': True,
        'triggers': ["action:create_database"],
    },
    "create_database": {
        'command': "sudo -u postgres createdb -O teamvault teamvault",
        'triggered': True,
    },
}
