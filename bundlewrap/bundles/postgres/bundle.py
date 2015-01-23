pkg_apt = {
    "postgresql": {
        'triggers': ["action:create_role"],
    },
    "postgresql-contrib": {},
}

actions = {
    "create_role": {
        'command': "sudo -u postgres psql -c \"CREATE USER teamvault WITH NOCREATEDB NOCREATEUSER ENCRYPTED PASSWORD E'teamvault'\"",
        'triggered': True,
        'triggers': ["action:create_database"],
    },
    "create_database": {
        'command': "sudo -u postgres createdb -O teamvault teamvault",
        'triggered': True,
    },
}
