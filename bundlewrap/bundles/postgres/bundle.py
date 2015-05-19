pkg_apt = {
    "postgresql": {},
    "postgresql-contrib": {},
}

postgres_dbs = {
    "teamvault": {
        'owner': "teamvault",
    },
}

postgres_roles = {
    "teamvault": {
        'superuser': True,
        'password': "teamvault",
    },
}
