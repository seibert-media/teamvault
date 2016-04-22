pkg_apt = {
    "postgresql": {
        'needed_by': ["postgres_db:", "postgres_role:"],
    },
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
