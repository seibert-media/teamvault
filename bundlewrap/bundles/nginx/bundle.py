pkg_apt = {
    "nginx": {},
}

svc_systemv = {
    "nginx": {},
}

files = {
    "/etc/nginx/sites-enabled/teamvault.conf": {
        'content_type': 'text',
        'source': "teamvault.conf",
        'triggers': ["svc_systemv:nginx:reload"],
    }
}
