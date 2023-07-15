from os import environ

from setuptools import setup, find_packages

# included here for running tests
environ.setdefault("DJANGO_SETTINGS_MODULE", "teamvault.settings")
environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")

setup(
    name="teamvault",
    version="1.0.0rc1",
    description="Keep your passwords behind the firewall",
    author="//SEIBERT/MEDIA GmbH",
    license="GPLv3",
    url="https://github.com/seibert-media/teamvault",
    packages=find_packages(),
    include_package_data=True,
    test_suite="tests",
    entry_points={
        'console_scripts': [
            "teamvault=teamvault.cli:main",
        ],
    },
    keywords=["password", "safe", "manager", "sharing"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Framework :: Django",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Office/Business",
        "Topic :: Security",
    ],
    install_requires=[  # pipenv requirements
        "asgiref==3.7.2 ; python_version >= '3.7'",
        "brotli==1.0.9",
        "certifi==2023.5.7 ; python_version >= '3.6'",
        "cffi==1.15.1",
        "charset-normalizer==3.2.0 ; python_full_version >= '3.7.0'",
        "cryptography==41.0.2",
        "defusedxml==0.7.1 ; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3, 3.4'",
        "django==4.2.3",
        "django-auth-ldap==4.3.0",
        "django-bootstrap5==23.3",
        "django-filter==23.2",
        "django-htmx==1.16.0",
        "django-webpack-loader==2.0.1",
        "djangorestframework==3.14.0",
        "gunicorn==20.1.0",
        "hashids==1.3.1",
        "idna==3.4 ; python_version >= '3.5'",
        "oauthlib==3.2.2 ; python_version >= '3.6'",
        "psycopg2==2.9.6",
        "pyasn1==0.5.0 ; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3, 3.4, 3.5'",
        "pyasn1-modules==0.3.0 ; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3, 3.4, 3.5'",
        "pycparser==2.21 ; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3'",
        "pyjwt==2.7.0 ; python_version >= '3.7'",
        "python-ldap==3.4.3 ; python_version >= '3.6'",
        "python3-openid==3.2.0 ; python_version >= '3.0'",
        "pytz==2023.3",
        "requests==2.31.0 ; python_version >= '3.7'",
        "requests-oauthlib==1.3.1 ; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3'",
        "setuptools==68.0.0 ; python_version >= '3.7'",
        "social-auth-app-django==5.2.0",
        "social-auth-core==4.4.2 ; python_version >= '3.6'",
        "sqlparse==0.4.4 ; python_version >= '3.5'",
        "urllib3==2.0.3 ; python_version >= '3.7'",
        "whitenoise[brotli]==6.5.0",
    ],
    zip_safe=False,
)
