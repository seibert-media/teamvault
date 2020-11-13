from os import environ

from setuptools import setup, find_packages

# included here for running tests
environ.setdefault("DJANGO_SETTINGS_MODULE", "teamvault.settings")
environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")

setup(
    name="teamvault",
    version="0.8.5",
    description="Keep your passwords behind the firewall",
    author="Torsten Rehn",
    author_email="torsten@rehn.email",
    license="GPLv3",
    url="https://github.com/trehn/teamvault",
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
    install_requires=[  # pipenv lock -r | sed "s/ --hash.*//g"
        "asn1crypto==0.24.0",
        "cffi==1.12.3",
        "cryptography==2.7",
        "dj-static==0.0.6",
        "django-auth-ldap==2.0.0",
        "django-filter==2.2.0",
        "django-gravatar2==1.4.2",
        "django==2.2.5",
        "djangorestframework==3.10.3",
        "gunicorn==19.9.0",
        "hashids==1.2.0",
        "psycopg2==2.8.3",
        "pyasn1-modules==0.2.6",
        "pyasn1==0.4.7",
        "pycparser==2.19",
        "python-ldap==3.2.0",
        "pytz==2019.2",
        "six==1.12.0",
        "sqlparse==0.3.0",
        "static3==0.7.0",
    ],
    zip_safe=False,
)
