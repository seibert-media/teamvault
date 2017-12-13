from os import environ

from setuptools import setup, find_packages

# included here for running tests
environ.setdefault("DJANGO_SETTINGS_MODULE", "teamvault.settings")
environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")

setup(
    name="teamvault",
    version="0.7.3",
    description="Keep your passwords behind the firewall",
    author="Torsten Rehn",
    author_email="torsten@rehn.email",
    license="GPLv3",
    url="https://github.com/trehn/teamvault",
    package_dir={'': "src"},
    packages=find_packages("src"),
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
        "asn1crypto==0.23.0",
        "cffi==1.11.2; platform_python_implementation != 'PyPy'",
        "cryptography==2.1.4",
        "dj-static==0.0.6",
        "django==2.0",
        "django-auth-ldap==1.3.0",
        "django-gravatar2==1.4.2",
        "djangorestframework==3.7.3",
        "gunicorn==19.7.1",
        "hashids==1.2.0",
        "idna==2.6",
        "psycopg2==2.7.3.2",
        "pycparser==2.18",
        "pyldap==2.4.45; python_version >= '3.0'",
        "pytz==2017.3",
        "six==1.11.0",
        "static3==0.7.0",
    ],
    zip_safe=False,
)
