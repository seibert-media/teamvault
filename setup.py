from os import environ

from setuptools import setup, find_packages

# included here for running tests
environ.setdefault("DJANGO_SETTINGS_MODULE", "teamvault.settings")
environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")

setup(
    name="teamvault",
    version="0.6.0",
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
    install_requires=[
        "cryptography == 1.5.3",
        "dj-static == 0.0.6",
        "Django == 1.10.3",
        "django-auth-ldap == 1.2.8",
        "django-gravatar2 == 1.4.0",
        "djangorestframework == 3.5.0",
        "gunicorn == 19.6.0",
        "hashids == 1.1.0",
        "psycopg2 == 2.6.2",
        "pytz == 2016.6.1",
    ],
    zip_safe=False,
)
