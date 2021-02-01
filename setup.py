from os import environ

from setuptools import setup, find_packages

# included here for running tests
environ.setdefault("DJANGO_SETTINGS_MODULE", "teamvault.settings")
environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")

setup(
    name="teamvault",
    version="0.9.0",
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
    install_requires=[  # pipenv lock -r
        "asgiref==3.3.1; python_version >= '3.5'",
        "brotli==1.0.9",
        "cffi==1.14.4",
        "cryptography==3.3.1",
        "django-auth-ldap==2.2.0",
        "django-filter==2.4.0",
        "django-gravatar2==1.4.4",
        "django==3.1.5",
        "djangorestframework==3.12.2",
        "gunicorn==20.0.4",
        "hashids==1.3.1",
        "psycopg2==2.8.6",
        "pyasn1-modules==0.2.8",
        "pyasn1==0.4.8",
        "pycparser==2.20; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3'",
        "python-ldap==3.3.1; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3'",
        "pytz==2020.5",
        "six==1.15.0; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3'",
        "sqlparse==0.4.1; python_version >= '3.5'",
        "whitenoise[brotli]==5.2.0",
    ],
    zip_safe=False,
)
