from os import environ

from setuptools import setup, find_packages

# included here for running tests
environ.setdefault("DJANGO_SETTINGS_MODULE", "teamvault.settings")
environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")

setup(
    name="teamvault",
    version="0.9.2",
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
        "asgiref==3.4.1; python_version >= '3.6'",
        "brotli==1.0.9",
        "certifi==2021.5.30",
        "cffi==1.14.6",
        "charset-normalizer==2.0.4; python_version >= '3.0'",
        "cryptography==3.4.7",
        "defusedxml==0.7.1; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3, 3.4'",
        "django-auth-ldap==3.0.0",
        "django-filter==2.4.0",
        "django-gravatar2==1.4.4",
        "django==3.2.13",
        "djangorestframework==3.12.4",
        "gunicorn==20.1.0",
        "hashids==1.3.1",
        "idna==3.2; python_version >= '3.0'",
        "oauthlib==3.1.1; python_version >= '3.6'",
        "psycopg2==2.9.1",
        "pyasn1-modules==0.2.8",
        "pyasn1==0.4.8",
        "pycparser==2.20; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3'",
        "pyjwt==2.1.0; python_version >= '3.6'",
        "python-ldap==3.3.1; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3'",
        "python3-openid==3.2.0; python_version >= '3.0'",
        "pytz==2021.1",
        "requests-oauthlib==1.3.0",
        "requests==2.26.0; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3, 3.4, 3.5'",
        "social-auth-app-django==5.0.0",
        "social-auth-core==4.1.0; python_version >= '3.6'",
        "sqlparse==0.4.1; python_version >= '3.5'",
        "urllib3==1.26.6; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3, 3.4' and python_version < '4'",
        "whitenoise[brotli]==5.3.0",
    ],
    zip_safe=False,
)
