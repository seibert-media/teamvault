# TeamVault

TeamVault is an open-source web-based shared password manager for behind-the-firewall installation. It requires Python 3.8+ and PostgreSQL (with the unaccent extension).

## Installation

	apt-get install libffi-dev libldap2-dev libpq-dev libsasl2-dev python3.X-dev postgresql-contrib
	pip install teamvault
	teamvault setup
	vim /etc/teamvault.conf
	# note that the teamvault database user will need SUPERUSER privileges
	# during this step in order to activate the unaccent extension
	teamvault upgrade
	teamvault plumbing createsuperuser
	teamvault run

## Update

	pip install --upgrade teamvault
	teamvault upgrade

## Development

Install Postgres and create a database and superuser for TeamVault to use, for example by starting a Docker container:

	docker run --rm --detach --publish=5432:5432 --name teamvault-postgres -e POSTGRES_USER=teamvault -e POSTGRES_PASSWORD=teamvault postgres:latest


To compile all JS & SCSS files, you'll need to install all required packages via bun (or yarn/npm) with node >= v18.

Use ```bun/yarn/npm run serve``` to start a dev server.


Now create a virtual environment to install and configure TeamVault in:

	pipenv install
	pipenv shell
	pip install -e .
	export TEAMVAULT_CONFIG_FILE=teamvault.cfg
	teamvault setup
	vim teamvault.cfg  # base_url = http://localhost:8000
	                   # session_cookie_secure = False
	                   # database config as needed
	teamvault upgrade
	teamvault plumbing createsuperuser
	teamvault run

Now open http://localhost:8000

## Scheduled background jobs

We use [huey](https://huey.readthedocs.io/en/latest/) to run background jobs. This requires you to run a second process, in parallel to TeamVault itself. You can launch it via `manage.py`:

    teamvault run_huey

## Release process
1. Install the "build" and "twine" packages via pip
2. Bump the version in ```teamvault/__version__.py```
3. Update CHANGELOG.md with the new version and current date
4. Make a release commit with the changes made above
5. Push the commit
6. Run ```./build.sh``` to create a new package
7. Sign and push the artifacts to PyPI (```twine upload -s dist/*```)
8. Add a new GitHub release
