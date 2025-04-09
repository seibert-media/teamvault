# TeamVault

TeamVault is an open-source web-based shared password manager for behind-the-firewall installation. It requires Python 3.10+ and PostgreSQL (with the unaccent extension).

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
### Start a PostgreSQL database
Create a database and superuser for TeamVault to use, for example by starting a Docker container:

	docker run --rm --detach --publish=5432:5432 --name teamvault-postgres -e POSTGRES_USER=teamvault -e POSTGRES_PASSWORD=teamvault postgres:latest


### Run Webpack to serve static files
To compile all JS & SCSS files, you'll need to install all required packages via bun (or yarn/npm) with node >= v18.

Use ```bun/yarn/npm run serve``` to start a dev server.

**Note**:
Some MacOS users have reported errors when running the dev server via bun. In this case feel free to switch to NPM.


### Configure your Virtualenv via uv
	uv sync

### Setup TeamVault
	export TEAMVAULT_CONFIG_FILE=teamvault.cfg
	teamvault setup
	vim teamvault.cfg  # base_url = http://localhost:8000
	                   # session_cookie_secure = False
	                   # database config as needed
	teamvault upgrade
	teamvault plumbing createsuperuser

### Start the development server
	teamvault run

Now open http://localhost:8000

## Scheduled background jobs

We use [huey](https://huey.readthedocs.io/en/latest/) to run background jobs. This requires you to run a second process, in parallel to TeamVault itself. You can launch it via `manage.py`:

    teamvault run_huey

## Release process
1. Bump the version in ```teamvault/__version__.py``` and ```pyproject.toml```
2. Update CHANGELOG.md with the new version and current date
3. Make a release commit with the changes made above
4. Push the commit
5. Run ```./build.sh``` to create a new package
6. Sign and push the artifacts to PyPI via ```uv publish```
7. Test that the package can be installed: ```uv run --isolated --no-cache --prerelease allow --with teamvault --no-project -- teamvault --version```
8. Add a new GitHub release
