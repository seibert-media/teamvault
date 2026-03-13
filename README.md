# TeamVault

TeamVault is an open-source web-based shared password manager for behind-the-firewall installation. It requires Python 3.12+ and PostgreSQL (with the unaccent extension).

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
Run the github action to cut a release with a specific version number.
