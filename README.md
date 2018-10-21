# TeamVault

TeamVault is an open-source web-based shared password manager for behind-the-firewall installation. It requires Python 3.3+ and Postgres (with the unaccent extension).

## Installation

	apt-get install libffi-dev libldap2-dev libpq-dev libsasl2-dev python3.6-dev postgresql-contrib
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
