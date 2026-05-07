# TeamVault

TeamVault is an open-source web-based shared password manager for behind-the-firewall installation. It requires Python 3.12+ and PostgreSQL (with the unaccent extension).

## Installation

	apt-get install libffi-dev libldap2-dev libpq-dev libsasl2-dev python3.X-dev postgresql-contrib
	pip install teamvault
	teamvault setup
	vim /etc/teamvault.conf
	# note that the teamvault database user will need SUPERUSER privileges
	# during this step in order to activate the unaccent extension
	mkdir -p /var/lib/teamvault  # or whatever you set as `data_dir` in the config
	teamvault upgrade
	teamvault plumbing createsuperuser
	teamvault run

The `data_dir` setting in the `[teamvault]` section of the config file points to a writable directory used for runtime state (currently the huey scheduler's SQLite database). It defaults to `/var/lib/teamvault` and must exist and be writable by the user running TeamVault.

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
	                   # data_dir = /tmp  (or any writable path; default /var/lib/teamvault won't exist locally)
	teamvault upgrade
	teamvault plumbing createsuperuser

### Start the development server
	teamvault run

Now open http://localhost:8000

## Scheduled background jobs

We use [huey](https://huey.readthedocs.io/en/latest/) to run background jobs. This requires you to run a second process, in parallel to TeamVault itself. You can launch it via `manage.py`:

    teamvault run_huey

## Fernet key rotation

TeamVault encrypts all secrets with a Fernet key defined in your config file. To rotate this key:

1. Generate a new key:

		teamvault plumbing generate_fernet_key

2. Save your current `fernet_key` from the config file (you'll need it in step 4).

3. Replace `fernet_key` in your config file with the new key.

4. Re-encrypt all secrets with the new key:

		teamvault plumbing rotate_fernet_key <old_key>

   This re-encrypts all stored revisions in a single transaction. If anything fails, all changes are rolled back and your data remains encrypted with the old key.

5. Verify TeamVault starts without errors.

**Important:** The application must be stopped during key rotation to prevent read/write conflicts while secrets are being re-encrypted.

## Release process
Run the github action to cut a release with a specific version number.
