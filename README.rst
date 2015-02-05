TeamVault
=========

TeamVault is an open-source web-based shared password manager for behind-the-firewall installation. It requires Python 3.3+ and Postgres (with the unaccent extension).

Installation
------------

.. code-block::

	apt-get install libffi-dev libpq-dev mercurial python3.4-dev postgresql-contrib
	pip install teamvault
	pip install hg+https://bitbucket.org/kavanaugh_development/django-auth-ldap@python3-ldap
	teamvault setup
	vim /etc/teamvault.conf
	# note that the teamvault database user will need SUPERUSER privileges
	# during this step in order to activate the unaccent extension
	teamvault upgrade
	teamvault run

Update
------

.. code-block::

	pip install --upgrade teamvault
	teamvault upgrade

Development VM
--------------

.. code-block::

	pip install bundlewrap
	vagrant up
	vagrant ssh -c "sudo teamvault plumbing createsuperuser"
	vagrant ssh -c "sudo teamvault upgrade && sudo teamvault run"

Go to http://teamvault and log in with the username and password you set.
To handle code changes, just interrupt the last command with CTRL+C and run it again.
