TeamVault
=========

TeamVault is an open-source web-based shared password manager for behind-the-firewall installation. It requires Python 3.3+ and Postgres.

Installation
------------

.. code-block::

	apt-get install libffi-dev libpq-dev mercurial python3.4-dev
	pip install teamvault
	pip install hg+https://bitbucket.org/kavanaugh_development/django-auth-ldap@python3-ldap
	teamvault setup
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
	vagrant ssh -c "sudo teamvault upgrade"
	vagrant ssh -c "sudo teamvault plumbing createsuperuser"
	vagrant ssh -c "sudo teamvault run"

Go to http://teamvault and log in with the username and password you set.
To handle code changes, just interrupt the command and run:

.. code-block::

	vagrant ssh -c "sudo teamvault upgrade && sudo teamvault run"
