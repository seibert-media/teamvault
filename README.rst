TeamVault
=========

TeamVault is an open-source web-based shared password manager for behind-the-firewall installation. It requires Python 3.3+ and Postgres.

Installation
------------

.. code-block::

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
