TeamVault
=========

TeamVault is an open-source web-based shared password manager for behind-the-firewall installation.

Installation
------------

.. hint:: You should use a virtualenv or at least a dedicated virtual machine for this.

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
