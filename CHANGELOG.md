# 0.9.2

2021-02-08

* follow deeplinks after Google login


# 0.9.1

2021-02-01

* fixed missing social auth depedency


# 0.9.0

2021-02-01

* added Google OAuth2
* added LDAP client certificate auth and StartTLS
* descriptions now have line breaks and clickable links
* improved LDAP debug logging
* removed Share button
* updated Python dependencies


# 0.8.5

2020-11-13

* fixed bootstrapping problem when running `teamvault upgrade` on empty DB


# 0.8.4

2019-11-06

* fixed sending email notifications


# 0.8.3

2019-10-24

* fixed creating access requests


# 0.8.2

2019-10-23

* fixed creating secrets by API


# 0.8.1

2019-09-23

* fixed packaging issue


# 0.8.0

2019-09-23

* added hidden URL parameters for filtering search results
* replaced owners with notification settings
* fixed storage of credit card CVV values as integers
* fixed deleting secrets by API
* fixed storing past iterations of passwords


# 0.7.3

2017-03-26

* fixed pagination with GET parameters


# 0.7.2

2017-03-13

* fixed missing opensearch.xml
* improved database integrity protection


# 0.7.1

2017-03-06

* fixed "needs changing on leave" option
* include actions on user in user audit log


# 0.7.0

2017-03-05

* added `teamvault run --bind`
* added audit log
* added OpenSearch
* added user management
* added user-friendly URLs to API output
* removed syslog logging in favor of stdout
* improved secret status diplay
* fixed access request API
* fixed API pagination


# 0.6.1

2016-11-07

* fixed an issue that prevented adding oneself to owners and allowed users


# 0.6.0

2016-11-06

* added search bar to every page
* added secret details in access request view
* added most used and recently used secrets to dashboard
* added secret owners
* new fonts
* removed broken hotkey copy feature
* fixed assignment of deactivated users as reviewers


# 0.5.1

2015-10-27

* added more copy confirmation messages
* used brighter colors for password strength indication
* fix exception when searching via API


# 0.5.0

2015-10-24

* added rudimentary password generator and strength meter
* added 404 error pages
* added secret restoration for admins
* fixed revealing credit card secrets
* fixed display of deleted secrets


# 0.4.3

2015-05-25

* show username field by default when adding passwords
* fixed `teamvault upgrade` missing update_search_field
* fixed typing in secret sharing modal


# 0.4.2

2015-05-19

* added a password copy confirmation message
* improved pagination
* made session settings configurable
* fixed duplicate search results


# 0.4.1

2015-04-15

* fixed missing email templates in distribution
* fixed Python 3 tag on wheel distribution
* fixed exceptions not being logged
* fixed exception when closing access request as non-reviewer


# 0.4.0

2015-04-06

* changed URLs to use hashids
* added substring search for filename, URL, and username
* added notification emails for access requests
* fixed display of allowed users/group in secret detail view


# 0.3.0

2015-02-05

* added full text search
* added search API
* improved secret list display
* added pagination for secret lists
* relaxed URL validation even further


# 0.2.2

2015-01-27

* fixed overzealous URL validation
* fixed access policy selection


# 0.2.1

2015-01-20

* fixed uploading of non-tiny files (#30)
* fixed editing secrets without changing encrypted data (#30)


# 0.2.0

2015-01-11

* added file secrets
* added credit card secrets
* added logging to syslog
* added `teamvault plumbing` command
* fixed login with some WebKit-based browsers


# 0.1.0

2014-12-20

* first public release
