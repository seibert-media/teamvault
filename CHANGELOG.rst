0.4.2
=====

2015-05-19

* added a password copy confirmation message
* improved pagination
* made session settings configurable
* fixed duplicate search results


0.4.1
=====

2015-04-15

* fixed missing email templates in distribution
* fixed Python 3 tag on wheel distribution
* fixed exceptions not being logged
* fixed exception when closing access request as non-reviewer


0.4.0
=====

2015-04-06

* changed URLs to use hashids
* added substring search for filename, URL, and username
* added notification emails for access requests
* fixed display of allowed users/group in secret detail view


0.3.0
=====

2015-02-05

* added full text search
* added search API
* improved secret list display
* added pagination for secret lists
* relaxed URL validation even further


0.2.2
=====

2015-01-27

* fixed overzealous URL validation
* fixed access policy selection


0.2.1
=====

2015-01-20

* fixed uploading of non-tiny files (#30)
* fixed editing secrets without changing encrypted data (#30)


0.2.0
=====

2015-01-11

* added file secrets
* added credit card secrets
* added logging to syslog
* added `teamvault plumbing` command
* fixed login with some WebKit-based browsers


0.1.0
=====

2014-12-20

* first public release
