#!/bin/bash
# Removes useless clutter from our bower dependencies :(

BASE_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
BUNDLED_DIR="${BASE_DIR}/src/teamvault/static/bundled"

# bigtext
rm -rvf ${BUNDLED_DIR}/bigtext/demo
rm -rvf ${BUNDLED_DIR}/bigtext/grunt
rm -rvf ${BUNDLED_DIR}/bigtext/src
rm -rvf ${BUNDLED_DIR}/bigtext/test
rm -rvf ${BUNDLED_DIR}/bigtext/Gruntfile.js
rm -rvf ${BUNDLED_DIR}/bigtext/package.json
rm -rvf ${BUNDLED_DIR}/bigtext/README.md

# bootstrap
rm -rvf ${BUNDLED_DIR}/bootstrap/fonts
rm -rvf ${BUNDLED_DIR}/bootstrap/grunt
rm -rvf ${BUNDLED_DIR}/bootstrap/js
rm -rvf ${BUNDLED_DIR}/bootstrap/less
rm -rvf ${BUNDLED_DIR}/bootstrap/Gruntfile.js
rm -rvf ${BUNDLED_DIR}/bootstrap/package.json
rm -rvf ${BUNDLED_DIR}/bootstrap/README.md

# card
rm -rvf ${BUNDLED_DIR}/card/src
rm -rvf ${BUNDLED_DIR}/card/gulpfile.coffee
rm -rvf ${BUNDLED_DIR}/card/package.json
rm -rvf ${BUNDLED_DIR}/card/README.md

# font-awesome
rm -rvf ${BUNDLED_DIR}/font-awesome/less
rm -rvf ${BUNDLED_DIR}/font-awesome/scss
rm -rvf ${BUNDLED_DIR}/font-awesome/.gitignore
rm -rvf ${BUNDLED_DIR}/font-awesome/.npmignore

# jquery
rm -rvf ${BUNDLED_DIR}/jquery/src

# password-generator
rm -rvf ${BUNDLED_DIR}/password-generator/*.html
rm -rvf ${BUNDLED_DIR}/password-generator/*.js
rm -rvf ${BUNDLED_DIR}/password-generator/*.yml
rm -rvf ${BUNDLED_DIR}/password-generator/.gitignore
rm -rvf ${BUNDLED_DIR}/password-generator/bin
rm -rvf ${BUNDLED_DIR}/password-generator/dist/password-generator.js
rm -rvf ${BUNDLED_DIR}/password-generator/lib
rm -rvf ${BUNDLED_DIR}/password-generator/Makefile
rm -rvf ${BUNDLED_DIR}/password-generator/test

# select2
rm -rvf ${BUNDLED_DIR}/select2/.gitignore
rm -rvf ${BUNDLED_DIR}/select2/component.json
rm -rvf ${BUNDLED_DIR}/select2/*.md
rm -rvf ${BUNDLED_DIR}/select2/package.json
rm -rvf ${BUNDLED_DIR}/select2/release.sh
rm -rvf ${BUNDLED_DIR}/select2/select2.js
rm -rvf ${BUNDLED_DIR}/select2/select2_locale_*

# select2-bootstrap
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/_jekyll
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/compass
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/docs
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/lib
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/test
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/Gemfile
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/Gruntfile.js
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/Makefile
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/package.json
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/README.md
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/select2-bootstrap-css.gemspec

# typeahead.js
rm -rvf ${BUNDLED_DIR}/typeahead.js/doc
rm -rvf ${BUNDLED_DIR}/typeahead.js/src
rm -rvf ${BUNDLED_DIR}/typeahead.js/test
rm -rvf ${BUNDLED_DIR}/typeahead.js/.gitignore
rm -rvf ${BUNDLED_DIR}/typeahead.js/.jshintrc
rm -rvf ${BUNDLED_DIR}/typeahead.js/.travis.yml
rm -rvf ${BUNDLED_DIR}/typeahead.js/composer.json
rm -rvf ${BUNDLED_DIR}/typeahead.js/*.md
rm -rvf ${BUNDLED_DIR}/typeahead.js/Gruntfile.js
rm -rvf ${BUNDLED_DIR}/typeahead.js/karma.conf.js
rm -rvf ${BUNDLED_DIR}/typeahead.js/package.json
rm -rvf ${BUNDLED_DIR}/typeahead.js/typeahead.js.jquery.json

# underscore
rm -rvf ${BUNDLED_DIR}/underscore/.eslintrc
rm -rvf ${BUNDLED_DIR}/underscore/.gitignore
rm -rvf ${BUNDLED_DIR}/underscore/component.json
rm -rvf ${BUNDLED_DIR}/underscore/package.json
rm -rvf ${BUNDLED_DIR}/underscore/README.md
rm -rvf ${BUNDLED_DIR}/underscore/underscore.js

# zeroclipboard
rm -rvf ${BUNDLED_DIR}/zeroclipboard/dist/.jshintrc
rm -rvf ${BUNDLED_DIR}/zeroclipboard/dist/ZeroClipboard.Core.js
rm -rvf ${BUNDLED_DIR}/zeroclipboard/dist/ZeroClipboard.js
