#!/bin/bash
# Removes useless clutter from our bower dependencies :(

BASE_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
BUNDLED_DIR="${BASE_DIR}/src/teamvault/static/bundled"

rm -rvf ${BUNDLED_DIR}/*/*.gemspec
rm -rvf ${BUNDLED_DIR}/*/*.html
rm -rvf ${BUNDLED_DIR}/*/*.map
rm -rvf ${BUNDLED_DIR}/*/*.sh
rm -rvf ${BUNDLED_DIR}/*/*.yml
rm -rvf ${BUNDLED_DIR}/*/.*.yml
rm -rvf ${BUNDLED_DIR}/*/.editorconfig
rm -rvf ${BUNDLED_DIR}/*/.eslintrc
rm -rvf ${BUNDLED_DIR}/*/.gitignore
rm -rvf ${BUNDLED_DIR}/*/.jshintignore
rm -rvf ${BUNDLED_DIR}/*/.jshintrc
rm -rvf ${BUNDLED_DIR}/*/.npmignore
rm -rvf ${BUNDLED_DIR}/*/AUTHORS.*
rm -rvf ${BUNDLED_DIR}/*/CHANGELOG.*
rm -rvf ${BUNDLED_DIR}/*/CONTRIBUTING.*
rm -rvf ${BUNDLED_DIR}/*/dist/*.map
rm -rvf ${BUNDLED_DIR}/*/dist/test
rm -rvf ${BUNDLED_DIR}/*/doc
rm -rvf ${BUNDLED_DIR}/*/docs
rm -rvf ${BUNDLED_DIR}/*/Gemfile
rm -rvf ${BUNDLED_DIR}/*/Gemfile.lock
rm -rvf ${BUNDLED_DIR}/*/Gruntfile.js
rm -rvf ${BUNDLED_DIR}/*/gulpfile.coffee
rm -rvf ${BUNDLED_DIR}/*/ISSUE_TEMPLATE.*
rm -rvf ${BUNDLED_DIR}/*/less
rm -rvf ${BUNDLED_DIR}/*/Makefile
rm -rvf ${BUNDLED_DIR}/*/package.json
rm -rvf ${BUNDLED_DIR}/*/PULL_REQUEST_TEMPLATE.*
rm -rvf ${BUNDLED_DIR}/*/README.*
rm -rvf ${BUNDLED_DIR}/*/scss
rm -rvf ${BUNDLED_DIR}/*/src
rm -rvf ${BUNDLED_DIR}/*/test
rm -rvf ${BUNDLED_DIR}/*/tests


# bigtext
rm -rvf ${BUNDLED_DIR}/bigtext/demo
rm -rvf ${BUNDLED_DIR}/bigtext/grunt

# bootstrap
rm -rvf ${BUNDLED_DIR}/bootstrap/fonts
rm -rvf ${BUNDLED_DIR}/bootstrap/grunt
rm -rvf ${BUNDLED_DIR}/bootstrap/js
rm -rvf ${BUNDLED_DIR}/bootstrap/less

# card
rm -rvf ${BUNDLED_DIR}/card/webpack.config.js

# password-generator
rm -rvf ${BUNDLED_DIR}/password-generator/*.js
rm -rvf ${BUNDLED_DIR}/password-generator/bin
rm -rvf ${BUNDLED_DIR}/password-generator/dist/password-generator.js
rm -rvf ${BUNDLED_DIR}/password-generator/lib

# font-awesome
rm -rvf ${BUNDLED_DIR}/font-awesome/HELP-US-OUT.txt

# select2-bootstrap
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/_jekyll
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/compass
rm -rvf ${BUNDLED_DIR}/select2-bootstrap/lib

# typeahead.js
rm -rvf ${BUNDLED_DIR}/typeahead.js/composer.json
rm -rvf ${BUNDLED_DIR}/typeahead.js/karma.conf.js
rm -rvf ${BUNDLED_DIR}/typeahead.js/typeahead.js.jquery.json

# underscore
rm -rvf ${BUNDLED_DIR}/underscore/component.json
rm -rvf ${BUNDLED_DIR}/underscore/underscore.js

# zeroclipboard
rm -rvf ${BUNDLED_DIR}/zeroclipboard/dist/.jshintrc
rm -rvf ${BUNDLED_DIR}/zeroclipboard/dist/ZeroClipboard.Core.js
rm -rvf ${BUNDLED_DIR}/zeroclipboard/dist/ZeroClipboard.js
