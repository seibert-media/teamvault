#!/usr/bin/env bash

printf ">> Creating webpack bundle...\n\n"
yarn run build
[ $? -eq 0 ] && printf "\n>> Bundle created.\n"

printf ">> Checking setup.py...\n\n"
python3 setup.py check
printf "\n>> setup.py checked.\n"

printf ">> Generating python package...\n\n"
python3 setup.py sdist
printf "\n>> Generated python package in dist/."
