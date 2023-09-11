#!/usr/bin/env bash

printf ">> Creating webpack bundle...\n\n"
yarn run build
[ $? -eq 0 ] && printf "\n>> Bundle created.\n"

printf ">> Generating python package...\n\n"
python3 -m build
printf "\n>> Generated python package in dist/."
