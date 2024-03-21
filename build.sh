#!/usr/bin/env bash

if $(command -v bun); then
    BUILDER="bun" 
elif $(command -v yarn); then
    BUILDER="yarn"
else
    BUILDER="npm"
fi

PROJECT_DIR="$(dirname "$0")"
PKG_DIR="$PROJECT_DIR/dist"

cd "$PROJECT_DIR"

printf ">> Cleaning up old build packages...\n\n"
[ -e "$PKG_DIR" ] && printf "Deleting existing dist in $PKG_DIR...\n" && rm -r "$PKG_DIR"

printf ">> Creating webpack bundle via $BUILDER...\n\n"
$BUILDER run build
[ $? -eq 0 ] && printf "\n>> Bundle created.\n"

printf ">> Generating python package...\n\n"
python3 -m build
[ $? -eq 0 ] && printf "\n>> Generated python package in dist/."
