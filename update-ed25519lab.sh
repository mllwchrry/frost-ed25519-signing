#!/bin/sh

# Update the ed25519lab git subtree to the latest upstream version
#
# The ed25519lab library is vendored as a git subtree at python/ed25519lab/
# This script updates it to the latest version from the upstream repository.

git fetch https://github.com/DarkWindman/ed25519lab.git main
git subtree pull --prefix=python/ed25519lab https://github.com/DarkWindman/ed25519lab.git main --squash
