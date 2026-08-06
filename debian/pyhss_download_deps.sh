#!/bin/sh -e
# Get python dependencies for which we can't use the debian packages from pip
# and vendor them in "debian/deps", so we can build the debian package offline.
# Copyright 2026 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
PYHSS_DIR="$(realpath "$(dirname "$0")/..")"
REQ_TXT=debian/deps/requirements.txt
cd "$PYHSS_DIR"

if [ -e debian/deps ]; then
	echo "ERROR: debian/deps exists already!"
	exit 1
fi

mkdir debian/deps

# Start with requirements.txt dependencies marked as 'vendor-in-deb' and add
# transitive deps and additional build deps below
grep "# vendor-in-deb" requirements.txt >"$REQ_TXT"

# pyosmocom runtime deps
# https://gitea.osmocom.org/osmocom/pyosmocom/src/branch/master/requirements.txt
echo "gsm0338==1.1.0" >>"$REQ_TXT"

# flask-restx runtime deps
# https://github.com/python-restx/flask-restx/blob/master/requirements/install.pip
echo "importlib_resources~=6.5" >>"$REQ_TXT"

# build deps (system versions cannot be used)
echo "flit_core<4,>=3.11" >>"$REQ_TXT"
echo "packaging>=24.0" >>"$REQ_TXT"
echo "poetry-core>=1.0.0" >>"$REQ_TXT"
echo "setuptools-scm~=10.2" >>"$REQ_TXT"
echo "setuptools~=78.1" >>"$REQ_TXT"
echo "vcs-versioning~=2.2" >>"$REQ_TXT"
echo "wheel~=0.46" >>"$REQ_TXT"

pip download \
	--dest debian/deps \
	--no-binary=:all: \
	--no-deps \
	-r "$REQ_TXT"

echo "Done"
