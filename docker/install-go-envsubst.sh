#!/usr/bin/env sh
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -e

ARCH="$(dpkg --print-architecture)"
DOWNLOAD_ARCH=""

case "$ARCH" in
  amd64)
    DOWNLOAD_ARCH="x86_64"
    ;;
  arm64)
    DOWNLOAD_ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

curl -s --fail-with-body -L "https://github.com/a8m/envsubst/releases/download/v1.4.3/envsubst-Linux-${DOWNLOAD_ARCH}" -o envsubst && \
  chmod a+x envsubst && \
  mv envsubst /usr/local/bin/
