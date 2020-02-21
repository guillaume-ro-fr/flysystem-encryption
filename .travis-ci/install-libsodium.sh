#!/bin/sh
# The purpose of this file is to install libsodium in
# the Travis CI environment. Outside this environment,
# you would probably not want to install it like this.
# @see https://github.com/google/hat-backup/blob/master/travis-install-libsodium.sh

set -e

# check if libsodium is already installed
if [ ! -d "$HOME/libsodium/lib" ]; then
  wget https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz
  tar xvfz libsodium-1.0.18.tar.gz
  cd libsodium-1.0.18.tar.gz
  ./configure --prefix=$HOME/libsodium
  make
  make install
else
  echo 'Using cached directory for LibSodium.'
fi
