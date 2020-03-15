#!/usr/bin/env bash

set -x

#####################
### CONFIGURATION ###
#####################

# RELIC version of March 15, 2020
RELIC_VERSION=13f88f6e6fa3c54b48309baa16cd19c61b4bd850

# Configure RELIC to use the BLS-381 pairing curve
PRESET=preset/x64-pbc-bls381.sh

APT_INSTALL="sudo DEBIAN_FRONTEND=noninteractive apt-get install -qq"

############################
### INSTALL DEPENDENCIES ###
############################

sudo apt-get update
$APT_INSTALL git

# Not strictly necessary for building RELIC
$APT_INSTALL build-essential libgmp-dev libsodium-dev libssl-dev ntpdate
sudo ntpdate -u pool.ntp.org

$APT_INSTALL cmake

#####################
### INSTALL RELIC ###
#####################

mkdir -p ~/local/
cd ~/local/

if [ ! -d relic ]; then
    git clone https://github.com/relic-toolkit/relic.git
    cd relic
    git checkout $RELIC_VERSION
    cd ..
fi
cd relic

# Build RELIC
$PRESET
make
sudo make install
