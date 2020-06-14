FROM ubuntu:bionic

MAINTAINER Wouter Lueks <wouter.lueks@epfl.ch>

RUN apt-get update \
    && apt-get install -y \
       build-essential \
       cmake \
       git \
       libgmp-dev \
       libsodium-dev \
       libssl-dev \
    && rm -r /var/lib/apt/lists/*

WORKDIR /tmp
RUN git clone https://github.com/relic-toolkit/relic.git \
    && cd relic \
    && git checkout 13f88f6e6fa3c54b48309baa16cd19c61b4bd850 \
    && preset/x64-pbc-bls381.sh \
    && make \
    && make install
