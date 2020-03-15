# Tandem proof of concept

This repository accompanies the paper "Tandem: Securing Keys by Using a Central Server While Preserving Privacy" by Wouter Lueks, Brinda Hampiholi, Greg Alpár, and Carmela Troncoso, which will be included in PoPETs 2020.3. This repository contains a proof of concept implementation of the timing critical Tandem protocols.

The goal of this repository is to enable reproducing the measurements in the paper.

## Getting started using the Vagrant VM

This repository includes a Vagrant virtual machine that will install and configure all the necessary dependencies. To use it, first install [Vagrant](https://www.vagrantup.com/) using your package manager of choice, and then call (from the root of this repository):

```
vagrant up
```

This will setup an Ubuntu virtual machine, install the required dependencies, and compile RELIC. You can access this machine by calling:

```
vagrant ssh
```

The source files of this repository are in the `/vagrant` directory.

## Installing dependencies by hand (Linux only)

Alternatively, and only on recent Linux machine, you can also try to install the
dependencies by hand. Compare with the `tools/bootstrap-relic.sh` script that is
used to set up the virtual machine on Ubuntu Bionic. First, install the
necessary dependencies:

```
apt-get install build-essential libgmp-dev libsodium-dev libssl-dev cmake
```

Next, checkout and build RELIC. These instructions will install RELIC in `$HOME/local` modify as necessary. The preset will configure RELIC to use the BL12-381 curve which offers 128 bits of security, for a group order of around 255 bits. See [the ZCash blog](https://blog.z.cash/new-snark-curve).

```
git clone https://github.com/relic-toolkit/relic.git
cd relic
# Use a version of RELIC which we know works, later versions might work as well
git checkout 13f88f6e6fa3c54b48309baa16cd19c61b4bd850
./preset/x64-pbc-128-b12.sh -DCMAKE_INSTALL_PREFIX=$HOME/local/
make
make install
```

To ensure `cmake` can find RELIC set the following environment variables:

```
export LIBRARY_PATH=$LIBRARY_PATH:$HOME/local/lib
export CPATH=$CPATH:$HOME/local/include
export CMAKE_LIBRARY_PATH=$HOME/local/lib
```

## Building Tandem code

In the Vagrant virtual machine, this repository is mounted under `/vagrant`. When using your own machine, checkout this repository first. Then run:

```
mkdir build
cd build
cmake ..
make install
```

Thereafter, the binaries can be found in `bin/`.

## Included libraries

The `extern/` directory contains two included external libraries:

 * The [original libpaillier library](http://acsc.cs.utexas.edu/libpaillier/) implements a relatively unoptimized version of Paillier. The benchmark script shows 26 ms for encrypting and 13 ms for decrypting for 2048 bit keys. In this repository (see `extern/paillier`) we include a [more optimized version](https://github.com/mcornejo/libpaillier) that yields better results: 13ms for encrypting, 3.6 ms for decrypting. It is licensed under GPL 2.0
 
 * An efficient implementation of the Joux-Libert additively homomorphic encryption scheme from the [labhe project](https://github.com/haslab/labhe). See `extern/bhjl`. It is licensed under the MIT license.

 * An updated version of the BBS+ credentials implementation from [Vote to Link](https://github.com/wouterl/vote-to-link).

# Running experiments

The program `bin/bench-tandem` will output most of the numbers used in the paper. It takes as input the difficulty level for the cut-and-choose proofs. For example, you could call:

```
bin/bench-tandem 20
```

To compute the benchmarks for k = 20. The program will output the results to standard output in human-readable format, and appends them to the file `test.log` for plotting. The input files for the paper were generated by running:

```
for i in `seq 2 2 64`; do ./bench-tandem $i; done
```

The program hardcodes a some parameter choices: the size of the Joux-Libert modulus (2048 bits) and the size of the Joux-Libert plaintext space (394 bits). These numbers offer reasonable security. Update the defines at the top of `bench/bench-tandem.c` to increase the size of the modulus. (Don't forget to recompile afterwards.)

If you want to repeat the experiments more often, or change where the output is written, you can do so by changing the `NR_EXPERIMENTS` and `LOG_FILE` parameters.

To increase the size of k beyond 63, please recompute the new size of the plaintext space, update `PTXT_BITS` in `bench/bench-tandem.c` _and_ update `TANDEM_DELTA_BITS` in `includes/tandem.h`. Under normal circumstances, these values do not have to be changed.

## Other benchmark scripts

This repository contains several other benchmark scripts that measure the running time of several subcomponents:

 * `bin/bench-bbsplus` Benchmarks our BBS+ credential scheme implementation. The program takes as argument the number of attributes the credential should contain.
 * `bin/bench-homenc` Benchmarks the Joux-Libert additively-homomorphic encryption scheme for several sizes of the plaintext space. Edit the defines at the top of `bench/bench-homenc.c` to change the parameters.
 * `bin/bench-paillier` Benchmarks Pailliers additively-homomorphic encryption scheme. For Paillier, the plaintext space always equals the modulus. Edit the defines at the top of `bench/bench-paillier.c` to change the parameters.
 * `bin/bench-primitives` will compute computational cost of exponentiations and pairings for BLS12-381.
 
## Simple tests/example scripts

This repository also contains some simple tests/examples programs. The programs are very basic, and essentially serve to verify happy-flow functionality and to serve as simple usage example. They do not aim to be complete.

 * `bin/test-bbsplus` Examples and tests for the included BBS+ credential implementation. Edit the defines at the top of the file to test with a different number of attributes.
 * `bin/test-commit` Examples and tests for the included commitment scheme.
 * `bin/test-homenc` Example and test for Joux-Libert's homomorphic encryption scheme.
 * `bin/test-paillier` Example and test for Paillier's homomorphic encryption scheme.
 * `bin/test-openssl` Simple example program of using Elliptic Curves in OpenSSL. Not used at the moment.
 * `bin/test-tandem` Simple example and test script for the Tandem implementation.
