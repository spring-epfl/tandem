#include <relic/relic.h>
#include <gmp.h>
#include "paillier.h"
#include <openssl/bn.h>

void bn_inv_mod(bn_t res, const bn_t input, const bn_t n);

void bn_rands_from_stream(bn_t *res, size_t n, size_t nr_bytes,
        uint8_t *key);

void print_bytes(uint8_t *p, int count);

void paillier_plaintext_from_bn_t(paillier_plaintext_t *xs_ptxt, bn_t xs);
void sample_subset(unsigned int **indices, size_t subset_size, size_t set_size);
void complement_of_indices(unsigned int **complement, unsigned int *indices,
        size_t indices_size, size_t max);
void print_set(unsigned int *set, size_t set_size);

void bn_from_mpz(bn_t b, mpz_t m);
void mpz_from_bn(mpz_t m, bn_t b);

void bignum_from_mpz(BIGNUM **a, mpz_t b);
void bignum_from_bn(BIGNUM **a, bn_t b);

void hash_mpz_to_bn_t(bn_t h, mpz_t n, bn_t q);
void hash_mpz_and_g1_to_bn(bn_t h, mpz_t n, g1_t m, bn_t q);
