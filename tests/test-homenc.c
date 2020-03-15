/*
 * Simple test program for the Joux-Libert encryption scheme
 */

#include <stdio.h>
#include "homenc.h"

#define MODULUS_BITS 2048
#define PTXT_BITS 394

int
main (int argc, char **argv) {
    // GMP setup
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);

    // KeyGen
    struct homenc_sk sk;
    struct homenc_pk pk;
    homenc_keygen(MODULUS_BITS, PTXT_BITS, &pk, &sk, rand_state);

    // Encrypt things
    struct homenc_ptxt m0, m1;
    homenc_init_ptxt(&m0);
    homenc_init_ptxt(&m1);
    mpz_set_ui(m0.m, 1234);
    mpz_set_ui(m1.m, 1337);

    struct homenc_ctxt c0, c1, c2;
    homenc_init_ctxt(&c0);
    homenc_init_ctxt(&c1);
    homenc_init_ctxt(&c2);

    homenc_enc(&c0, &pk, &m0, rand_state);
    homenc_enc(&c1, &pk, &m1, rand_state);

    // Decrypt things

    struct homenc_ptxt res;
    homenc_init_ptxt(&res);
    homenc_dec(&res, &pk, &sk, &c0);
    if (mpz_cmp(m0.m, res.m) != 0) {
        printf("ERROR: Incorrect decryption of m0\n");
        return 1;
    }
    homenc_dec(&res, &pk, &sk, &c1);
    if (mpz_cmp(m1.m, res.m) != 0) {
        printf("ERROR: Incorrect decryption of m1\n");
        return 1;
    }

    // Testing homomorphic operations
    homenc_add(&c2, &pk, &c0, &c1);
    homenc_dec(&res, &pk, &sk, &c2);
    gmp_printf("Recovered c0*c1 as %Zd\n", res.m);
    if(mpz_cmp_ui(res.m, 2571) != 0) {
        printf("ERROR: additive homomorphic failed\n");
        return 1;
    } else {
        printf("Correct homomorphic addition\n");
    }

    // Free things up
    homenc_clear_pk(&pk);
    homenc_clear_sk(&sk);
    gmp_randclear(rand_state);

    homenc_clear_ptxt(&m0);
    homenc_clear_ptxt(&m1);
    homenc_clear_ptxt(&res);

    homenc_clear_ctxt(&c0);
    homenc_clear_ctxt(&c1);
    homenc_clear_ctxt(&c2);
}
