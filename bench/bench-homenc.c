/*
 * Computes computational complexity of Joux-Libert's additively-homomorphic
 * encryption scheme for several sizes of the plaintext space.
 *
 * Change the defines at the top of this file to change the modulus size, the
 * evaluated options for the plaintext space or how often the experiments are
 * run.
 */
#include <gmp.h>
#include "homenc.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MODULUS_BITS 2048
#define NR_EXPERIMENTS 100
#define PTXT_SIZES {128, 256, 384, 394, 512}

void
run_experiment(int ptxt_bits, gmp_randstate_t rand_state);

int
main(int argc, char **argv) {
    // GMP setup
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);

    printf("Modulus size: %i bits\n", MODULUS_BITS);

    int exp[] = PTXT_SIZES;

    for(int i = 0; i < sizeof(exp) / sizeof(exp[0]); i++) {
        printf("######## Experiment with k = %i ##########\n", exp[i]);
        run_experiment(exp[i], rand_state);
        printf("\n\n");
    }

    return 0;
}

void
run_experiment(int ptxt_bits, gmp_randstate_t rand_state) {
    clock_t tic, toc;
    double time_taken;

    // KeyGen
    struct homenc_sk sk;
    struct homenc_pk pk;
    homenc_keygen(MODULUS_BITS, ptxt_bits, &pk, &sk, rand_state);

    // Generate some plaintexts
    struct homenc_ptxt m[NR_EXPERIMENTS];
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        homenc_init_ptxt(m + i);
        mpz_urandomb((m + i)->m, rand_state, ptxt_bits);
    }

    // Trial encryption
    struct homenc_ctxt c[NR_EXPERIMENTS];
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        homenc_init_ctxt(c + i);
        homenc_enc(c + i, &pk, m + i, rand_state);
    }
    toc = clock();
    time_taken = (double)(toc - tic) / CLOCKS_PER_SEC;
    printf("  Time to encrypt: %e miliseconds\n", time_taken * 1000.0 / NR_EXPERIMENTS);

    // Trial decryption
    struct homenc_ptxt res[NR_EXPERIMENTS];
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        homenc_init_ptxt(res + i);
        homenc_dec(res + i, &pk, &sk, c + i);
    }
    toc = clock();
    time_taken = (double)(toc - tic) / CLOCKS_PER_SEC;
    printf("  Time to decrypt: %e miliseconds\n", time_taken * 1000.0 / NR_EXPERIMENTS);

    // TODO: free allocated mpz's as well
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        homenc_clear_ptxt(m + i);
        homenc_clear_ctxt(c + i);
        homenc_clear_ptxt(res + i);
    }

    homenc_clear_pk(&pk);
    homenc_clear_sk(&sk);
}
