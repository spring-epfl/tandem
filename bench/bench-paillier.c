/*
 * Computes computational complexity of Paillier encryption and decryption using
 * an optimized library.
 *
 * Change the defines at the top of this file to change the modulus size or how
 * often the experiments are run.
 */

#include <gmp.h>
#include "paillier.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MODULUS_BITS 2048
#define NR_EXPERIMENTS 100

int
main(int argc, char **argv) {
    paillier_pubkey_t *pk;
    paillier_prvkey_t *sk;

    gmp_randstate_t rnd_state;
    gmp_randinit_default(rnd_state);
    clock_t tic, toc;
    double time_taken;

    paillier_keygen(MODULUS_BITS, &pk, &sk, &paillier_get_rand_devurandom);

    // Generate some plaintexts
    paillier_plaintext_t m[NR_EXPERIMENTS];
    printf("Generating plaintexts...");
    fflush(stdout);
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        mpz_init((m + i)->m);
        mpz_urandomb((m + i)->m, rnd_state, MODULUS_BITS - 1);
    }
    printf(" done\n\n");

    // Trial encryption
    paillier_ciphertext_t c[NR_EXPERIMENTS];
    printf("Starting encryption benchmark\n");
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        paillier_init_ciphertext(c + i);
        paillier_enc(c + i, pk, m + i, &paillier_get_rand_devurandom);
    }
    toc = clock();
    time_taken = (double)(toc - tic) / CLOCKS_PER_SEC;
    printf("Time to encrypt: %e miliseconds\n\n", time_taken * 1000.0 / NR_EXPERIMENTS);

    // Trial decryption
    paillier_plaintext_t res[NR_EXPERIMENTS];
    printf("Starting decryption benchmark\n");
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        paillier_init_plaintext(res + i);
        paillier_dec(res + i, pk, sk, c + i);
    }
    toc = clock();
    time_taken = (double)(toc - tic) / CLOCKS_PER_SEC;
    printf("Time to decrypt: %e miliseconds\n\n", time_taken * 1000.0 / NR_EXPERIMENTS);

    // TODO: free allocated mpz's as well
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        mpz_clear((m + i)->m);
        paillier_clearciphertext(c + i);
        paillier_clearplaintext(res + i);
    }

    paillier_freepubkey(pk);
    paillier_freeprvkey(sk);

    return 0;
}
