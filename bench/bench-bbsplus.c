/*
 * Simple benchmark program for BBS+ credentials implementation.
 *
 * This program takes as argument the number of attributes.
 */

#include "bbsplus.h"
#include "utils.h"

#include <stdio.h>
#include <relic/relic.h>

#include <time.h>

#define NR_EXPERIMENTS 100

int
main(int argc, char **argv) {
    // Initialize relic
    if( core_init() != RLC_OK ) {
        core_clean();
        printf("Error loading relic");
        return 1;
    }

    if( pc_param_set_any() != RLC_OK ) {
        printf("Error: No curve!");
        return 1;
    }

    unsigned int nr_attributes;
    if(argc <= 1) {
        printf("Please supply the number of attributes as argument\n");
        exit(1);
    } else {
        nr_attributes = atoi(argv[1]);
    }

    printf("Configuration:\n");
    printf("  Nr. of attributes: %i\n\n", nr_attributes);

    struct bbsplus_pk pk;
    struct bbsplus_sk sk;
    struct bbsplus_sign sign;


    // Initialize messages
    bn_t *msgs = malloc(nr_attributes * sizeof(bn_t));
    for(int i = 0; i < nr_attributes; i++) {
        bn_null(msgs[i]);
        bn_new(msgs[i]);
    }

    // Example list of hidden attributes
    unsigned int *hidden = malloc(nr_attributes * sizeof(unsigned int));
    for(unsigned int i = 0; i < nr_attributes; i++) {
        hidden[i] = i;
    }

    // Example list of auxiliary data for non-interactive proofs
    uint8_t L[] = {8, 44, 18};
    size_t lL = 3;


    clock_t tic, toc;

    // Generate signing key
    bbsplus_keygen(&pk, &sk, nr_attributes);

    // Generate random messages and create signature
    for(int i = 0; i < nr_attributes; i++) {
        bn_rand_mod(msgs[i], pk.q);
    }
    bbsplus_sign(&sign, &pk, &sk, &msgs[0], nr_attributes);

    tic = clock();
    struct bbsplus_proof proofs[NR_EXPERIMENTS];
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        bbsplus_prove(proofs + i, &sign, &pk, &msgs[0], nr_attributes,
                hidden, nr_attributes, &L[0], lL);
    }
    toc = clock();
    printf("Time per disclosure proof (all hidden): %e seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    tic = clock();
    struct bbsplus_proof proofs2[NR_EXPERIMENTS];
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        bbsplus_prove(proofs2 + i, &sign, &pk, &msgs[0], nr_attributes,
                hidden, 0, &L[0], lL);
    }
    toc = clock();
    printf("Time per disclosure proof (all disclosed): %e seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        bbsplus_proof_verify(proofs + i, &pk, nr_attributes, &L[0], lL);
    }
    toc = clock();
    printf("Time per disclosure proof verification (all hidden): %e seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        bbsplus_proof_verify(proofs2 + i, &pk, nr_attributes, &L[0], lL);
    }
    toc = clock();
    printf("Time per disclosure proof verification (all disclosed): %e seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    // Cleanup proofs
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        bbsplus_proof_free(proofs + i);
    }
    bbsplus_pk_free(&pk);
    bbsplus_sk_free(&sk);

    return 0;
}
