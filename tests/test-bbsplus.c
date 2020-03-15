/*
 * Simple test program for BBS+ credentials implementation
 *
 * This script only performs basic testing.
 */

#include "bbsplus.h"
#include "utils.h"

#include <stdio.h>
#include <relic/relic.h>

#define NR_MSGS 10
#define NR_TESTS 10

int
main(int argc, char **argv) {
    printf("Testing BBS+ credentials!\n");

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

    struct bbsplus_pk pk;
    struct bbsplus_sk sk;

    bn_t msgs[500];
    for(int i = 0; i < 500; i++) {
        bn_null(msgs[i]);
        bn_new(msgs[i]);
    }

    struct bbsplus_sign sign;
    struct bbsplus_proof proof;

    uint8_t L[] = {8, 44, 18};
    size_t lL = 3;

    unsigned int hidden[500];
    for(unsigned int i = 0; i < 500; i++) {
        hidden[i] = i;
    }

    printf("\nDoing basic tests (all hidden): ");
    for(int i = 0; i < NR_TESTS; i++) {
        bbsplus_keygen(&pk, &sk, NR_MSGS);

        for(int j = 0; j < NR_MSGS; j++) {
            bn_rand_mod(msgs[j], pk.q);
        }

        bbsplus_sign(&sign, &pk, &sk, &msgs[0], NR_MSGS);

        if(!bbsplus_verify(&sign, &pk, &msgs[0], NR_MSGS)) {
            printf("ERROR: signature invalid\n");
            return 1;
        }

        bbsplus_prove(&proof, &sign, &pk, &msgs[0], NR_MSGS,
                hidden, NR_MSGS, &L[0], lL);
        if(!bbsplus_proof_verify(&proof, &pk, NR_MSGS, &L[0], lL)) {
            printf("ERROR: proof doesn't verify\n");
            return 1;
        }

        bbsplus_proof_free(&proof);
        bbsplus_pk_free(&pk);
        bbsplus_sk_free(&sk);
    }
    printf("Test passed!\n");

    printf("\nDoing basic tests (all disclosed): ");
    for(int i = 0; i < NR_TESTS; i++) {
        bbsplus_keygen(&pk, &sk, NR_MSGS);

        for(int j = 0; j < NR_MSGS; j++) {
            bn_rand_mod(msgs[j], pk.q);
        }

        bbsplus_sign(&sign, &pk, &sk, &msgs[0], NR_MSGS);

        if(!bbsplus_verify(&sign, &pk, &msgs[0], NR_MSGS)) {
            printf("ERROR: signature invalid\n");
            return 1;
        }

        bbsplus_prove(&proof, &sign, &pk, &msgs[0], NR_MSGS,
                hidden, 0, &L[0], lL);
        if(!bbsplus_proof_verify(&proof, &pk, NR_MSGS, &L[0], lL)) {
            printf("ERROR: proof doesn't verify\n");
            return 1;
        }

        bbsplus_proof_free(&proof);
        bbsplus_pk_free(&pk);
        bbsplus_sk_free(&sk);
    }
    printf("Test passed!\n");

    printf("\nDoing basic tests (some disclosed): ");
    for(int i = 0; i < NR_TESTS; i++) {
        bbsplus_keygen(&pk, &sk, NR_MSGS);

        for(int j = 0; j < NR_MSGS; j++) {
            bn_rand_mod(msgs[j], pk.q);
        }

        bbsplus_sign(&sign, &pk, &sk, &msgs[0], NR_MSGS);

        if(!bbsplus_verify(&sign, &pk, &msgs[0], NR_MSGS)) {
            printf("ERROR: signature invalid\n");
            return 1;
        }

        bbsplus_prove(&proof, &sign, &pk, &msgs[0], NR_MSGS,
                hidden, NR_MSGS / 2, &L[0], lL);
        if(!bbsplus_proof_verify(&proof, &pk, NR_MSGS, &L[0], lL)) {
            printf("ERROR: proof doesn't verify\n");
            return 1;
        }

        bbsplus_proof_free(&proof);
        bbsplus_pk_free(&pk);
        bbsplus_sk_free(&sk);
    }
    printf("Test passed!\n\n\n");

    return 0;
}
