#include "commit.h"
#include <stdio.h>

void commit_keygen(struct commit_pk *pk) {
    g1_null(pk->g);
    g1_new(pk->g);
    g1_rand(pk->g);

    g1_null(pk->h);
    g1_new(pk->h);
    g1_rand(pk->h);

    g1_get_ord(pk->q);

}

void commit_pk_free(struct commit_pk *pk) {
    g1_free(pk->g);
    g1_free(pk->h);
}

void commit_rand_gen(struct commit_rand *rand, struct commit_pk *pk) {
    bn_null(rand->r);
    bn_new(rand->r);
    bn_rand_mod(rand->r, pk->q);
}

void commit_rand_free(struct commit_rand *rand) {
    bn_free(rand->r);
}

void commit_com(struct commit_com *com, bn_t t,
        struct commit_rand *rand, struct commit_pk *pk) {
    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    g1_null(com->com);
    g1_new(com->com);

    // com = g^c
    g1_mul(com->com, pk->g, t);
    // tmp = h^(rand->r)
    g1_mul(tmp, pk->h, rand->r);
    g1_add(com->com, com->com, tmp);

    g1_free(tmp);
}


int commit_verify(struct commit_com *com, bn_t t,
        struct commit_rand *rand, struct commit_pk *pk) {
    struct commit_com com2;
    commit_com(&com2, t, rand, pk);

    int result = g1_cmp(com->com, com2.com) == RLC_EQ;

    commit_com_free(&com2);
    return result;
}

void commit_com_free(struct commit_com *com) {
    g1_free(com->com);
}
