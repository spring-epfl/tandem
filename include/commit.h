#include <relic/relic.h>
#include <gmp.h>


struct commit_pk {
    g1_t g;
    g1_t h;

    bn_t q;
};

struct commit_rand {
    bn_t r;
};

struct commit_com {
    g1_t com;
};


void commit_keygen(struct commit_pk *pk);
void commit_pk_free(struct commit_pk *pk);

void commit_rand_gen(struct commit_rand *rand, struct commit_pk *pk);
void commit_rand_free(struct commit_rand *rand);

void commit_com(struct commit_com *com, bn_t n,
        struct commit_rand *rand, struct commit_pk *pk);
int commit_verify(struct commit_com *com, bn_t n,
        struct commit_rand *rand, struct commit_pk *pk);
void commit_com_free(struct commit_com *com);

