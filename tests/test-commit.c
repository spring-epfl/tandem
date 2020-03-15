#include <stdio.h>
#include "commit.h"

int
main(int argc, char** argv) {
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

    // Try to commit to something
    struct commit_pk com_pk;
    commit_keygen(&com_pk);

    bn_t t;
    bn_null(t);
    bn_new(t);
    bn_rand_mod(t, com_pk.q);

    struct commit_com com;
    struct commit_rand rand;
    commit_rand_gen(&rand, &com_pk);
    commit_com(&com, t, &rand, &com_pk);

    int valid = commit_verify(&com, t, &rand, &com_pk);
    if(valid) {
        printf("Correct, commitment verified\n");
    } else {
        printf("ERROR: commitment should check.\n");
        return 1;
    }

    // Changing input, commitment check should fail
    bn_add(t, t, t);
    valid = commit_verify(&com, t, &rand, &com_pk);
    if(!valid) {
        printf("Correct, commitment should not verify\n");
    } else {
        printf("ERROR: commitment should not verify.\n");
        return 1;
    }

    commit_com_free(&com);
    commit_rand_free(&rand);
    commit_pk_free(&com_pk);

    bn_free(t);

    return 0;
}
