#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

#include <stdio.h>
#include <time.h>

#define NR_EXPERIMENTS 10000

int
main (int argc, char **argv) {
    EC_GROUP *group;
    BN_CTX *ctx;

    group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    if(group == NULL) {
        printf("ERROR: could not instantiate group\n");
        exit(1);
    }

    // Setup temporary bn's
    ctx = BN_CTX_new();
    if(ctx == NULL) {
        printf("Could not allocate CTXT\n");
        exit(1);
    }

    BIGNUM *order = BN_new();
    EC_GROUP_get_order(group, order, NULL);

    printf("Order of group secp521r1: ");
    BN_print_fp(stdout, order);
    printf("\n");

    BIGNUM *a = BN_new();
    BN_set_word(a, 1337);
    BIGNUM *b = BN_new();
    BN_set_word(b, 981242338);
    BIGNUM *sum = BN_new();
    BN_add(sum, a, b);

    const EC_POINT *P = EC_GROUP_get0_generator(group);

    EC_POINT *aP = EC_POINT_new(group);
    EC_POINT_mul(group, aP, NULL, P, a, ctx);

    EC_POINT *bP = EC_POINT_new(group);
    EC_POINT_mul(group, bP, NULL, P, b, ctx);

    EC_POINT *sumP = EC_POINT_new(group);
    EC_POINT_mul(group, sumP, NULL, P, sum, ctx);

    EC_POINT *sumP2 = EC_POINT_new(group);
    EC_POINT_add(group, sumP2, aP, bP, ctx);

    char *str1 = EC_POINT_point2hex(group, sumP, POINT_CONVERSION_COMPRESSED, ctx);
    char *str2 = EC_POINT_point2hex(group, sumP2, POINT_CONVERSION_COMPRESSED, ctx);

    printf("sumP:  %s\n", str1);
    printf("sumP2: %s\n", str2);

    // Benchmark group operation
    clock_t tic, toc;
    double time_taken;

    EC_POINT **pts = malloc(NR_EXPERIMENTS * sizeof(EC_POINT *));
    BIGNUM **exps = malloc(NR_EXPERIMENTS * sizeof(BIGNUM *));

    // Initialize
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
      exps[i] = BN_new();
      BN_rand_range(exps[i], order);

      pts[i] = EC_POINT_new(group);
    }

    // Do point multiplication
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
      EC_POINT_mul(group, pts[i], NULL, P, exps[i], ctx);
    }
    toc = clock();
    time_taken = (double)(toc - tic) / CLOCKS_PER_SEC;
    printf("Time for exponentiation OPENSSL: %e miliseconds\n\n", time_taken * 1000.0 / NR_EXPERIMENTS);

    BN_free(order);
    BN_CTX_free(ctx);
}
