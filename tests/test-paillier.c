#include <gmp.h>
#include "paillier.h"
#include <stdio.h>

#define MODULUS_BITS 2048

int
main(int argc, char **argv) {
    paillier_pubkey_t *pk;
    paillier_prvkey_t *sk;

    paillier_keygen(MODULUS_BITS, &pk, &sk, &paillier_get_rand_devurandom);

    paillier_plaintext_t *m0, *m1;
    m0 = paillier_plaintext_from_ui(1234);
    m1 = paillier_plaintext_from_ui(1337);

    paillier_ciphertext_t c0, c1, c2;
    paillier_init_ciphertext(&c0);
    paillier_init_ciphertext(&c1);
    paillier_init_ciphertext(&c2);

    paillier_enc(&c0, pk, m0, &paillier_get_rand_devurandom);
    paillier_enc(&c1, pk, m1, &paillier_get_rand_devurandom);

    paillier_plaintext_t res0, res1, res2;
    paillier_init_plaintext(&res0);
    paillier_init_plaintext(&res1);
    paillier_init_plaintext(&res2);

    paillier_dec(&res0, pk, sk, &c0);
    paillier_dec(&res1, pk, sk, &c1);
    gmp_printf("Recovered m0 as %Zd\n", res0.m);
    gmp_printf("Recovered m1 as %Zd\n", res1.m);

    if(mpz_cmp(res0.m, m0->m) != 0 ||
            mpz_cmp(res1.m, m1->m) != 0) {
        printf("ERROR: decryption incorrect\n");
        return 1;
    } else {
        printf("Correct decryption.\n\n");
    }

    paillier_mul(&c2, pk, &c0, &c1);
    paillier_dec(&res2, pk, sk, &c2);
    gmp_printf("Recovered m0*m1 as %Zd\n", res2.m);
    if(mpz_cmp_ui(res2.m, 2571) != 0) {
        printf("ERROR: additive homomorphic failed\n");
        return 1;
    } else {
        printf("Correct homomorphic addition\n");
    }

    paillier_freeplaintext(m0);
    paillier_freeplaintext(m1);

    paillier_clearplaintext(&res0);
    paillier_clearplaintext(&res1);
    paillier_clearplaintext(&res2);
    paillier_clearciphertext(&c0);
    paillier_clearciphertext(&c1);
    paillier_clearciphertext(&c2);

    paillier_freepubkey(pk);
    paillier_freeprvkey(sk);

    return 0;
}
