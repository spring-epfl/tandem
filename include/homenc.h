#include <gmp.h>

#ifndef HOMENC_H
#define HOMENC_H

struct homenc_ctxt {
    mpz_t c;
};

struct homenc_ptxt {
    mpz_t m;
};

struct homenc_encrand {
    mpz_t r;
};

struct homenc_pk {
    mpz_t n;
    mpz_t y;

    int k;

    // Precomputed values
    mpz_t _2k;
    mpz_t _2k1;
};

struct homenc_sk {
    mpz_t p;
    mpz_t D;

    // Precomputed values
    mpz_t pm12k;
};

// KEY GENERATION

void
homenc_keygen(int modulusbits, int k, struct homenc_pk *pk,
        struct homenc_sk *sk, gmp_randstate_t rand);
void
homenc_clear_pk(struct homenc_pk *pk);

void
homenc_clear_sk(struct homenc_sk  *sk);

// ENCRYPTION / DECRYPTION

void
homenc_init_ptxt(struct homenc_ptxt *ptxt);

void
homenc_init_encrand(struct homenc_encrand *r);

void
homenc_init_ctxt(struct homenc_ctxt *ctxt);

void
homenc_gen_encrand(struct homenc_encrand *r, struct homenc_pk *pk,
        gmp_randstate_t rand);

void
homenc_enc(struct homenc_ctxt *ctxt, struct homenc_pk *pk,
        struct homenc_ptxt *ptxt, gmp_randstate_t rand);

void
homenc_enc_r(struct homenc_ctxt *ctxt, struct homenc_pk *pk,
        struct homenc_ptxt *ptxt, struct homenc_encrand *r);

void
homenc_dec(struct homenc_ptxt *ptxt, struct homenc_pk *pk,
        struct homenc_sk *sk, struct homenc_ctxt *ctxt);

void
homenc_clear_ptxt(struct homenc_ptxt *ptxt);

void
homenc_clear_encrand(struct homenc_encrand *r);

void
homenc_clear_ctxt(struct homenc_ctxt *ctxt);

// HOMOMORPHIC OPERATIONS

void
homenc_add(struct homenc_ctxt *res, struct homenc_pk *pk,
        struct homenc_ctxt *c0, struct homenc_ctxt *c1);

#endif
