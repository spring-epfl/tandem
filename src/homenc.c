#include "homenc.h"
#include "bhjl.h"
#include "bhjl_gen.h"

void
homenc_keygen(int modulusbits, int k, struct homenc_pk *pk,
        struct homenc_sk *sk, gmp_randstate_t rand) {

    pk->k = k;
    mpz_init(sk->p);
    mpz_init(sk->D);
    mpz_init(pk->n);
    mpz_init(pk->y);
    bhjl_gen(sk->p, pk->n, pk->y, sk->D,
            modulusbits, pk->k, rand);

    mpz_init(pk->_2k);
    mpz_init(pk->_2k1);
    mpz_init(sk->pm12k);
    bhjl_precom(pk->_2k1, pk->_2k, sk->pm12k,
            sk->p, pk->k);
}

void
homenc_clear_pk(struct homenc_pk *pk) {
    mpz_clear(pk->n);
    mpz_clear(pk->_2k);
    mpz_clear(pk->_2k1);
    mpz_clear(pk->y);
}

void
homenc_clear_sk(struct homenc_sk *sk) {
    mpz_clear(sk->p);
    mpz_clear(sk->D);
    mpz_clear(sk->pm12k);
}

void
homenc_init_ptxt(struct homenc_ptxt *ptxt) {
    mpz_init(ptxt->m);
}

void
homenc_init_encrand(struct homenc_encrand *r) {
    mpz_init(r->r);
}

void
homenc_init_ctxt(struct homenc_ctxt *ctxt) {
    mpz_init(ctxt->c);
}

void
homenc_gen_encrand(struct homenc_encrand *r, struct homenc_pk *pk,
        gmp_randstate_t rand) {
	mpz_urandomm(r->r, rand, pk->n);
}

void
homenc_enc(struct homenc_ctxt *ctxt, struct homenc_pk *pk,
        struct homenc_ptxt *ptxt, gmp_randstate_t rand) {
    struct homenc_encrand r;
    homenc_init_encrand(&r);
    homenc_gen_encrand(&r, pk, rand);
    homenc_enc_r(ctxt, pk, ptxt, &r);
    homenc_clear_encrand(&r);
}

void
homenc_enc_r(struct homenc_ctxt *ctxt, struct homenc_pk *pk,
        struct homenc_ptxt *ptxt, struct homenc_encrand *r) {
    bhjl_encrypt_r(ctxt->c, ptxt->m, r->r, pk->n, pk->y,
            pk->k, pk->_2k);
}

void
homenc_dec(struct homenc_ptxt *ptxt, struct homenc_pk *pk,
        struct homenc_sk *sk, struct homenc_ctxt *ctxt) {
    bhjl_decrypt(ptxt->m, ctxt->c, sk->p, sk->D, pk->k,
            pk->_2k1, sk->pm12k);
}

void
homenc_clear_ptxt(struct homenc_ptxt *ptxt) {
    mpz_clear(ptxt->m);
}

void
homenc_clear_encrand(struct homenc_encrand *r) {
    mpz_clear(r->r);
}

void
homenc_clear_ctxt(struct homenc_ctxt *ctxt) {
    mpz_clear(ctxt->c);
}

void
homenc_add(struct homenc_ctxt *res, struct homenc_pk *pk,
        struct homenc_ctxt *c0, struct homenc_ctxt *c1) {
    bhjl_homadd(res->c, c0->c, c1->c, pk->n);
}
