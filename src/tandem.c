#include "tandem.h"
#include "sodium.h"

#define MODULUS_BITS 2048

void
credential_commitment_represent(g1_t A, struct bbsplus_pk *pk, bn_t s,
        bn_t sk, bn_t ctxt_hash, bn_t token_id,
        bn_t *msgs, size_t nr_msgs) {
    g1_null(A);
    g1_new(A);

    g1_mul(A, pk->bases[0], s);

    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    g1_mul(tmp, pk->bases[1], sk);
    g1_add(A, A, tmp);

    g1_mul(tmp, pk->bases[2], ctxt_hash);
    g1_add(A, A, tmp);

    g1_mul(tmp, pk->bases[3], token_id);
    g1_add(A, A, tmp);

    for(int i = 4; i < nr_msgs + 4; i++) {
        g1_mul(tmp, pk->bases[i], msgs[i - 4]);
        g1_add(A, A, tmp);
    }

    g1_free(tmp);
}

void
tandem_setup_server(struct ServerState *state,
        struct homenc_pk *pk, struct homenc_sk *sk,
        struct bbsplus_pk *bbs_pk, struct bbsplus_sk *bbs_sk,
        struct commit_pk *com_pk, bn_t xs, size_t difficulty,
        gmp_randstate_t *rand_state,
        EC_GROUP *group, EC_POINT *genh, BN_CTX *ctx) {

    state->pk = pk;
    state->sk = sk;
    state->bbs_pk = bbs_pk;
    state->bbs_sk = bbs_sk;
    state->com_pk = com_pk;

    bn_null(state->xs);
    bn_new(state->xs);
    bn_copy(state->xs, xs);

    state->difficulty = difficulty;
    state->rand_state = rand_state;

    state->group = group;
    state->genh = genh;
    state->ctx = ctx;
    state->order = BN_new();
    EC_GROUP_get_order(group, state->order, NULL);

    // Compute delta limit (note server has one extra bit)
    mpz_init_set_ui(state->delta_limit, 1);
    mpz_mul_2exp(state->delta_limit, state->delta_limit, TANDEM_DELTA_BITS + 1);
}

void
tandem_setup_user(struct UserState *state,
        struct homenc_pk *pk, struct bbsplus_pk *bbs_pk,
        struct commit_pk *com_pk, bn_t xu, size_t difficulty,
        gmp_randstate_t *rand_state,
        EC_GROUP *group, EC_POINT *genh, BN_CTX *ctx) {

    state->pk = pk;
    state->bbs_pk = bbs_pk;
    state->com_pk = com_pk;

    state->difficulty = difficulty;

    bn_null(state->xu);
    bn_new(state->xu);
    bn_copy(state->xu, xu);

    // Create encryption key for tokenids
    bn_null(state->skid);
    bn_new(state->skid);
    bn_rand_mod(state->skid, com_pk->q);
    g1_null(state->pkid);
    g1_new(state->pkid);
    g1_mul_gen(state->pkid, state->skid);

    state->rand_state = rand_state;

    state->group = group;
    state->genh = genh;
    state->ctx = ctx;

    // Compute delta limit
    mpz_init_set_ui(state->delta_limit, 1);
    mpz_mul_2exp(state->delta_limit, state->delta_limit, TANDEM_DELTA_BITS);
}

void
tandem_register_server_start(struct RegisterServerStart *msg,
        struct ServerRegisterState *state,
        struct ServerState *st) {
    state->st = st;

    // Compute xs and r
    bignum_from_bn(&state->xs, state->st->xs);
    state->r = BN_new();
    BN_rand_range(state->r, state->st->order);

    // C = g^{xs} h^{r}
    state->C = EC_POINT_new(state->st->group);
    EC_POINT_mul(state->st->group, state->C,
            state->xs, state->st->genh, state->r, state->st->ctx);

    // Set in message
    msg->C = EC_POINT_new(state->st->group);
    EC_POINT_copy(msg->C, state->C);

    // Prepare xs for encryption
    struct homenc_ptxt xs_ptxt;
    homenc_init_ptxt(&xs_ptxt);
    mpz_from_bn(xs_ptxt.m, st->xs);

    // Create xsenc = Enc(xs)
    homenc_init_ctxt(&state->st->xsenc);
    homenc_enc(&state->st->xsenc, state->st->pk, &xs_ptxt,
            *state->st->rand_state);

    homenc_init_ctxt(&msg->xsenc);
    mpz_set(msg->xsenc.c, state->st->xsenc.c);
}

void
tandem_register_user_start(struct RegisterUserStart *msg,
        struct UserRegisterState *state,
        struct UserState *st,
        struct RegisterServerStart *server_msg) {

    state->st = st;

    // Store commitment C
    state->C = EC_POINT_new(state->st->group);
    EC_POINT_copy(state->C, server_msg->C);

    // Store xsenc
    homenc_init_ctxt(&state->st->xsenc);
    mpz_set(state->st->xsenc.c, server_msg->xsenc.c);

    // Send pkid
    g1_null(msg->pkid);
    g1_new(msg->pkid);
    g1_copy(msg->pkid, state->st->pkid);

    // Choose and commit to indices
    sample_subset(&state->indices,
            state->st->difficulty, 2*state->st->difficulty);
    randombytes_buf(state->indicesRand, TANDEM_SECPAR_BYTES);
    tandem_commit_to_indices(msg->discloseCommit, state->indices,
            state->indicesRand, state->st->difficulty);
}

void
tandem_register_server_cut(struct RegisterServerCommit *msg,
        struct ServerRegisterState *state,
        struct RegisterUserStart *user_msg) {

    // Process user message
    g1_null(state->st->pkid);
    g1_new(state->st->pkid);
    g1_copy(state->st->pkid, user_msg->pkid);
    memcpy(state->discloseCommit, user_msg->discloseCommit, TANDEM_SECPAR_BYTES);

    size_t k2 = 2 * state->st->difficulty;

    state->deltas = malloc(k2 * sizeof(struct homenc_ptxt));
    state->kappas = malloc(k2 * sizeof(struct homenc_encrand));
    state->rs = malloc(k2 * sizeof(BIGNUM *));

    msg->cs = malloc(k2 * sizeof(struct homenc_ctxt));
    msg->Cs = malloc(k2 * sizeof(EC_POINT *));

    BIGNUM *delta = BN_new();

    for(size_t i = 0; i < 2 * state->st->difficulty; i++) {
        // Pick deltas
        homenc_init_ptxt(state->deltas + i);
        mpz_urandomm((state->deltas + i)->m, *state->st->rand_state,
                state->st->delta_limit);

        // Create ciphertexts
        homenc_init_encrand(state->kappas + i);
        homenc_gen_encrand(state->kappas + i, state->st->pk,
                *state->st->rand_state);
        homenc_init_ctxt(msg->cs + i);
        homenc_enc_r(msg->cs + i, state->st->pk, state->deltas + i,
                state->kappas + i);

        // Compute commitments to delta
        // CHECK: is st->order the right group order?
        bignum_from_mpz(&delta, (state->deltas + i)->m);
        state->rs[i] = BN_new();
        BN_rand_range(state->rs[i], state->st->order);

        // C = g^{delta[i]} h^{r}
        msg->Cs[i] = EC_POINT_new(state->st->group);
        EC_POINT_mul(state->st->group, msg->Cs[i],
                delta, state->st->genh, state->rs[i], state->st->ctx);
    }
}

void
tandem_setup_fakeregister(struct UserState *user_state,
        struct ServerState *server_state) {
    // Prepare xs for encryption
    struct homenc_ptxt xs_ptxt;
    homenc_init_ptxt(&xs_ptxt);
    mpz_from_bn(xs_ptxt.m, server_state->xs);

    // Create xsenc = Enc(xs)
    homenc_init_ctxt(&server_state->xsenc);
    homenc_enc(&server_state->xsenc, server_state->pk, &xs_ptxt,
            *server_state->rand_state);
    homenc_init_ctxt(&user_state->xsenc);
    mpz_set(user_state->xsenc.c, server_state->xsenc.c);

    // Copy user's public key for encrypting token identifiers
    g1_null(server_state->pkid);
    g1_new(server_state->pkid);
    g1_copy(server_state->pkid, user_state->pkid);

    homenc_clear_ptxt(&xs_ptxt);
}

void
tandem_clear_server_state(struct ServerState *state) {
    // Most variables have been externally allocated and copied only
    homenc_clear_ctxt(&state->xsenc);
    mpz_clear(state->delta_limit);
}

void
tandem_clear_user_state(struct UserState *state) {
    // Most variables have been externally allocated and copied only
    homenc_clear_ctxt(&state->xsenc);
    mpz_clear(state->delta_limit);
}

void
tandem_commit_to_indices(unsigned char *commitment, unsigned int *indices,
        unsigned char *rand, size_t difficulty) {
    // Compute commitment to send to user
    size_t l_indices = sizeof(unsigned int) * difficulty;
    size_t l_random = TANDEM_SECPAR / 8;
    unsigned char* buf = malloc(l_indices + l_random);

    memcpy(buf, indices, l_indices);
    memcpy(buf + l_indices, rand, l_random);
    md_map_sh256(commitment, buf, l_indices + l_random);

    free(buf);
}


void
tandem_obtain_server_start(struct ServerObtainStart *msg,
        struct ServerObtainState *state, struct ServerState *st) {
    // Store ServerState
    state->st = st;

    // Pick subset \mathcal{D}
    sample_subset(&state->indices,
            state->st->difficulty, 2*state->st->difficulty);

    // Pick randomizer to commit to indices
    randombytes_buf(state->indicesRand, TANDEM_SECPAR_BYTES);

    // Compute commitment
    tandem_commit_to_indices(msg->discloseCommit, state->indices,
            state->indicesRand, state->st->difficulty);
}


// OUTPUT:
//  - hash is 32 bytes allocated buffer
void tandem_commit_to_delta_and_kappa(uint8_t *hash, mpz_t delta, mpz_t kappa, uint8_t *xi) {
    size_t l_delta = (mpz_sizeinbase(delta, 2) + 7) / 8;
    size_t l_kappa = (mpz_sizeinbase(kappa, 2) + 7) / 8;
    size_t l_xi = TANDEM_SECPAR_BYTES;
    uint8_t *buf = malloc(l_delta + l_kappa + l_xi);

    mpz_export(buf,           &l_delta, 1, 1, 1, 0, delta);
    mpz_export(buf + l_delta, &l_kappa, 1, 1, 1, 0, kappa);
    memcpy(buf + l_delta + l_kappa, xi, l_xi);

    md_map_sh256(hash, buf, l_delta + l_kappa + l_xi);
    free(buf);
}

void
tandem_obtain_user_cut(struct UserObtainState *state,
        struct UserObtainCommitMsg *commit_msg,
        struct UserState *st,
        struct ServerObtainStart *server_msg) {

    state->st = st;
    size_t k2 = 2 * state->st->difficulty;

    state->deltas = malloc(k2 * sizeof(struct homenc_ptxt));
    state->kappas = malloc(k2 * sizeof(struct homenc_encrand));
    state->rs = malloc(k2 * sizeof(struct commit_rand));
    state->xis = malloc(k2 * TANDEM_SECPAR_BYTES);

    state->cs = malloc(k2 * sizeof(struct homenc_ctxt));
    state->hash = malloc(k2 * sizeof(bn_t));
    state->Commits = malloc(k2 * sizeof(struct commit_com));
    state->DeltaCommits = malloc(k2 * TANDEM_SECPAR_BYTES);

    randombytes_buf(state->xis, k2 * TANDEM_SECPAR_BYTES);

    // Create ciphertext c itself

    // Pick delta \in [2^DELTA_LIMIT, 2^(DELTA_LIMIT + 1)
    homenc_init_ptxt(&state->delta);
    mpz_urandomm(state->delta.m, *state->st->rand_state,
            state->st->delta_limit);
    mpz_add(state->delta.m, state->delta.m, state->st->delta_limit);

    homenc_init_encrand(&state->kappa);
    homenc_gen_encrand(&state->kappa, state->st->pk,
            *state->st->rand_state);
    homenc_init_ctxt(&state->ctxt);
    homenc_enc_r(&state->ctxt, state->st->pk, &state->delta,
            &state->kappa);
    homenc_add(&state->ctxt, state->st->pk, &state->st->xsenc, &state->ctxt);

    bn_null(state->ctxt_hash);
    bn_new(state->ctxt_hash);
    hash_mpz_to_bn_t(state->ctxt_hash, (state->ctxt).c, state->st->com_pk->q);

    // Create all witness ciphertexts
    for(size_t i = 0; i < 2 * state->st->difficulty; i++) {
        // Pick deltas
        homenc_init_ptxt(state->deltas + i);
        mpz_urandomm((state->deltas + i)->m, *state->st->rand_state,
                state->st->delta_limit);

        // Create randomized ciphertexts
        homenc_init_encrand(state->kappas + i);
        homenc_gen_encrand(state->kappas + i, state->st->pk,
                *state->st->rand_state);
        homenc_init_ctxt(state->cs + i);
        homenc_enc_r(state->cs + i, state->st->pk, state->deltas + i,
                state->kappas + i);
        homenc_add(state->cs + i, state->st->pk, &state->st->xsenc, state->cs + i);

        // Calculate hashes of ciphertexts
        bn_null(state->hash[i]);
        bn_new(state->hash[i]);
        hash_mpz_to_bn_t(state->hash[i], (state->cs + i)->c, state->st->com_pk->q);

        // Commit to hashes of plaintexts
        commit_rand_gen(state->rs + i, state->st->com_pk);
        commit_com(state->Commits + i, state->hash[i],
                state->rs + i, state->st->com_pk);

        // Commit to deltas[i] using a hash
        tandem_commit_to_delta_and_kappa(
                state->DeltaCommits + i*TANDEM_SECPAR_BYTES,
                (state->deltas + i)->m,
                (state->kappas + i)->r,
                state->xis + i*TANDEM_SECPAR_BYTES);
    }

    commit_msg->Commits = state->Commits;
    commit_msg->DeltaCommits = state->DeltaCommits;

    memcpy(state->discloseCommit, server_msg->discloseCommit, TANDEM_SECPAR_BYTES);
}

void
tandem_obtain_server_choose(struct ServerObtainChoice *choice_msg,
        struct ServerObtainState *state,
        struct UserObtainCommitMsg *commit_msg) {
    // TODO: maybe make these deep copies
    state->Commits = commit_msg->Commits;
    state->DeltaCommits = commit_msg->DeltaCommits;
    choice_msg->indices = state->indices;
    memcpy(choice_msg->indicesRand, state->indicesRand, TANDEM_SECPAR_BYTES);
}

void
tandem_obtain_user_reveal(struct UserObtainReveal *reveal_msg,
        struct ServerObtainChoice *choice_msg,
        struct UserObtainState *state) {

    size_t k = state->st->difficulty;

    // check revealed indices
    uint8_t discloseCommitRecovered[TANDEM_SECPAR_BYTES];
    tandem_commit_to_indices(discloseCommitRecovered, choice_msg->indices,
            choice_msg->indicesRand, k);
    if( memcmp(state->discloseCommit, discloseCommitRecovered,
                TANDEM_SECPAR_BYTES) != 0 ) {
        printf("Error: Server did not reveal correct indices");
        exit(1);
    }

    reveal_msg->cs = malloc(k * sizeof(struct homenc_ctxt));
    reveal_msg->deltas = malloc(k * sizeof(struct homenc_ptxt));
    reveal_msg->rs = malloc(k * sizeof(struct commit_rand));
    reveal_msg->kappas = malloc(k * sizeof(struct homenc_encrand));
    reveal_msg->xis = malloc(k * TANDEM_SECPAR_BYTES);

    for(unsigned int i = 0; i < k; i++) {
        reveal_msg->cs[i] = state->cs[choice_msg->indices[i]];
        reveal_msg->deltas[i] = state->deltas[choice_msg->indices[i]];
        reveal_msg->rs[i] = state->rs[choice_msg->indices[i]];
        reveal_msg->kappas[i] = state->kappas[choice_msg->indices[i]];
        memcpy(reveal_msg->xis + i * TANDEM_SECPAR_BYTES,
                state->xis + choice_msg->indices[i] * TANDEM_SECPAR_BYTES,
                TANDEM_SECPAR_BYTES);
    }

    // Create a token identifier
    bn_null(state->tokenid);
    bn_new(state->tokenid);
    bn_rand_mod(state->tokenid, state->st->bbs_pk->q);

    // Setup the attributes on which we will receive a signature
    state->attributes = malloc((k + 3) * sizeof(bn_t));
    state->indices = choice_msg->indices;
    complement_of_indices(&state->complement, choice_msg->indices, k, 2*k);

    for(unsigned int i = 0; i < k + 3; i++) {
        bn_null(state->attributes[i]);
        bn_new(state->attributes[i]);
    }

    bn_copy(state->attributes[0], state->st->skid);
    bn_copy(state->attributes[1], state->ctxt_hash);
    bn_copy(state->attributes[2], state->tokenid);
    for(unsigned int i = 3; i < k + 3; i++) {
        // Load ciphertexts as attributes
        bn_copy(state->attributes[i], state->hash[state->complement[i - 3]]);
    }

    // Commitment for blind signature
    bn_null(state->s);
    bn_new(state->s);
    bn_rand_mod(state->s, state->st->bbs_pk->q);

    bbsplus_represent(reveal_msg->A, state->st->bbs_pk, state->s,
        state->attributes, k + 3);

    struct tandem_proof_randomizers randomizers;
    struct tandem_proof_commitments commitments;
    bn_t challenge;

    tandem_obtain_proof_randomizers(&randomizers, k,
            state->st->com_pk);
    tandem_obtain_proof_commitments(&commitments, &randomizers, state->st);
    tandem_obtain_proof_challenge(challenge, &commitments,
        choice_msg->indices, k);
    tandem_obtain_proof_create(&reveal_msg->proof,
            &randomizers, state, challenge);

    tandem_free_proof_randomizers(&randomizers, k);
    tandem_free_proof_commitments(&commitments, k);
}

int
tandem_obtain_server_check_and_issue(struct ServerObtainIssue *issue_msg,
        struct ServerObtainState *state,
        struct UserObtainReveal *reveal) {

    size_t k = state->st->difficulty;

    struct homenc_ctxt ctmp1, ctmp2;
    homenc_init_ctxt(&ctmp1);
    homenc_init_ctxt(&ctmp2);

    bn_t h;
    bn_null(h);
    bn_new(h);

    uint8_t hash[TANDEM_SECPAR_BYTES];

    for(unsigned int i = 0; i < k; i++) {
        unsigned int idx = state->indices[i];

        // Deltas have right size
        if(mpz_cmp((reveal->deltas+i)->m, state->st->delta_limit) >= 0) {
          printf("Error: delta %u is too big\n", i);
          gmp_printf("Delta is: %Zx\n", (reveal->deltas+i)->m);
          gmp_printf("Limit is: %Zx\n", state->st->delta_limit);
          return 0;
        }

        // Ciphertexts are correct
        homenc_enc_r(&ctmp1, state->st->pk, reveal->deltas + i, reveal->kappas + i);
        homenc_add(&ctmp2, state->st->pk, &state->st->xsenc, &ctmp1);
        if(mpz_cmp(reveal->cs[i].c, ctmp2.c) != 0) {
            printf("Error: ciphertext %u is not what it should be\n", i);
            return 0;
        }

        // Commitments are correct
        hash_mpz_to_bn_t(h, (reveal->cs + i)->c, state->st->com_pk->q);
        int verifies = commit_verify(state->Commits + idx, h,
                reveal->rs + i, state->st->com_pk);
        if(!verifies) {
            printf("Error: commitment does not commit to ciphertext at idx %u\n", i);
            return 0;
        }

        // Check commits deltas[i] using a hash
        tandem_commit_to_delta_and_kappa(hash, (reveal->deltas + i)->m,
                (reveal->kappas + i)->r,
                reveal->xis + i*TANDEM_SECPAR_BYTES);
        if (memcmp(hash, state->DeltaCommits + idx*TANDEM_SECPAR_BYTES,
                    TANDEM_SECPAR_BYTES) != 0) {
            printf("Error: DeltaCommit[%u] is not correct\n", i);
            return 0;
        }
    }

    homenc_clear_ctxt(&ctmp1);
    homenc_clear_ctxt(&ctmp2);
    bn_free(h);

    unsigned int *complement;
    complement_of_indices(&complement, state->indices, k, 2*k);

    // TODO: extract proof verification maybe?
    struct tandem_proof_commitments com_reconstructed;
    tandem_reconstruct_commitments(&com_reconstructed,
            &reveal->proof, reveal->A,
            state->st->pkid,
            state->Commits, complement,
            state->st->bbs_pk, state->st->com_pk, k);

    bn_t challenge;
    bn_null(challenge);
    bn_new(challenge);
    tandem_obtain_proof_challenge(challenge, &com_reconstructed,
        state->indices, k);

    //printf("Recovered challenge: ");
    //bn_print(challenge);
    //printf("Proof challenge: ");
    //bn_print(reveal->proof.challenge);

    if(bn_cmp(challenge, reveal->proof.challenge) != RLC_EQ) {
        printf("Error: proof did not verify\n");
        issue_msg->status = TANDEM_PROOF_FAILED;
        return 0 ;
    }

    bbsplus_sign_commitment(&issue_msg->sign, reveal->A,
            state->st->bbs_pk, state->st->bbs_sk);

    tandem_free_proof_commitments(&com_reconstructed, k);

    free(complement);

    // Free allocated memory during obtain
    tandem_free_server_obtain_state(state);

    return 1;
}

int
tandem_obtain_user_token(struct KeyShareToken *token,
        struct ServerObtainIssue *issue_msg,
        struct UserObtainState *state) {

    size_t k = state->st->difficulty;

    token->deltas = malloc(k * sizeof(struct homenc_ptxt));
    token->kappas = malloc(k * sizeof(struct homenc_encrand));
    token->cs = malloc(k * sizeof(struct homenc_ctxt));
    token->hash = malloc(k * sizeof(bn_t));

    for(size_t i = 0; i < k; i++) {
        homenc_init_ptxt(token->deltas + i);
        mpz_set((token->deltas + i)->m, (state->deltas + state->complement[i])->m);

        homenc_init_ctxt(token->cs + i);
        mpz_set((token->cs + i)->c, (state->cs + state->complement[i])->c);

        homenc_init_encrand(token->kappas + i);
        mpz_set((token->kappas + i)->r, (state->kappas + state->complement[i])->r);

        bn_null(token->hash[i]);
        bn_new(token->hash[i]);
        bn_copy(token->hash[i], state->hash[state->complement[i]]);
    }

    homenc_init_ptxt(&token->delta);
    mpz_set(token->delta.m, state->delta.m);

    homenc_init_ctxt(&token->ctxt);
    mpz_set(token->ctxt.c, state->ctxt.c);

    homenc_init_encrand(&token->kappa);
    mpz_set(token->kappa.r, state->kappa.r);

    bn_null(token->ctxt_hash);
    bn_new(token->ctxt_hash);
    bn_copy(token->ctxt_hash, state->ctxt_hash);

    // Finalize signature and verify
    bn_add(issue_msg->sign.s, issue_msg->sign.s, state->s);
    int verified = bbsplus_verify(&issue_msg->sign, state->st->bbs_pk,
            state->attributes, k + 3);

    if(!verified) {
        printf("Bummer, server signature does not verify\n");
        return 0;
    }

    // Copy signature
    g1_null(token->sign.A);
    g1_new(token->sign.A);
    g1_copy(token->sign.A, issue_msg->sign.A);

    bn_null(token->sign.e);
    bn_new(token->sign.e);
    bn_copy(token->sign.e, issue_msg->sign.e);

    bn_null(token->sign.s);
    bn_new(token->sign.s);
    bn_copy(token->sign.s, issue_msg->sign.s);

    token->difficulty = k;

    // Free allocated memory during obtain
    tandem_free_user_obtain_state(state);

    // Compute user's share in token
    bn_null(token->ushare);
    bn_new(token->ushare);
    bn_from_mpz(token->ushare, token->delta.m);
    bn_sub(token->ushare, state->st->xu, token->ushare);
    bn_mod(token->ushare, token->ushare, state->st->com_pk->q);

    // Copy tokenid
    bn_null(token->tokenid);
    bn_new(token->tokenid);
    bn_copy(token->tokenid, state->tokenid);

    return 1;
}

void
tandem_free_user_obtain_state(struct UserObtainState *state) {
    for(size_t i = 0; i < 2 * state->st->difficulty; i++) {
        mpz_clear((state->deltas + i)->m);
        homenc_clear_ctxt(state->cs + i);
        homenc_clear_encrand(state->kappas + i);
        bn_free(state->hash[i]);
        commit_com_free(state->Commits + i);
    }

    homenc_clear_ctxt(&state->ctxt);
    homenc_clear_encrand(&state->kappa);
    mpz_clear(state->delta.m);

    for(size_t i = 0; i < state->st->difficulty + 3; i++) {
        bn_free(state->attributes[i]);
    }
    free(state->attributes);

    free(state->deltas);
    free(state->cs);
    free(state->kappas);
    free(state->hash);
    free(state->rs);
    free(state->xis);
    free(state->Commits);
    free(state->DeltaCommits);
    free(state->complement);
}

void
tandem_free_server_obtain_state(struct ServerObtainState *state) {
    free(state->indices);
}

void
tandem_free_user_reveal(struct UserObtainReveal *reveal_msg, size_t difficulty) {
    free(reveal_msg->cs);
    free(reveal_msg->deltas);
    free(reveal_msg->rs);
    free(reveal_msg->kappas);
    free(reveal_msg->xis);

    tandem_free_obtain_proof(&reveal_msg->proof, difficulty);

    g1_free(reveal_msg->idenc1);
    g1_free(reveal_msg->idenc2);
    g1_free(reveal_msg->A);
}

#if 0
void
tandem_free_server_obtain_choice(struct ServerObtainChoice *choice_msg) {
    free(choice_msg->indices);
}
#endif

void
tandem_free_user_token(struct KeyShareToken *token) {
    for(size_t i = 0; i < token->difficulty; i++) {
        homenc_clear_ctxt(token->cs + i);
        homenc_clear_ptxt(token->deltas + i);
        homenc_clear_encrand(token->kappas + i);
        bn_free(token->hash[i]);
    }

    free(token->deltas);
    free(token->cs);
    free(token->kappas);
    free(token->hash);

    // TODO: free signature?
}

void
tandem_obtain_proof_randomizers(struct tandem_proof_randomizers *rand,
        size_t difficulty, struct commit_pk *com_pk) {

    rand->hrands = malloc(difficulty * sizeof(bn_t));
    rand->rrands = malloc(difficulty * sizeof(bn_t));

    for(size_t i = 0; i < difficulty; i++) {
        bn_null(rand->hrands[i]);
        bn_new(rand->hrands[i]);
        bn_rand_mod(rand->hrands[i], com_pk->q);

        bn_null(rand->rrands[i]);
        bn_new(rand->rrands[i]);
        bn_rand_mod(rand->rrands[i], com_pk->q);
    }

    bn_null(rand->hrand);
    bn_new(rand->hrand);
    bn_rand_mod(rand->hrand, com_pk->q);

    bn_null(rand->skrand);
    bn_new(rand->skrand);
    bn_rand_mod(rand->skrand, com_pk->q);

    bn_null(rand->sprimerand);
    bn_new(rand->sprimerand);
    bn_rand_mod(rand->sprimerand, com_pk->q);

    bn_null(rand->tokenidrand);
    bn_new(rand->tokenidrand);
    bn_rand_mod(rand->tokenidrand, com_pk->q);
}

void
tandem_free_proof_randomizers(struct tandem_proof_randomizers *rand,
        size_t difficulty) {
    for(size_t i = 0; i < difficulty; i++) {
        bn_free(rand->hrands[i]);
        bn_free(rand->rrands[i]);
    }

    bn_free(rand->hrand);
    bn_free(rand->skrand);
    bn_free(rand->sprimerand);
    bn_free(rand->tokenidrand);

    free(rand->hrands);
    free(rand->rrands);
}

void tandem_obtain_proof_commitments(struct tandem_proof_commitments *coms,
        struct tandem_proof_randomizers *rand,
        struct UserState *state) {

    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    coms->ccoms = malloc(state->difficulty * sizeof(g1_t));
    for(size_t i = 0; i < state->difficulty; i++) {
        g1_null(coms->ccoms[i]);
        g1_new(coms->ccoms[i]);

        // ccoms[i] = g^{hrands[i]} h^{rrands[i]}
        g1_mul(coms->ccoms[i], state->com_pk->g, rand->hrands[i]);
        g1_mul(tmp, state->com_pk->h, rand->rrands[i]);
        g1_add(coms->ccoms[i], coms->ccoms[i], tmp);

        // g1_norm(coms->ccoms[i], coms->ccoms[i]);
        // printf("CCom[%Zu]:\n", i);
        // g1_print(coms->ccoms[i]);
    }

    g1_null(coms->pkcom);
    g1_new(coms->pkcom);
    g1_mul_gen(coms->pkcom, rand->skrand);
    // g1_norm(coms->pkcom, coms->pkcom);
    // printf("pkCOM: \n");
    // g1_print(coms->pkcom);

    credential_commitment_represent( coms->Acom, state->bbs_pk, rand->sprimerand,
            rand->skrand, rand->hrand, rand->tokenidrand,
            rand->hrands, state->difficulty);

    // g1_norm(coms->Acom, coms->Acom);
    // printf("Acom:\n");
    // g1_print(coms->Acom);

    bn_free(tmp);
}

void tandem_free_proof_commitments(struct tandem_proof_commitments *coms,
        size_t difficulty) {
    for(size_t i = 0; i < difficulty; i++) {
        g1_free(coms->ccoms[i]);
    }
    free(coms->ccoms);
    g1_free(coms->Acom);
    g1_free(coms->pkcom);
}

void tandem_obtain_proof_challenge(bn_t c, struct tandem_proof_commitments *coms,
        unsigned int *indices, size_t difficulty) {

    // Compute size
    size_t len = 0;
    for(unsigned int i = 0; i < difficulty; i++) {
        len += g1_size_bin(coms->ccoms[i], 1);
    }
    size_t lA = g1_size_bin(coms->Acom, 1);
    size_t lpk = g1_size_bin(coms->pkcom, 1);
    len += lA + lpk;
    len += difficulty * sizeof(unsigned int);

    uint8_t *buf = malloc(len);
    uint8_t *iptr = buf;

    for(unsigned int i = 0; i < difficulty; i++) {
        size_t elem_len = g1_size_bin(coms->ccoms[i], 1);
        g1_write_bin(iptr, elem_len, coms->ccoms[i], 1);
        iptr += elem_len;
    }
    g1_write_bin(iptr, lA, coms->Acom, 1);
    iptr += lA;
    g1_write_bin(iptr, lpk, coms->pkcom, 1);
    iptr += lpk;

    uint8_t *indices_ptr = (uint8_t *) indices;
    for(unsigned int i = 0; i < difficulty * sizeof(unsigned int); i++) {
        *iptr++ = *indices_ptr++;
    }

    uint8_t hash[RLC_MD_LEN_SH256];
    md_map_sh256(hash, buf, len);

    bn_null(c);
    bn_new(c);
    bn_read_bin(c, hash, 160 / 8);

    free(buf);
}

void
tandem_obtain_proof_create(struct tandem_proof *proof,
        struct tandem_proof_randomizers *rand,
        struct UserObtainState *state, bn_t c) {

    proof->hresps = malloc(state->st->difficulty * sizeof(bn_t));
    proof->rresps = malloc(state->st->difficulty * sizeof(bn_t));

    for(unsigned int i = 0; i < state->st->difficulty; i++) {
        bn_null(proof->hresps[i]);
        bn_new(proof->hresps[i]);
        bn_mul(proof->hresps[i], c, state->hash[state->complement[i]]);
        bn_add(proof->hresps[i], proof->hresps[i], rand->hrands[i]);
        bn_mod(proof->hresps[i], proof->hresps[i], state->st->com_pk->q);

        // printf("Attribute[%u]: ", i);
        // bn_print(state->hs[state->complement[i]]);

        bn_null(proof->rresps[i]);
        bn_new(proof->rresps[i]);
        bn_mul(proof->rresps[i], c, state->rs[state->complement[i]].r);
        bn_add(proof->rresps[i], proof->rresps[i], rand->rrands[i]);
        bn_mod(proof->rresps[i], proof->rresps[i], state->st->com_pk->q);
    }

    bn_null(proof->hresp);
    bn_new(proof->hresp);
    bn_mul(proof->hresp, c, state->ctxt_hash);
    bn_add(proof->hresp, proof->hresp, rand->hrand);
    bn_mod(proof->hresp, proof->hresp, state->st->com_pk->q);

    bn_null(proof->skresp);
    bn_new(proof->skresp);
    bn_mul(proof->skresp, c, state->st->skid);
    bn_add(proof->skresp, proof->skresp, rand->skrand);
    bn_mod(proof->skresp, proof->skresp, state->st->com_pk->q);

    bn_null(proof->sprimeresp);
    bn_new(proof->sprimeresp);
    bn_mul(proof->sprimeresp, c, state->s);
    bn_add(proof->sprimeresp, proof->sprimeresp, rand->sprimerand);
    bn_mod(proof->sprimeresp, proof->sprimeresp, state->st->com_pk->q);

    bn_null(proof->tokenidresp);
    bn_new(proof->tokenidresp);
    bn_mul(proof->tokenidresp, c, state->tokenid);
    bn_add(proof->tokenidresp, proof->tokenidresp, rand->tokenidrand);
    bn_mod(proof->tokenidresp, proof->tokenidresp, state->st->com_pk->q);

    bn_null(proof->challenge);
    bn_new(proof->challenge);
    bn_copy(proof->challenge, c);
}

void
tandem_free_obtain_proof(struct tandem_proof *proof, size_t difficulty) {
    for(size_t i = 0; i < difficulty; i++) {
        bn_free(proof->hresps[i]);
        bn_free(proof->rresps[i]);
    }

    bn_free(proof->sprimeresp);
    bn_free(proof->challenge);
    bn_free(proof->tokenidresp);
    bn_free(proof->skresp);
    bn_free(proof->hresp);

    free(proof->hresps);
    free(proof->rresps);
}

void
tandem_reconstruct_commitments(struct tandem_proof_commitments *coms,
        struct tandem_proof *proof, g1_t A, g1_t pkid,
        struct commit_com *Commits, unsigned int *complement,
        struct bbsplus_pk *bbs_pk, struct commit_pk *com_pk,
        size_t difficulty) {

    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    coms->ccoms = malloc(difficulty * sizeof(g1_t));

    for(size_t i = 0; i < difficulty; i++) {
        g1_null(coms->ccoms[i]);
        g1_new(coms->ccoms[i]);

        // ccoms[i] = C[complement[i]]^{-c} * g^{hresp[i]} * h^{rresp[i]}
        g1_neg(tmp, Commits[complement[i]].com);
        g1_mul(coms->ccoms[i], tmp, proof->challenge);
        g1_mul(tmp, com_pk->g, proof->hresps[i]);
        g1_add(coms->ccoms[i], coms->ccoms[i], tmp);
        g1_mul(tmp, com_pk->h, proof->rresps[i]);
        g1_add(coms->ccoms[i], coms->ccoms[i], tmp);

        // g1_norm(coms->ccoms[i], coms->ccoms[i]);
        // printf("CCom[%Zu]:\n", i);
        // g1_print(coms->ccoms[i]);
    }

    // pkcom = pkid^{-c} * g^{skresp}
    g1_null(coms->pkcom);
    g1_new(coms->pkcom);
    g1_neg(tmp, pkid);
    g1_mul(coms->pkcom, tmp, proof->challenge);
    g1_mul_gen(tmp, proof->skresp);
    g1_add(coms->pkcom, coms->pkcom, tmp);
    // g1_norm(coms->pkcom, coms->pkcom);
    // printf("pkcom: \n");
    // g1_print(coms->pkcom);

    // printf("Representation:\n");
    // g1_norm(A, A);
    // printf("A:\n");
    // g1_print(A);

    g1_null(coms->Acom);
    g1_new(coms->Acom);

    g1_neg(tmp, A);
    // Acom = (A^{-1})^{challenge} = A^{-challenge}
    g1_mul(coms->Acom, tmp, proof->challenge);

    // tmp = g
    g1_get_gen(tmp);
    // tmp = tmp^{challenge} = g^{challenge}
    g1_mul(tmp, tmp, proof->challenge);

    // Acom = Acom * tmp = A^{-challenge} * g^{challenge}
    g1_add(coms->Acom, coms->Acom, tmp);

    // tmp = B[0]^{sprimeresp} * B[1]^{hresp[i]} * ...
    credential_commitment_represent(tmp, bbs_pk, proof->sprimeresp,
            proof->skresp, proof->hresp, proof->tokenidresp,
            proof->hresps, difficulty);
    g1_add(coms->Acom, coms->Acom, tmp);

    // g1_norm(coms->Acom, coms->Acom);
    // printf("Acom:\n");
    // g1_print(coms->Acom);
}

void
tandem_gen_user_make_token(struct ServerToken *stoken,
        struct KeyShareToken *token, struct UserState *state) {

    size_t k = state->difficulty;

    bn_t *attributes = malloc((k + 3) * sizeof(bn_t));
    for(unsigned int i = 0; i < k + 3; i++) {
        bn_null(attributes[i]);
        bn_new(attributes[i]);
    }

    bn_copy(attributes[0], state->skid);
    bn_copy(attributes[1], token->ctxt_hash);
    bn_copy(attributes[2], token->tokenid);

    // Copy hash-values
    for(unsigned int i = 0; i < k; i++) {
        bn_copy(attributes[i + 3], token->hash[i]);
    }

    unsigned int hidden[1] = {0};
    bbsplus_prove(&stoken->proof, &token->sign, state->bbs_pk,
            attributes, k + 3, hidden, 1, NULL, 0);

    // Compute gammas
    stoken->gammas = malloc(k * sizeof(struct homenc_ptxt));
    for(unsigned int i = 0; i < k; i++) {
        homenc_init_ptxt(stoken->gammas + i);
        mpz_sub((stoken->gammas + i)->m, token->delta.m,
                (token->deltas + i)->m);
    }

    // Compute nus
    stoken->nus = malloc(k * sizeof(struct homenc_encrand));
    for(unsigned int i = 0; i < k; i++) {
        homenc_init_encrand(stoken->nus + i);
        mpz_invert((stoken->nus + i)->r, (token->kappas + i)->r,
                state->pk->n);
        mpz_mul((stoken->nus + i)->r, (stoken->nus + i)->r,
                token->kappa.r);
    }

    // TODO: maybe make this a real copy?
    stoken->cs = token->cs;

    homenc_init_ctxt(&stoken->ctxt);
    mpz_set(stoken->ctxt.c, token->ctxt.c);

    bn_null(stoken->tokenid);
    bn_new(stoken->tokenid);
    bn_copy(stoken->tokenid, token->tokenid);
}

void
tandem_clear_server_token(struct ServerToken *stoken, size_t difficulty) {
    for(unsigned int i = 0; i < difficulty; i++) {
        homenc_clear_ptxt(stoken->gammas + i);
        homenc_clear_encrand(stoken->nus + i);
    }

    bbsplus_proof_free(&stoken->proof);
    free(stoken->gammas);
    free(stoken->nus);
}

int
tandem_gen_server_check_token(struct ServerToken *stoken,
        struct ServerState *state) {

    // Check disclosure proof
    int verifies =
        bbsplus_proof_verify(&stoken->proof, state->bbs_pk, state->difficulty + 3,
                NULL, 0);
    if(!verifies) {
        printf("ERROR: disclosure proof does not verify\n");
        return 0;
    }

    // Check hashes of ciphertexts
    bn_t h;
    bn_null(h);
    bn_new(h);

    hash_mpz_to_bn_t(h, stoken->ctxt.c, state->com_pk->q);
    if(bn_cmp(h, stoken->proof.disclosed[0]) != RLC_EQ) {
        printf("ERROR: hash of ctxt is wrong!\n");
        return 0;
    }

    for(unsigned int i = 0; i < state->difficulty; i++) {
        hash_mpz_to_bn_t(h, (stoken->cs + i)->c, state->com_pk->q);
        if(bn_cmp(h, stoken->proof.disclosed[i+2]) != RLC_EQ) {
            printf("ERROR: hash of ctxt[%i] is wrong!\n", i);
            return 0;
        }
    }
    bn_free(h);

    // Check tokenid (this is not strictly necessary, the disclosed
    // value would suffice).
    if(bn_cmp(stoken->proof.disclosed[1],
                stoken->tokenid) != RLC_EQ) {
        printf("ERROR: disclosed token id is wrong\n");
        return 0;
    }
    // TODO: check if tokenid blocked

    // Checking ciphertexts and gammas
    struct homenc_ctxt ctmp;
    homenc_init_ctxt(&ctmp);

    for(unsigned int i = 0; i < state->difficulty; i++) {
        if(mpz_cmp(state->delta_limit, (stoken->gammas + i)->m) <= 0) {
            gmp_printf("limit: %Zd\n seen: %Zd\n", state->delta_limit, (stoken->gammas+i)->m);
            printf("ERROR: gamma[%u] too big\n", i);
            return 0;
        }

        homenc_enc_r(&ctmp, state->pk, stoken->gammas + i, stoken->nus + i);
        homenc_add(&ctmp, state->pk, stoken->cs + i, &ctmp);
        if(mpz_cmp(ctmp.c, stoken->ctxt.c) != 0) {
            printf("ERROR: ciphertext equality does not hold\n");
            return 0;
        }
    }

    homenc_clear_ctxt(&ctmp);

    return 1;
}

void
tandem_gen_server_compute_share(bn_t sshare, struct ServerToken *stoken,
        struct ServerState *state) {
    struct homenc_ptxt ptxt;
    homenc_init_ptxt(&ptxt);
    homenc_dec(&ptxt, state->pk, state->sk, &stoken->ctxt);

    bn_null(sshare);
    bn_new(sshare);
    bn_from_mpz(sshare, ptxt.m);
    bn_mod(sshare, sshare, state->com_pk->q);

    homenc_clear_ptxt(&ptxt);
}
