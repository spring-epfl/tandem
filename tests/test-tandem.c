#include <stdio.h>
#include "tandem.h"
#include "homenc.h"

#define MODULUS_BITS 2048
#define PTXT_BITS 394

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

    // GMP setup
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);

    // Difficulty
    size_t difficulty = 2;
    printf("Difficulty is set to %zu\n", difficulty);

    // Setup homenc scheme
    struct homenc_sk sk;
    struct homenc_pk pk;
    homenc_keygen(MODULUS_BITS, PTXT_BITS, &pk, &sk, rand_state);

    // Setup commitment scheme
    struct commit_pk com_pk;
    commit_keygen(&com_pk);
    printf("G1 element size: %i\n", g1_size_bin(com_pk.h, 1));

    // Setup BBS+
    struct bbsplus_pk bbs_pk;
    struct bbsplus_sk bbs_sk;
    bbsplus_keygen(&bbs_pk, &bbs_sk, difficulty + 3);

    // Setup big commit group + openssl context
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    if(group == NULL) {
        printf("ERROR: could not instantiate group\n");
        exit(1);
    }
    BN_CTX *ctx = BN_CTX_new();
    if(ctx == NULL) {
        printf("Could not allocate CTXT\n");
        exit(1);
    }
    // WARNING: This way of generating genh is not secure
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(group, order, NULL);
    EC_POINT *genh = EC_POINT_new(group);
    BIGNUM *exph = BN_new();
    BN_rand_range(exph, order);
    const EC_POINT *gen = EC_GROUP_get0_generator(group);
    EC_POINT_mul(group, genh, NULL, gen, exph, ctx);

    // Generate key-shares
    bn_t xu, xs, x;
    bn_null(xu);
    bn_null(xs);
    bn_null(x);

    bn_new(xu);
    bn_new(xs);
    bn_new(x);

    bn_rand_mod(xu, com_pk.q);
    bn_rand_mod(xs, com_pk.q);
    bn_add(x, xu, xs);
    bn_mod(x, x, com_pk.q);

    printf("Xu: "); bn_print(xu);
    printf("Xs: "); bn_print(xs);
    printf("X:  "); bn_print(x);
    printf("Group order: "); bn_print(com_pk.q);

    struct ServerState server_state;
    tandem_setup_server(&server_state, &pk, &sk, &bbs_pk, &bbs_sk,
            &com_pk, xs, difficulty, &rand_state, group, genh, ctx);

    struct UserState user_state;
    tandem_setup_user(&user_state, &pk, &bbs_pk, &com_pk,
            xu, difficulty, &rand_state, group, genh, ctx);

    // **************************************
    // *************** REGISTER *************
    // **************************************

    // This registration procedure is _not_ complete. It implements the
    // beginning of the Register protocol, but does not include the server's
    // range proof of correct encryption.

    struct ServerRegisterState server_register_state;
    struct RegisterServerStart register_server_start_msg;
    tandem_register_server_start(&register_server_start_msg,
            &server_register_state, &server_state);

    struct UserRegisterState user_register_state;
    struct RegisterUserStart register_user_start_msg;
    tandem_register_user_start(&register_user_start_msg,
            &user_register_state, &user_state, 
            &register_server_start_msg);

    // WARNING: in the real registration protocol user needs to verify server's
    // message
    tandem_setup_fakeregister(&user_state, &server_state);

    // **************************************
    // **************** OBTAIN **************
    // **************************************

    // Tandem server -> User
    struct ServerObtainState server_obtain_state;
    struct ServerObtainStart server_start_msg;
    tandem_obtain_server_start(&server_start_msg,
            &server_obtain_state, &server_state);

    // User -> Tandem server
    struct UserObtainState user_obtain_state;
    struct UserObtainCommitMsg commit_msg;
    tandem_obtain_user_cut(&user_obtain_state, &commit_msg,
            &user_state, &server_start_msg);

    // Tandem server -> User
    struct ServerObtainChoice choice_msg;
    tandem_obtain_server_choose(&choice_msg, &server_obtain_state, &commit_msg);

    // User -> Server
    struct UserObtainReveal reveal_msg;
    tandem_obtain_user_reveal(&reveal_msg, &choice_msg, &user_obtain_state);

    // Server -> User
    struct ServerObtainIssue issue_msg;
    int correct =
        tandem_obtain_server_check_and_issue(&issue_msg, &server_obtain_state, &reveal_msg);
    if(!correct) {
        printf("ERROR: server obtain verification failed");
        exit(1);
    }

    // User
    struct KeyShareToken token;
    int sig_correct = tandem_obtain_user_token(&token, &issue_msg, &user_obtain_state);
    if(!sig_correct) {
        printf("ERROR: obtain server signature verification failed");
        exit(1);
    }

    tandem_free_user_reveal(&reveal_msg, difficulty);

    // tandem_free_user_obtain_state(&user_obtain_state);
    // tandem_free_server_obtain_state(&server_obtain_state);
    // tandem_free_server_obtain_choice(&choice_msg);

    //
    // GENERATING KEY-SHARES NOW

    // User sends disclosure proof and ciphertexts
    struct ServerToken stoken;
    tandem_gen_user_make_token(&stoken, &token, &user_state);

    // Server checks ServerToken and computes key-share
    int checked = 
        tandem_gen_server_check_token(&stoken, &server_state);

    if(!checked) {
        printf("ERROR: server refused token\n");
        exit(1);
    }

    bn_t sshare;
    tandem_gen_server_compute_share(sshare, &stoken, &server_state);

    bn_t x_rec;
    bn_null(x_rec);
    bn_new(x_rec);
    bn_add(x_rec, sshare, token.ushare);
    bn_mod(x_rec, x_rec, com_pk.q);

    printf("Xu: "); bn_print(token.ushare);
    printf("Xs: "); bn_print(sshare);
    printf("X:  "); bn_print(x_rec);

    if(bn_cmp(x, x_rec) != RLC_EQ) {
        printf("ERROR: incorrect key recovered\n");
    } else {
        printf("CORRECT: recovered same key\n");
    }

    tandem_free_user_token(&token);
    tandem_clear_server_token(&stoken, difficulty);

    tandem_clear_user_state(&user_state);
    tandem_clear_server_state(&server_state);

    homenc_clear_pk(&pk);
    homenc_clear_sk(&sk);

    bbsplus_pk_free(&bbs_pk);
    bbsplus_sk_free(&bbs_sk);

    commit_pk_free(&com_pk);

    gmp_randclear(rand_state);

    return 0;
}
