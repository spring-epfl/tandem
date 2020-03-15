/**
 * Script to compute benchmarks for Tandem protocols
 *
 * The script takes as input the difficulty level k for the cut-and-choose
 * parts of the protocol. A reasonable value for k in practice is k=20. In
 * the paper we evaluate up to k=64 which gives almost 128 bits of security.
 *
 * The results are printed to standard out and accumulated in the file
 * "test.log". If at any point one of the parties aborts. This script will
 * abort as well.
 *
 * To run the script, simply call:
 *
 *       ./bench-tandem <difficulty>
 *
 */

#include <stdio.h>
#include "tandem.h"
#include <time.h>
#include <math.h>

/******************************
 **** SCRIPT CONFIGURATION ****
 ******************************/

#define MODULUS_BITS 2048
#define PTXT_BITS 394

#define NR_EXPERIMENTS 100
#define LOG_FILE "test.log"


// Internal defines
#define NR_METRICS 16
#define METRIC_OBTAIN_SERVER_START 0
#define METRIC_OBTAIN_USER_CUT 1
#define METRIC_OBTAIN_SERVER_CHOOSE 2
#define METRIC_OBTAIN_USER_REVEAL 3
#define METRIC_OBTAIN_SERVER_CHECK_AND_ISSUE 4
#define METRIC_OBTAIN_USER_TOKEN 5
#define METRIC_OBTAIN_USER_TOTAL 6
#define METRIC_OBTAIN_SERVER_TOTAL 7
#define METRIC_OBTAIN_TOTAL 8

#define METRIC_GENSHARES_USER 9
#define METRIC_GENSHARES_SERVER_CHECK 10
#define METRIC_GENSHARES_SERVER_COMPUTE 11
#define METRIC_GENSHARES_SERVER_TOTAL 12
#define METRIC_GENSHARES_TOTAL 13

#define METRIC_HOMENC_ENC 14
#define METRIC_HOMENC_DEC 15

char *metric_names[] = {
    "ObtainServerStart",
    "ObtainUserCut",
    "ObtainServerChoose",
    "ObtainUserReveal",
    "ObtainServerCheckAndIssue",
    "ObtainUserToken",
    "ObtainUserTotal",
    "ObtainServerTotal",
    "ObtainTotal",
    "GenSharesUser",
    "GenSharesServerCheck",
    "GenSharesServerCompute",
    "GenSharesServerTotal",
    "GenSharesTotal",
    "HomEncEnc",
    "HomEncDec",
};

#define CLOCK_START tic = clock();
#define CLOCK_RECORD(TYPE,I) \
    toc = clock();\
    measurements[TYPE][I] = (double)(toc - tic) / CLOCKS_PER_SEC;

double measurements[NR_METRICS][NR_EXPERIMENTS];

void
compute_metric_statistics(double *mean, double *error,
        double *measurements, size_t nr_measurements) {
    double sum = 0;
    for(unsigned int i = 0; i < nr_measurements; i++) {
        sum += measurements[i];
    }
    *mean = sum / nr_measurements;

    double sum_sqerror = 0;
    double tmp;
    for(unsigned int i = 0; i < nr_measurements; i++) {
        tmp = measurements[i] - *mean;
        sum_sqerror += tmp * tmp;
    }
    *error = sqrt( sum_sqerror / (nr_measurements - 1) ) / sqrt(nr_measurements);
}

void
print_benchmarks(size_t difficulty) {
    printf("Metrics for obtain phase (difficulty = %li)\n", difficulty);

    double mean, error;

    for(unsigned int i = 0; i < NR_METRICS; i++) {
        printf("%25s: ", metric_names[i]);

        compute_metric_statistics(&mean, &error,
                measurements[i], NR_EXPERIMENTS);
        printf("%f s (std. error %f s)\n", mean, error);
    }
}

void
log_benchmarks(size_t difficulty, char *logfile) {
    FILE *f = fopen(logfile, "a+");

    // Print header for log file
    fprintf(f, "# difficulty bitlength ");
    for(unsigned int i = 0; i < NR_METRICS; i++) {
        fprintf(f, "%s %sError ", metric_names[i], metric_names[i]);
    }
    fprintf(f,"\n");

    // Print data row
    double mean, error;
    fprintf(f, "%li %i ", difficulty, MODULUS_BITS);
    for(unsigned int i = 0; i < NR_METRICS; i++) {
        compute_metric_statistics(&mean, &error,
                measurements[i], NR_EXPERIMENTS);
        fprintf(f, "%f %f ", mean, error);
    }
    fprintf(f,"\n");
}

int
main(int argc, char** argv) {

    // Difficulty
    size_t difficulty;

    if(argc <= 1) {
        printf("Please supply difficulty as argument\n");
        exit(1);
    } else {
        difficulty = atoi(argv[1]);
    }
    printf("Configuration:\n");
    printf("  Difficulty is set to k=%zu\n", difficulty);
    printf("  Joux-Libert ciphertexts are %i bits\n", MODULUS_BITS);
    printf("  Joux-Libert plaintexts are %i bits\n", PTXT_BITS);
    printf("  Running %i experiments\n\n", NR_EXPERIMENTS);

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

    // Setup commitment scheme
    struct commit_pk com_pk;
    commit_keygen(&com_pk);

    // Setup homenc scheme
    struct homenc_sk sk;
    struct homenc_pk pk;
    homenc_keygen(MODULUS_BITS, PTXT_BITS, &pk, &sk, rand_state);

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

    struct ServerState server_state;
    struct UserState user_state;

    struct ServerObtainState server_obtain_state;
    struct UserObtainState user_obtain_state;

    struct ServerObtainStart server_start_msg;
    struct UserObtainCommitMsg commit_msg;
    struct ServerObtainChoice choice_msg;
    struct UserObtainReveal reveal_msg;
    struct ServerObtainIssue issue_msg;
    struct KeyShareToken token;

    struct ServerToken stoken;

    clock_t tic, toc;
    clock_t tic_total, toc_total;

    int obtain_correct;
    int obtain_sig_correct;

    bn_t x_rec;
    bn_null(x_rec);

    bn_t sshare;

    bn_new(xu);
    bn_new(xs);
    bn_new(x);

    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        tic_total = clock();

        // #########################################
        // ############## Setup() ##################
        // #########################################
        bn_rand_mod(xu, com_pk.q);
        bn_rand_mod(xs, com_pk.q);
        bn_add(x, xu, xs);
        bn_mod(x, x, com_pk.q);

        tandem_setup_server(&server_state, &pk, &sk, &bbs_pk, &bbs_sk,
                &com_pk, xs, difficulty, &rand_state, group, genh, ctx);
        tandem_setup_user(&user_state, &pk, &bbs_pk, &com_pk,
                xu, difficulty, &rand_state, group, genh, ctx);

        // #########################################
        // ############# Register() ################
        // ####### WARNING: NOT IMPLEMENTED ########
        // #########################################

        tandem_setup_fakeregister(&user_state, &server_state);

        // #########################################
        // ############# ObtainToken() #############
        // #########################################

        // Tandem server -> User
        CLOCK_START;
        tandem_obtain_server_start(&server_start_msg, &server_obtain_state,
                &server_state);
        CLOCK_RECORD(METRIC_OBTAIN_SERVER_START, i);

        // User -> Tandem server
        CLOCK_START;
        tandem_obtain_user_cut(&user_obtain_state, &commit_msg,
                &user_state, &server_start_msg);
        CLOCK_RECORD(METRIC_OBTAIN_USER_CUT, i);

        // Tandem server -> User
        CLOCK_START;
        tandem_obtain_server_choose(&choice_msg, &server_obtain_state, &commit_msg);
        CLOCK_RECORD(METRIC_OBTAIN_SERVER_CHOOSE, i);

        // User -> Server
        CLOCK_START;
        tandem_obtain_user_reveal(&reveal_msg, &choice_msg, &user_obtain_state);
        CLOCK_RECORD(METRIC_OBTAIN_USER_REVEAL, i);

        // Server -> User
        CLOCK_START;
        obtain_correct = tandem_obtain_server_check_and_issue(
                &issue_msg, &server_obtain_state, &reveal_msg);
        CLOCK_RECORD(METRIC_OBTAIN_SERVER_CHECK_AND_ISSUE, i);
        if(!obtain_correct) {
            printf("ERROR: server rejected user message in obtain\n");
            exit(1);
        }

        // User
        CLOCK_START;
        obtain_sig_correct = tandem_obtain_user_token(&token, &issue_msg,
                &user_obtain_state);
        CLOCK_RECORD(METRIC_OBTAIN_USER_TOKEN, i);
        if(!obtain_sig_correct) {
            printf("ERROR: user rejected server signature in obtain\n");
            exit(1);
        }

        toc_total = clock();
        measurements[METRIC_OBTAIN_TOTAL][i] =
            (double)(toc_total - tic_total) / CLOCKS_PER_SEC;

        // Record total time for user
        measurements[METRIC_OBTAIN_USER_TOTAL][i] =
            measurements[METRIC_OBTAIN_USER_CUT][i] +
            measurements[METRIC_OBTAIN_USER_REVEAL][i] +
            measurements[METRIC_OBTAIN_USER_TOKEN][i];

        // Record total time for server
        measurements[METRIC_OBTAIN_SERVER_TOTAL][i] =
            measurements[METRIC_OBTAIN_SERVER_START][i] +
            measurements[METRIC_OBTAIN_SERVER_CHOOSE][i] +
            measurements[METRIC_OBTAIN_SERVER_CHECK_AND_ISSUE][i];

        // #########################################
        // ############## GenShares() ##############
        // #########################################

        tic_total = clock();

        // User sends disclosure proof and ciphertexts
        CLOCK_START;
        tandem_gen_user_make_token(&stoken, &token, &user_state);
        CLOCK_RECORD(METRIC_GENSHARES_USER, i);

        // Server checks ServerToken and computes key-share
        CLOCK_START;
        int checked =
            tandem_gen_server_check_token(&stoken, &server_state);
        CLOCK_RECORD(METRIC_GENSHARES_SERVER_CHECK, i);

        if(!checked) {
            printf("ERROR: server refused token\n");
            exit(1);
        }

        CLOCK_START;
        tandem_gen_server_compute_share(sshare, &stoken, &server_state);
        CLOCK_RECORD(METRIC_GENSHARES_SERVER_COMPUTE, i);

        // Record total server time for GenShares()
        measurements[METRIC_GENSHARES_SERVER_TOTAL][i] =
            measurements[METRIC_GENSHARES_SERVER_CHECK][i] +
            measurements[METRIC_GENSHARES_SERVER_COMPUTE][i];

        bn_new(x_rec);
        bn_add(x_rec, sshare, token.ushare);
        bn_mod(x_rec, x_rec, com_pk.q);

        if(bn_cmp(x, x_rec) != RLC_EQ) {
            printf("ERROR: incorrect key recovered\n");
            exit(1);
        }

        toc_total = clock();
        measurements[METRIC_GENSHARES_TOTAL][i] =
            (double)(toc_total - tic_total) / CLOCKS_PER_SEC;

        tandem_free_user_reveal(&reveal_msg, difficulty);
        tandem_free_user_token(&token);
        tandem_clear_server_token(&stoken, difficulty);
        tandem_clear_user_state(&user_state);
        tandem_clear_server_state(&server_state);
    }

    struct homenc_ptxt *m = malloc(2 * difficulty * sizeof(struct homenc_ptxt));
    struct homenc_ctxt *c = malloc(2 * difficulty * sizeof(struct homenc_ctxt));
    struct homenc_ptxt *res = malloc(difficulty * sizeof(struct homenc_ptxt));

    // Benchmark HomEnc at this level of difficulty
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        // Generate some messages
        for(int j = 0; j < 2*difficulty; j++) {
            homenc_init_ptxt(m + j);
            mpz_urandomb((m + j)->m, rand_state, PTXT_BITS);
        }

        // Trial encryption
        CLOCK_START;
        for(int j = 0; j < 2*difficulty; j++) {
            homenc_init_ctxt(c + j);
            homenc_enc(c + j, &pk, m + j, rand_state);
        }
        CLOCK_RECORD(METRIC_HOMENC_ENC, i);

        // Trial decryption
        CLOCK_START;
        homenc_init_ptxt(res);
        homenc_dec(res, &pk, &sk, c);
        CLOCK_RECORD(METRIC_HOMENC_DEC, i);

        homenc_clear_ptxt(res);
    }

    print_benchmarks(difficulty);
    log_benchmarks(difficulty, LOG_FILE);

    homenc_clear_pk(&pk);
    homenc_clear_sk(&sk);

    bbsplus_pk_free(&bbs_pk);
    bbsplus_sk_free(&bbs_sk);
    commit_pk_free(&com_pk);

    return 0;
}
