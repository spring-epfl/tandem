#include <relic/relic.h>
#include <sodium.h>

#include "utils.h"

void
bn_inv_mod(bn_t res, const bn_t input, const bn_t n) {
    bn_t tmp1, tmp2;
    bn_null(tmp1);
    bn_new(tmp1);
    bn_null(tmp2);
    bn_new(tmp2);

    bn_gcd_ext(tmp1, res, tmp2, input, n);

    if(bn_sign(res) == RLC_NEG) {
        bn_add(res, res, n);
    }
}


/*
 * Creates n bn_t's containing nr_bytes bytes of random stream
 *
 * NOTE: The key needs to be 32 bytes
 */
void
bn_rands_from_stream(bn_t *res, size_t n, size_t nr_bytes,
        uint8_t *key) {
    // Always using a fixed nonce
    uint64_t nonce = 0;

    size_t stream_len = n * nr_bytes;
    uint8_t *stream = malloc(stream_len);

    crypto_stream_salsa20(stream, stream_len, (uint8_t *) &nonce, key);

    for(int i = 0; i < n; i++) {
        bn_null(res[i]);
        bn_new(res[i]);
        bn_read_bin(res[i], stream + i * nr_bytes, nr_bytes);
    }

    free(stream);
}

void
print_bytes(uint8_t *p, int count) {
    uint8_t* p_end = p + count;
    unsigned int i = 0;
    for(;p < p_end; p++) {
        printf("%02x", *p);
        i++;
        if(i > 0 && i % 8 == 0 && i < 64) {
            printf(" ");
        }
        if(i == 32) {
            printf("\n");
            i = 0;
        }
    }
    printf("\n");
}

void
paillier_plaintext_from_bn_t(paillier_plaintext_t *xs_ptxt, bn_t xs) {
    size_t len = bn_size_bin(xs);
    uint8_t *buf = malloc(len);
    bn_write_bin(buf, len, xs);
    //printf("Original:  "); bn_print(xs);

    mpz_import(xs_ptxt->m, len, 1, 1, 1, 0, buf);
    //gmp_printf("Converted: %Zx", xs_ptxt->m);

    free(buf);
}

void hash_mpz_to_bn_t(bn_t h, mpz_t n, bn_t q) {
    size_t nr_bytes = (mpz_sizeinbase(n,2) + 7) / 8;
    uint8_t *buf = malloc(nr_bytes);

    size_t len;
    mpz_export(buf, &len, 1, 1, 1, 0, n);

    uint8_t hash[RLC_MD_LEN_SH512];
    md_map_sh512(hash, buf, len);
    bn_read_bin(h, hash, RLC_MD_LEN_SH512);
    bn_mod(h, h, q);

    free(buf);
}

// COMMENT: this hash-function does not properly seperate the domains,
// so it might not be completely secure.
void hash_mpz_and_g1_to_bn(bn_t h, mpz_t n, g1_t m, bn_t q) {
    size_t l_mpz = (mpz_sizeinbase(n,2) + 7) / 8;
    size_t l_g1 = g1_size_bin(m, 1);
    uint8_t *buf = malloc(l_mpz + l_g1);

    mpz_export(buf, &l_mpz, 1, 1, 1, 0, n);
    g1_write_bin(buf + l_mpz, l_g1, m, 1);

    uint8_t hash[RLC_MD_LEN_SH512];
    md_map_sh512(hash, buf, l_mpz + l_g1);
    bn_read_bin(h, hash, RLC_MD_LEN_SH512);
    bn_mod(h, h, q);

    free(buf);
}

void sample_subset(unsigned int **indices, size_t subset_size, size_t set_size) {
    unsigned int nr_chosen = 0;

    *indices = malloc(subset_size * sizeof(unsigned int));

    // If indicator[i] = 1 -> element[i] has been chosen
    uint8_t *indicators = calloc(set_size, sizeof(uint8_t));

    while(nr_chosen < subset_size) {
        uint32_t index = randombytes_uniform(set_size - nr_chosen);
        uint32_t real_index = 0;
        for(uint32_t i = 0; i < index; i++) {
            // Skip items already chosen
            while(indicators[real_index] == 1) {
                real_index++;
            }
            // Move because index says so
            real_index++;
        }
        // Move to next unchosen item
        while(indicators[real_index] == 1) {
            real_index++;
        }
        // indicator[real_index] == 0

        indicators[real_index] = 1;
        nr_chosen++;
    }

    // Output proper indices into array
    size_t output_idx = 0;
    for(unsigned int i = 0; i < set_size; i++) {
        if(indicators[i] == 1) {
            (*indices)[output_idx] = i;
            output_idx++;
        }
    }

    free(indicators);
}

void complement_of_indices(unsigned int **complement, unsigned int *indices,
        size_t indices_size, size_t max) {

    *complement = malloc( (max - indices_size) * sizeof(unsigned int));

    unsigned int idx = 0;
    unsigned int set_idx = 0;
    for(unsigned int val = 0; val < max; val ++) {
        if( set_idx >= indices_size || indices[set_idx] > val ) {
            (*complement)[idx++] = val;
        } else {
            set_idx++;
        }
    }
}

void print_set(unsigned int *set, size_t set_size) {
    printf("[");
    for(size_t i = 0; i < set_size; i++) {
        printf("%u", set[i]);
        if(i < set_size - 1) {
            printf(", ");
        }
    }
    printf("]\n");
}

void bn_from_mpz(bn_t b, mpz_t m) {
    unsigned char *buf = malloc( (mpz_sizeinbase(m, 2) + 7) / 8 );
    size_t len;
    mpz_export(buf, &len, 1, 1, 1, 0, m);
    bn_read_bin(b, buf, len);
    free(buf);
}

void mpz_from_bn(mpz_t m, bn_t b) {
    unsigned char *buf = malloc( (bn_bits(b) + 7) / 8 );
    size_t len = bn_size_bin(b);
    bn_write_bin(buf, len, b);
    mpz_import(m, len, 1, 1, 1, 0, buf);
    // bn_print(b);
    // gmp_printf("%ZX\n", m);
    free(buf);
}

void bignum_from_mpz(BIGNUM **a, mpz_t b) {
    size_t mpz_len = mpz_sizeinbase(b, 16) + 2;
    char *buf = malloc(mpz_len);
    //gmp_printf("%ZX\n", b);
    gmp_snprintf(buf, mpz_len, "%ZX", b);
    //printf("%s\n", buf);
    BN_hex2bn(a, buf);
    //BN_print_fp(stdout, *a); printf("\n");
}

void bignum_from_bn(BIGNUM **a, bn_t b) {
    mpz_t val;
    mpz_init(val);
    //bn_print(b); printf("\n");
    mpz_from_bn(val, b);
    bignum_from_mpz(a, val);
    mpz_clear(val);
}
