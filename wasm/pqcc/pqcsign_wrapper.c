#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include "pqcsign_wrapper.h"
#include <string.h>
#include "./pqmagic/utils/randombytes.h"
#include "fips202.h"

#define MAX_SEED_LEN 72
#define SCHEME_COUNT 4

//#define DEBUG

size_t public_key_bytes[4] = {
    AIGIS_SIG3_PUBLICKEYBYTES, DILITHIUM3_PUBLICKEYBYTES, ML_DSA_65_PUBLICKEYBYTES,
    SLH_DSA_SHAKE_192f_PUBLICKEYBYTES
};
size_t secret_key_bytes[4] = {
    AIGIS_SIG3_SECRETKEYBYTES, DILITHIUM3_SECRETKEYBYTES, ML_DSA_65_SECRETKEYBYTES,
    SLH_DSA_SHAKE_192f_SECRETKEYBYTES
};

static int is_valid_scheme(int scheme) {
    return scheme >= 0 && scheme < SCHEME_COUNT;
}

static int derive_seed(uint8_t *seed, const uint8_t *input, size_t input_len) {
    if (seed == NULL || (input == NULL && input_len > 0)) {
        return -1;
    }
    shake256(seed, MAX_SEED_LEN, input, input_len);
    return 0;
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
    #ifdef DEBUG
    printf("%s: ", label);
    #endif
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int keyGen(int scheme, uint8_t *pk, uint8_t *sk) {
    if (!is_valid_scheme(scheme)) {
        return -1;
    }
    if (pk == NULL || sk == NULL) {
        return -3;
    }

    int ret = 0;
    switch (scheme) {
        case AIGIS_SIG:
            ret = pqmagic_aigis_sig3_std_keypair(pk, sk);
            break;
        case DILITHIUM:
            ret = pqmagic_dilithium3_std_keypair(pk, sk);
            break;
        case ML_DSA:
            ret = pqmagic_ml_dsa_65_std_keypair(pk, sk);
            break;
        case SLH_DSA:
            ret = pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(pk, sk);
            break;
        default:
            ret = -1;
    }
    #ifdef DEBUG
    print_hex("Public Key", pk, public_key_bytes[scheme]);
    print_hex("Secret Key", sk, secret_key_bytes[scheme]);
    #endif
    return ret;
}

int keyGenWithSeed(int scheme, uint8_t *pk, uint8_t *sk, const uint8_t *prepk, size_t prepklen) {
    if (!is_valid_scheme(scheme)) {
        return -1;
    }
    if (pk == NULL || sk == NULL || (prepk == NULL && prepklen > 0)) {
        return -3;
    }

    uint8_t *seed = malloc(MAX_SEED_LEN);
    if (seed == NULL) {
        return -4;
    }

    int ret = 0;
    if (derive_seed(seed, prepk, prepklen) != 0) {
        free(seed);
        return -3;
    }

    switch (scheme) {
        case AIGIS_SIG:
            ret = pqmagic_aigis_sig3_std_keypair_internal(pk, sk, seed);
            break;
        case DILITHIUM:
            ret = pqmagic_dilithium3_std_keypair_internal(pk, sk, seed);
            break;
        case ML_DSA:
            ret = pqmagic_ml_dsa_65_std_keypair_internal(pk, sk, seed);
            break;
        case SLH_DSA:
            ret = pqmagic_slh_dsa_shake_192f_simple_std_sign_seed_keypair(pk, sk, seed);
            break;
        default:
            ret = -1;
            break;
    }
    #ifdef DEBUG
    print_hex("Seed", seed, MAX_SEED_LEN);
    print_hex("Public Key", pk, public_key_bytes[scheme]);
    print_hex("Secret Key", sk, secret_key_bytes[scheme]);
    #endif
    free(seed);
    return ret;
}

int sign(int scheme, uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    if (!is_valid_scheme(scheme)) {
        return -1;
    }
    if (sig == NULL || siglen == NULL || (m == NULL && mlen > 0) || sk == NULL) {
        return -3;
    }

    int ret = 0;
    switch (scheme) {
        case AIGIS_SIG:
            ret = pqmagic_aigis_sig3_std_signature_internal(sig, siglen, m, mlen, sk);
            break;
        case DILITHIUM:
            ret = pqmagic_dilithium3_std_signature(sig, siglen, m, mlen, sk);
            break;
        case ML_DSA: {
            uint8_t coins[ML_DSA_SEEDBYTES];
            randombytes(coins, sizeof(coins));
            ret = pqmagic_ml_dsa_65_std_signature_internal(sig, siglen, m, mlen, coins, sk);
            break;
        }
        case SLH_DSA:
            ret = pqmagic_slh_dsa_shake_192f_simple_std_sign_signature(sig, siglen, m, mlen, sk);
            break;
        default:
            ret = -1;
            break;
    }
    #ifdef DEBUG
    print_hex("Message", m, mlen);
    print_hex("Signature", sig, *siglen);
    #endif
    return ret;
}

int verify(int scheme, const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    if (!is_valid_scheme(scheme)) {
        return -1;
    }
    if (sig == NULL || (m == NULL && mlen > 0) || pk == NULL) {
        return -3;
    }

    int ret = 0;
    switch (scheme) {
        case AIGIS_SIG:
            ret = pqmagic_aigis_sig3_std_verify_internal(sig, siglen, m, mlen, pk);
            break;
        case DILITHIUM:
            ret = pqmagic_dilithium3_std_verify(sig, siglen, m, mlen, pk);
            break;
        case ML_DSA:
            ret = pqmagic_ml_dsa_65_std_verify_internal(sig, siglen, m, mlen, pk);
            break;
        case SLH_DSA:
            ret = pqmagic_slh_dsa_shake_192f_simple_std_sign_verify(sig, siglen, m, mlen, pk);
            break;
        default:
            ret = -1;
            break;
    }
    #ifdef DEBUG
    print_hex("Message", m, mlen);
    print_hex("Signature", sig, siglen);
    print_hex("Public Key", pk, public_key_bytes[scheme]);
    #endif
    return ret;
}

int VerifyKeyGen(int scheme, const uint8_t *fsk, const uint8_t *bsk, const uint8_t *bpk) {
    if (!is_valid_scheme(scheme)) {
        return -1;
    }
    if (fsk == NULL || bsk == NULL || bpk == NULL) {
        return -3;
    }

    size_t pk_len = public_key_bytes[scheme];
    size_t sk_len = secret_key_bytes[scheme];
    uint8_t *tpk = malloc(pk_len);
    uint8_t *tsk = malloc(sk_len);
    uint8_t *seed = malloc(MAX_SEED_LEN);
    if (tpk == NULL || tsk == NULL || seed == NULL) {
        free(tpk);
        free(tsk);
        free(seed);
        return -4;
    }

    int ret = 0;
    if (derive_seed(seed, fsk, sk_len) != 0) {
        ret = -3;
        goto cleanup;
    }

    switch (scheme) {
        case AIGIS_SIG:
            if (pqmagic_aigis_sig3_std_keypair_internal(tpk, tsk, seed) != 0) {
                printf("[ERROR] Error occurred when doing aigis crypto_sign_keypair.\n");
                ret = -2;  // keypair failed
            }
            break;
        case DILITHIUM:
            if (pqmagic_dilithium3_std_keypair_internal(tpk, tsk, seed) != 0) {
                printf("[ERROR] Error occurred when doing dilithium crypto_sign_keypair.\n");
                ret = -2;  // keypair failed
            }
            break;
        case ML_DSA:
            if (pqmagic_ml_dsa_65_std_keypair_internal(tpk, tsk, seed) != 0) {
                printf("[ERROR] Error occurred when doing mldsa crypto_sign_keypair.\n");
                ret = -2;  // keypair failed
            }
            break;
        case SLH_DSA:
            if (pqmagic_slh_dsa_shake_192f_simple_std_sign_seed_keypair(tpk, tsk, seed) != 0) {
                printf("[ERROR] Error occurred when doing slh_dsa crypto_sign_keypair.\n");
                ret = -2;  // keypair failed
            }
            break;
        default:
            ret = -1;
            break;
    }

    if (ret == 0) {
        if (memcmp(tsk, bsk, sk_len) == 0 && memcmp(tpk, bpk, pk_len) == 0) {
            ret = 0;
        } else {
            ret = 1;
        }
    }

    #ifdef DEBUG
    print_hex("Seed", seed, MAX_SEED_LEN);
    print_hex("Generated Public Key", tpk, public_key_bytes[scheme]);
    print_hex("Generated Secret Key", tsk, secret_key_bytes[scheme]);
    print_hex("Provided Public Key", bpk, public_key_bytes[scheme]);
    print_hex("Provided Secret Key", bsk, secret_key_bytes[scheme]);
    #endif

cleanup:
    free(tpk);
    free(tsk);
    free(seed);
    return ret;
}

