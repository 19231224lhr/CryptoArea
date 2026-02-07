#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "pqcsign_wrapper.h"
#include "pqmagic/utils/randombytes.h"

#define TEST_MLEN 32
#define SHORT_MLEN 1

static int run_scheme(SignAlgType scheme,
                      size_t pk_len,
                      size_t sk_len,
                      size_t sig_len) {
    int failures = 0;
    uint8_t *message = malloc(TEST_MLEN);
    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t *sig = malloc(sig_len);
    uint8_t *tpk = malloc(pk_len);
    uint8_t *tsk = malloc(sk_len);

    if (message == NULL || pk == NULL || sk == NULL || sig == NULL || tpk == NULL || tsk == NULL) {
        printf("[ERROR] allocation failed for scheme %d\n", scheme);
        failures++;
        goto cleanup;
    }

    randombytes(message, TEST_MLEN);

    printf("Testing keyGen with scheme %d\n", scheme);
    if (keyGen(scheme, pk, sk) != 0) {
        printf("[ERROR] keyGen failed for scheme %d\n", scheme);
        failures++;
        goto cleanup;
    }

    printf("Testing keyGenWithSeed with scheme %d\n", scheme);
    if (keyGenWithSeed(scheme, tpk, tsk, pk, pk_len) != 0) {
        printf("[ERROR] keyGenWithSeed failed for scheme %d\n", scheme);
        failures++;
        goto cleanup;
    }

    printf("Testing sign/verify with scheme %d\n", scheme);
    size_t out_sig_len = 0;
    if (sign(scheme, sig, &out_sig_len, message, TEST_MLEN, sk) != 0) {
        printf("[ERROR] sign failed for scheme %d\n", scheme);
        failures++;
        goto cleanup;
    }
    if (verify(scheme, sig, out_sig_len, message, TEST_MLEN, pk) != 0) {
        printf("[ERROR] verify failed for scheme %d\n", scheme);
        failures++;
        goto cleanup;
    }

    printf("Testing VerifyKeyGen with scheme %d\n", scheme);
    if (VerifyKeyGen(scheme, sk, tsk, tpk) != 0) {
        printf("[ERROR] VerifyKeyGen failed for scheme %d\n", scheme);
        failures++;
        goto cleanup;
    }

    if (scheme == ML_DSA) {
        printf("Testing ML-DSA short message sign/verify\n");
        uint8_t short_message[SHORT_MLEN] = {0x42};
        out_sig_len = 0;
        if (sign(scheme, sig, &out_sig_len, short_message, SHORT_MLEN, sk) != 0) {
            printf("[ERROR] ML-DSA short message sign failed\n");
            failures++;
            goto cleanup;
        }
        if (verify(scheme, sig, out_sig_len, short_message, SHORT_MLEN, pk) != 0) {
            printf("[ERROR] ML-DSA short message verify failed\n");
            failures++;
            goto cleanup;
        }
    }

cleanup:
    free(message);
    free(pk);
    free(sk);
    free(sig);
    free(tpk);
    free(tsk);
    return failures;
}

int main(void) {
    SignAlgType schemes[4] = {AIGIS_SIG, DILITHIUM, ML_DSA, SLH_DSA};
    size_t public_key_bytes[4] = {
        AIGIS_SIG3_PUBLICKEYBYTES,
        DILITHIUM3_PUBLICKEYBYTES,
        ML_DSA_65_PUBLICKEYBYTES,
        SLH_DSA_SHAKE_192f_PUBLICKEYBYTES};
    size_t secret_key_bytes[4] = {
        AIGIS_SIG3_SECRETKEYBYTES,
        DILITHIUM3_SECRETKEYBYTES,
        ML_DSA_65_SECRETKEYBYTES,
        SLH_DSA_SHAKE_192f_SECRETKEYBYTES};
    size_t signature_bytes[4] = {
        AIGIS_SIG3_SIGBYTES,
        DILITHIUM3_SIGBYTES,
        ML_DSA_65_SIGBYTES,
        SLH_DSA_SHAKE_192f_SIGBYTES};

    int failures = 0;
    for (int i = 0; i < 4; i++) {
        failures += run_scheme(
            schemes[i],
            public_key_bytes[i],
            secret_key_bytes[i],
            signature_bytes[i]);
    }

    if (failures != 0) {
        printf("[ERROR] wrapper regression tests failed: %d\n", failures);
        return 1;
    }

    printf("All wrapper regression tests passed.\n");
    return 0;
}
