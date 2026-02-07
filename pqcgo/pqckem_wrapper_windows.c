#include "pqckem_wrapper.h"

#define KEM_SCHEME_COUNT 7

static int is_valid_kem_scheme(int scheme) {
    return scheme >= 0 && scheme < KEM_SCHEME_COUNT;
}

int kemKeyGen(int scheme, uint8_t *pk, uint8_t *sk) {
    if (!is_valid_kem_scheme(scheme)) {
        return -1;
    }
    if (pk == NULL || sk == NULL) {
        return -3;
    }

    switch (scheme) {
        case ML_KEM_512:
            return pqmagic_ml_kem_512_std_keypair(pk, sk);
        case ML_KEM_768:
            return pqmagic_ml_kem_768_std_keypair(pk, sk);
        case ML_KEM_1024:
            return pqmagic_ml_kem_1024_std_keypair(pk, sk);
        case AIGIS_ENC_1:
            return pqmagic_aigis_enc_1_std_keypair(pk, sk);
        case AIGIS_ENC_2:
            return pqmagic_aigis_enc_2_std_keypair(pk, sk);
        case AIGIS_ENC_3:
            return pqmagic_aigis_enc_3_std_keypair(pk, sk);
        case AIGIS_ENC_4:
            return pqmagic_aigis_enc_4_std_keypair(pk, sk);
        default:
            return -1;
    }
}

int kemEncaps(int scheme, uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    if (!is_valid_kem_scheme(scheme)) {
        return -1;
    }
    if (ct == NULL || ss == NULL || pk == NULL) {
        return -3;
    }

    switch (scheme) {
        case ML_KEM_512:
            return pqmagic_ml_kem_512_std_enc(ct, ss, pk);
        case ML_KEM_768:
            return pqmagic_ml_kem_768_std_enc(ct, ss, pk);
        case ML_KEM_1024:
            return pqmagic_ml_kem_1024_std_enc(ct, ss, pk);
        case AIGIS_ENC_1:
            return pqmagic_aigis_enc_1_std_enc(ct, ss, pk);
        case AIGIS_ENC_2:
            return pqmagic_aigis_enc_2_std_enc(ct, ss, pk);
        case AIGIS_ENC_3:
            return pqmagic_aigis_enc_3_std_enc(ct, ss, pk);
        case AIGIS_ENC_4:
            return pqmagic_aigis_enc_4_std_enc(ct, ss, pk);
        default:
            return -1;
    }
}

int kemDecaps(int scheme, uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    if (!is_valid_kem_scheme(scheme)) {
        return -1;
    }
    if (ss == NULL || ct == NULL || sk == NULL) {
        return -3;
    }

    switch (scheme) {
        case ML_KEM_512:
            return pqmagic_ml_kem_512_std_dec(ss, ct, sk);
        case ML_KEM_768:
            return pqmagic_ml_kem_768_std_dec(ss, ct, sk);
        case ML_KEM_1024:
            return pqmagic_ml_kem_1024_std_dec(ss, ct, sk);
        case AIGIS_ENC_1:
            return pqmagic_aigis_enc_1_std_dec(ss, ct, sk);
        case AIGIS_ENC_2:
            return pqmagic_aigis_enc_2_std_dec(ss, ct, sk);
        case AIGIS_ENC_3:
            return pqmagic_aigis_enc_3_std_dec(ss, ct, sk);
        case AIGIS_ENC_4:
            return pqmagic_aigis_enc_4_std_dec(ss, ct, sk);
        default:
            return -1;
    }
}
