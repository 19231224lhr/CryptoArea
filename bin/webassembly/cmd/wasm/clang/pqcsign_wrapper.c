#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "pqcsign_wrapper.h"
#include <string.h>
#include "./pqmagic/utils/randombytes.h"
#include "fips202.h"

size_t public_key_bytes[4] = {
    AIGIS_SIG3_PUBLICKEYBYTES, DILITHIUM3_PUBLICKEYBYTES, ML_DSA_65_PUBLICKEYBYTES,
    SLH_DSA_SHAKE_192f_PUBLICKEYBYTES
};
size_t secret_key_bytes[4] = {
    AIGIS_SIG3_SECRETKEYBYTES, DILITHIUM3_SECRETKEYBYTES, ML_DSA_65_SECRETKEYBYTES,
    SLH_DSA_SHAKE_192f_SECRETKEYBYTES
};
size_t signature_bytes[4] = {
    AIGIS_SIG3_SIGBYTES, DILITHIUM3_SIGBYTES, ML_DSA_65_SIGBYTES, SLH_DSA_SHAKE_192f_SIGBYTES
};

int keyGen(SignAlgType scheme, uint8_t *pk, uint8_t *sk) {
    switch (scheme) {
        case AIGIS_SIG:
            return pqmagic_aigis_sig3_std_keypair(pk, sk);
        case DILITHIUM:
            return pqmagic_dilithium3_std_keypair(pk, sk);
        case ML_DSA:
            return pqmagic_ml_dsa_65_std_keypair(pk, sk);
        case SLH_DSA:
            return pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(pk, sk);
        default:
            return -1;
    }
}

int keyGenWithSeed(SignAlgType scheme, uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    uint8_t *seedhash = malloc(32);
    uint8_t ret = 0;
    sha3_256(seedhash,seed,secret_key_bytes[scheme]);
    switch (scheme) {
        case AIGIS_SIG:
            ret = pqmagic_aigis_sig3_std_keypair_internal(pk, sk,seedhash);
            break;
        case DILITHIUM:
            ret =  pqmagic_dilithium3_std_keypair_internal(pk, sk,seedhash);
            break;
        case ML_DSA:
            ret =  pqmagic_ml_dsa_65_std_keypair_internal(pk, sk, seedhash);
            break;
        case SLH_DSA:
            ret = pqmagic_slh_dsa_shake_192f_simple_std_sign_seed_keypair(pk, sk,seedhash);
            break;
        default:
            ret =  -1;
            break;
    }
    free(seedhash);
    return ret;
}

int sign(SignAlgType scheme, uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    uint8_t *ctx = malloc(mlen);
    randombytes(ctx,mlen);
    int ret = 0;
    switch (scheme) {
        case AIGIS_SIG:
            ret =  pqmagic_aigis_sig3_std_signature(sig, siglen, m, mlen, sk);
            break;
        case DILITHIUM:
            ret =  pqmagic_dilithium3_std_signature(sig, siglen, m, mlen, sk);
            break;
        case ML_DSA:
             ret =  pqmagic_ml_dsa_65_std_signature_internal(sig, siglen, m, mlen,ctx,sk);
            break;
        case SLH_DSA:
            ret =  pqmagic_slh_dsa_shake_192f_simple_std_sign_signature(sig, siglen, m, mlen, sk);
            break;
        default:
            ret = -1 ;
            break;
    }
    free(ctx);
    return ret;
}

int verify(SignAlgType scheme, const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    uint8_t *ctx = malloc(mlen);
    randombytes(ctx,mlen);
    int ret = 0;
    switch (scheme) {
        case AIGIS_SIG:
            ret =  pqmagic_aigis_sig3_std_verify(sig, siglen, m, mlen, pk);
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
    free(ctx);
    return ret;
}

// return 0 if verify success  or return 1 when failed, otherwise return error code (neg number).
int VerifyKeyGen(SignAlgType scheme, const uint8_t *fsk, const uint8_t *bsk, const uint8_t *bpk) {
    uint8_t *tpk = malloc(public_key_bytes[scheme]);
    uint8_t *tsk = malloc(secret_key_bytes[scheme]);
    uint8_t *seed = malloc(32);
    int ret = 0;
    sha3_256(seed,fsk,secret_key_bytes[scheme]);
    switch (scheme) {
        case AIGIS_SIG:
            if (pqmagic_aigis_sig3_std_keypair_internal(tpk,tsk,seed) != 0) {
                printf("[ERROR] Error occured when doing aigis crypto_sign_keypair.\n");
                ret = -2;  // keypair failed
            }
           break;
        case DILITHIUM:
            if (pqmagic_dilithium3_std_keypair_internal(tpk,tsk,seed) != 0) {
                printf("[ERROR] Error occured when doing  dilithium crypto_sign_keypair.\n");
                ret =  -2;  // keypair failed
            }
            break;
        case ML_DSA:
            if (pqmagic_ml_dsa_65_std_keypair_internal(tpk,tsk,seed) != 0) {
                printf("[ERROR] Error occured when doing  mldsa crypto_sign_keypair.\n");
                ret =  -2;  // keypair failed
            }
            break;
        case SLH_DSA:
            if (pqmagic_slh_dsa_shake_192f_simple_std_sign_seed_keypair(tpk,tsk,seed) != 0) {
                printf("[ERROR] Error occured when doing  slh_dsa crypto_sign_keypair.\n");
                ret = -2;  // keypair failed
            }
         break;
        default:
            ret = -1;
        break;
    }
    // 判断tsk是否等于bsk 且 tpk是否等于bpk
    if (memcmp(tsk,bsk,secret_key_bytes[scheme]) == 0 && memcmp(tpk,bpk,public_key_bytes[scheme]) == 0) {
        ret = 0;
    } else {
        ret = 1;
    }
    free(tpk);
    free(tsk);
    free(seed);
    return ret;
}