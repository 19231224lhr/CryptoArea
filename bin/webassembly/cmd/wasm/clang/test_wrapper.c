#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pqcsign_wrapper.h"
#include "libs/include/pqmagic_api.h"
#include "pqmagic/utils/randombytes.h"

#define MLEN 32

int main() {

    SignAlgType schemes[4] = {AIGIS_SIG, DILITHIUM, ML_DSA, SLH_DSA};

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

    // TODO aigis verify failure

    for (int i = 0; i < 4; i++) {
        char *message[MLEN] ;
        randombytes(message,MLEN);
        size_t mlen = strlen(message);
        uint8_t *pk = malloc(public_key_bytes[i]);
        uint8_t *sk = malloc(secret_key_bytes[i]);
        uint8_t *sig = malloc(signature_bytes[i]);

        uint8_t *tpk = malloc(public_key_bytes[i]);
        uint8_t *tsk = malloc(secret_key_bytes[i]);

        size_t siglen;
        int ret = 0;

        // Key generation
        ret = keyGen(schemes[i], pk, sk);
        if (ret != 0) {
            printf("Key generation failed for scheme %d, error code: %d \n", schemes[i], ret);
            free(pk);
            free(sk);
            free(sig);
            continue;
        }
        printf("PUBLICKEYBYTES = %zu\n", public_key_bytes[i]);
        printf("SECRETKEYBYTES = %zu\n", secret_key_bytes[i]);
        printf("BYTES = %zu\n", signature_bytes[i]);

        // Key generation with seed
        ret = keyGenWithSeed(schemes[i], tpk, tsk, sk);
        if (ret  != 0) {
            printf("Key generation with seed failed for scheme %d, error code: %d\n", schemes[i],ret);
            free(pk);
            free(sk);
            free(sig);
            continue;
        }

        // Signing
        ret = sign(schemes[i], sig, &siglen, (const uint8_t *) message, mlen, sk);
        if (ret != 0) {
            printf("Signing failed for scheme %d, error code: %d\n", schemes[i], ret);
            free(pk);
            free(sk);
            free(sig);
            continue;
        }

        // Verification
        ret = verify(schemes[i], sig, siglen, (const uint8_t *) message, mlen, pk);
        if (ret != 0) {
            printf("Verification failed for scheme %d, error code: %d\n", schemes[i], ret);
        } else {
            printf("Verification succeeded for scheme %d\n", schemes[i]);
        }

        // Verify key generation
        ret = VerifyKeyGen(schemes[i], sk, tsk, tpk);
        if (ret == 0) {
            printf("VerifyKeyGen succeeded for scheme %d\n", schemes[i]);
        } else if (ret == 1) {
            printf("VerifyKeyGen failed for scheme %d: keys do not match\n", schemes[i]);
        } else {
            printf("VerifyKeyGen failed for scheme %d, error code: %d\n", schemes[i], ret);
        }

        free(pk);
        free(tpk);
        free(sk);
        free(tsk);
        free(sig);
    }

    return 0;
}
