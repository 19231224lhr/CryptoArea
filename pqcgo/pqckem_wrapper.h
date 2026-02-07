#ifndef PQC_KEM_WRAPPER_H
#define PQC_KEM_WRAPPER_H

#include <stddef.h>
#include <stdint.h>
#include "./libs/include/pqmagic_api.h"

typedef enum {
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
    AIGIS_ENC_1,
    AIGIS_ENC_2,
    AIGIS_ENC_3,
    AIGIS_ENC_4
} KEMAlgType;

int kemKeyGen(int scheme, uint8_t *pk, uint8_t *sk);
int kemEncaps(int scheme, uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int kemDecaps(int scheme, uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif // PQC_KEM_WRAPPER_H
