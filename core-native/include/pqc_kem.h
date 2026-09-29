#ifndef PQC_KEM_H
#define PQC_KEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ML-KEM-768 (FIPS 203) Parameter Sizes */
#define ML_KEM_768_PUBLIC_KEY_BYTES   1184
#define ML_KEM_768_CIPHERTEXT_BYTES   1088
#define ML_KEM_768_SHARED_SECRET_BYTES 32
#define ML_KEM_768_SECRET_KEY_BYTES   2400

typedef struct {
    uint8_t pk[ML_KEM_768_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_KEM_768_SECRET_KEY_BYTES];
} ml_kem_keypair_t;

/* Key generation */
int ml_kem_768_keygen(ml_kem_keypair_t *keypair);

/* Encapsulation: uses public key, produces ciphertext + shared secret */
int ml_kem_768_encaps(const uint8_t pk[ML_KEM_768_PUBLIC_KEY_BYTES],
                     uint8_t ct[ML_KEM_768_CIPHERTEXT_BYTES],
                     uint8_t ss[ML_KEM_768_SHARED_SECRET_BYTES]);

/* Decapsulation: uses secret key + ciphertext, produces shared secret */
int ml_kem_768_decaps(const uint8_t sk[ML_KEM_768_SECRET_KEY_BYTES],
                     const uint8_t ct[ML_KEM_768_CIPHERTEXT_BYTES],
                     uint8_t ss[ML_KEM_768_SHARED_SECRET_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* PQC_KEM_H */
