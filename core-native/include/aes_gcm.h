#ifndef AES_GCM_H
#define AES_GCM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_256_KEY_SIZE 32
#define AES_GCM_IV_SIZE  12
#define AES_GCM_TAG_SIZE 16

/* Standard AES-256 Key Schedule */
typedef struct {
    uint32_t round_keys[60];
} aes256_ctx_t;

void aes256_init_key(aes256_ctx_t *ctx, const uint8_t key[AES_256_KEY_SIZE]);

/* Authenticated Encryption with Associated Data (AEAD) */
int aes256_gcm_encrypt(const uint8_t key[AES_256_KEY_SIZE],
                      const uint8_t iv[AES_GCM_IV_SIZE],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *ciphertext,
                      uint8_t tag[AES_GCM_TAG_SIZE]);

/* Authenticated Decryption with Associated Data (AEAD) */
int aes256_gcm_decrypt(const uint8_t key[AES_256_KEY_SIZE],
                      const uint8_t iv[AES_GCM_IV_SIZE],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      const uint8_t tag[AES_GCM_TAG_SIZE],
                      uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* AES_GCM_H */
