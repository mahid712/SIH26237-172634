#ifndef KEYRING_H
#define KEYRING_H

#include "pqc_kem.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char user_id[64];
    uint8_t public_key[ML_KEM_768_PUBLIC_KEY_BYTES];
    uint8_t sealed_secret_key[ML_KEM_768_SECRET_KEY_BYTES + 32]; /* Encrypted with TPM / Passphrase */
    size_t sealed_len;
    uint8_t tpm_pcr_seal_digest[32];
    int is_tpm_sealed;
} user_key_entry_t;

/* Keyring operations */
int keyring_generate_user(const char *user_id, const char *passphrase, user_key_entry_t *out_entry);
int keyring_save_json(const user_key_entry_t *entry, const char *filepath);
int keyring_load_json(const char *filepath, user_key_entry_t *entry);

/* TPM Sealing & Unsealing */
int keyring_unseal_secret_key(const user_key_entry_t *entry, const char *passphrase, uint8_t sk_out[ML_KEM_768_SECRET_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* KEYRING_H */
