#include "keyring.h"
#include "aes_gcm.h"
#include "hkdf.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Hex helpers */
static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int val;
        if (sscanf(hex + i * 2, "%02x", &val) != 1) return -1;
        out[i] = (uint8_t)val;
    }
    return 0;
}

int keyring_generate_user(const char *user_id, const char *passphrase, user_key_entry_t *out_entry) {
    memset(out_entry, 0, sizeof(user_key_entry_t));
    strncpy(out_entry->user_id, user_id, sizeof(out_entry->user_id) - 1);

    ml_kem_keypair_t kp;
    if (ml_kem_768_keygen(&kp) != 0) return -1;

    memcpy(out_entry->public_key, kp.pk, ML_KEM_768_PUBLIC_KEY_BYTES);

    /* Simulate TPM PCR state (Platform Configuration Register 0-7 hash) */
    static const char pcr_sim_state[] = "TPM_PCR_PLATFORM_STATE_TRUSTED_BOOT_SECURE_ENCLAVE_2026";
    sha256_hash((const uint8_t*)pcr_sim_state, strlen(pcr_sim_state), out_entry->tpm_pcr_seal_digest);
    out_entry->is_tpm_sealed = 1;

    /* Derive master wrapping key from (passphrase + TPM PCR state) */
    uint8_t wrap_key[32];
    hkdf_sha256(out_entry->tpm_pcr_seal_digest, 32,
                (const uint8_t*)passphrase, strlen(passphrase),
                (const uint8_t*)"TPM_SEALED_KEYRING_WRAPPER", 26,
                wrap_key, 32);

    /* Encrypt secret key with AES-256-GCM */
    uint8_t iv[12] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0};
    uint8_t tag[16];
    aes256_gcm_encrypt(wrap_key, iv, (const uint8_t*)user_id, strlen(user_id),
                      kp.sk, ML_KEM_768_SECRET_KEY_BYTES,
                      out_entry->sealed_secret_key, tag);

    memcpy(out_entry->sealed_secret_key + ML_KEM_768_SECRET_KEY_BYTES, tag, 16);
    out_entry->sealed_len = ML_KEM_768_SECRET_KEY_BYTES + 16;

    return 0;
}

int keyring_unseal_secret_key(const user_key_entry_t *entry, const char *passphrase, uint8_t sk_out[ML_KEM_768_SECRET_KEY_BYTES]) {
    uint8_t wrap_key[32];
    hkdf_sha256(entry->tpm_pcr_seal_digest, 32,
                (const uint8_t*)passphrase, strlen(passphrase),
                (const uint8_t*)"TPM_SEALED_KEYRING_WRAPPER", 26,
                wrap_key, 32);

    uint8_t iv[12] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0};
    const uint8_t *tag = entry->sealed_secret_key + ML_KEM_768_SECRET_KEY_BYTES;

    if (aes256_gcm_decrypt(wrap_key, iv, (const uint8_t*)entry->user_id, strlen(entry->user_id),
                          entry->sealed_secret_key, ML_KEM_768_SECRET_KEY_BYTES,
                          tag, sk_out) != 0) {
        return -1; /* Authentication failure or wrong passphrase / PCR mismatch */
    }
    return 0;
}

int keyring_save_json(const user_key_entry_t *entry, const char *filepath) {
    FILE *f = fopen(filepath, "w");
    if (!f) return -1;

    char *pk_hex = (char*)malloc(ML_KEM_768_PUBLIC_KEY_BYTES * 2 + 1);
    char *sk_hex = (char*)malloc(entry->sealed_len * 2 + 1);
    char pcr_hex[65];

    bytes_to_hex(entry->public_key, ML_KEM_768_PUBLIC_KEY_BYTES, pk_hex);
    bytes_to_hex(entry->sealed_secret_key, entry->sealed_len, sk_hex);
    bytes_to_hex(entry->tpm_pcr_seal_digest, 32, pcr_hex);

    fprintf(f, "{\n");
    fprintf(f, "  \"user_id\": \"%s\",\n", entry->user_id);
    fprintf(f, "  \"is_tpm_sealed\": %s,\n", entry->is_tpm_sealed ? "true" : "false");
    fprintf(f, "  \"tpm_pcr_digest\": \"%s\",\n", pcr_hex);
    fprintf(f, "  \"public_key_kem_768\": \"%s\",\n", pk_hex);
    fprintf(f, "  \"sealed_secret_key_aes_gcm\": \"%s\"\n", sk_hex);
    fprintf(f, "}\n");

    free(pk_hex);
    free(sk_hex);
    fclose(f);
    return 0;
}

int keyring_load_json(const char *filepath, user_key_entry_t *entry) {
    FILE *f = fopen(filepath, "r");
    if (!f) return -1;

    memset(entry, 0, sizeof(user_key_entry_t));

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "\"user_id\":")) {
            sscanf(line, " \"user_id\": \"%63[^\"]\"", entry->user_id);
        } else if (strstr(line, "\"tpm_pcr_digest\":")) {
            char hex[65] = {0};
            if (sscanf(line, " \"tpm_pcr_digest\": \"%64[^\"]\"", hex) == 1) {
                hex_to_bytes(hex, entry->tpm_pcr_seal_digest, 32);
                entry->is_tpm_sealed = 1;
            }
        } else if (strstr(line, "\"public_key_kem_768\":")) {
            char *start = strstr(line, "\": \"");
            if (start) {
                start += 4;
                char *end = strchr(start, '\"');
                if (end) *end = '\0';
                hex_to_bytes(start, entry->public_key, ML_KEM_768_PUBLIC_KEY_BYTES);
            }
        } else if (strstr(line, "\"sealed_secret_key_aes_gcm\":")) {
            char *start = strstr(line, "\": \"");
            if (start) {
                start += 4;
                char *end = strchr(start, '\"');
                if (end) *end = '\0';
                size_t len = strlen(start) / 2;
                entry->sealed_len = len;
                hex_to_bytes(start, entry->sealed_secret_key, len);
            }
        }
    }

    fclose(f);
    return 0;
}
