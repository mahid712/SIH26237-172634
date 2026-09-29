#include "hkdf.h"
#include "sha256.h"
#include <string.h>

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[32]) {
    uint8_t k_pad[64];
    uint8_t tk[32];
    SHA256_CTX ctx;

    if (key_len > 64) {
        sha256_hash(key, key_len, tk);
        key = tk;
        key_len = 32;
    }

    /* Inner pad (ipad = 0x36) */
    memset(k_pad, 0x36, 64);
    for (size_t i = 0; i < key_len; i++) {
        k_pad[i] ^= key[i];
    }
    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, 64);
    sha256_update(&ctx, data, data_len);
    uint8_t inner_hash[32];
    sha256_final(&ctx, inner_hash);

    /* Outer pad (opad = 0x5c) */
    memset(k_pad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) {
        k_pad[i] ^= key[i];
    }
    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, out);
}

void hkdf_extract(const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm, size_t ikm_len,
                  uint8_t prk[32]) {
    static const uint8_t default_salt[32] = {0};
    if (salt == NULL || salt_len == 0) {
        salt = default_salt;
        salt_len = 32;
    }
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int hkdf_expand(const uint8_t prk[32],
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len) {
    if (okm_len > 255 * 32) return -1;

    uint8_t prev[32];
    size_t prev_len = 0;
    size_t generated = 0;
    uint8_t counter = 1;

    while (generated < okm_len) {
        uint8_t step_in[32 + 256 + 1];
        size_t step_in_len = 0;

        if (prev_len > 0) {
            memcpy(step_in, prev, prev_len);
            step_in_len += prev_len;
        }
        if (info && info_len > 0) {
            memcpy(step_in + step_in_len, info, info_len);
            step_in_len += info_len;
        }
        step_in[step_in_len++] = counter;

        hmac_sha256(prk, 32, step_in, step_in_len, prev);
        prev_len = 32;

        size_t to_copy = (okm_len - generated < 32) ? (okm_len - generated) : 32;
        memcpy(okm + generated, prev, to_copy);
        generated += to_copy;
        counter++;
    }

    return 0;
}

int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len) {
    uint8_t prk[32];
    hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    return hkdf_expand(prk, info, info_len, okm, okm_len);
}
