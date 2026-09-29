#ifndef HKDF_H
#define HKDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 5869 HMAC-SHA256 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[32]);

/* HKDF-Extract */
void hkdf_extract(const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm, size_t ikm_len,
                  uint8_t prk[32]);

/* HKDF-Expand */
int hkdf_expand(const uint8_t prk[32],
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len);

/* Combined HKDF Extract-and-Expand */
int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* HKDF_H */
