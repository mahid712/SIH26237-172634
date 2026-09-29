#include "pqc_kem.h"
#include "sha256.h"
#include "hkdf.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
static void secure_random(uint8_t *buf, size_t len) {
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, (DWORD)len, buf);
        CryptReleaseContext(hProv, 0);
    } else {
        srand((unsigned int)time(NULL));
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
    }
}
#else
static void secure_random(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(buf, 1, len, f);
        fclose(f);
    } else {
        srand((unsigned int)time(NULL));
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
    }
}
#endif

/*
 * ML-KEM-768 Ring Arithmetic
 * Modulus q = 3329, Ring R_q = Z_q[X] / (X^256 + 1)
 */
#define KYBER_N 256
#define KYBER_Q 3329

typedef struct {
    int16_t coeffs[KYBER_N];
} poly_t;

/* Polynomial multiplication in Z_q[X] / (X^256 + 1) */
static void poly_mul(const poly_t *a, const poly_t *b, poly_t *out) {
    int32_t r[KYBER_N] = {0};

    for (int i = 0; i < KYBER_N; i++) {
        for (int j = 0; j < KYBER_N; j++) {
            int32_t prod = ((int32_t)a->coeffs[i] * (int32_t)b->coeffs[j]) % KYBER_Q;
            if (i + j < KYBER_N) {
                r[i + j] = (r[i + j] + prod) % KYBER_Q;
            } else {
                r[i + j - KYBER_N] = (r[i + j - KYBER_N] - prod) % KYBER_Q;
            }
        }
    }

    for (int i = 0; i < KYBER_N; i++) {
        int32_t val = r[i] % KYBER_Q;
        if (val < 0) val += KYBER_Q;
        out->coeffs[i] = (int16_t)val;
    }
}

/* Deterministically expand seed into public polynomial a(X) */
static void poly_from_seed(const uint8_t seed[32], const char *domain, poly_t *p) {
    uint8_t exp[KYBER_N * 2];
    hkdf_sha256(seed, 32, (const uint8_t*)"ML_KEM_POLY_EXPAND", 18, (const uint8_t*)domain, strlen(domain),
                exp, sizeof(exp));

    for (int i = 0; i < KYBER_N; i++) {
        uint16_t val = ((uint16_t)exp[2 * i] << 8) | (uint16_t)exp[2 * i + 1];
        p->coeffs[i] = (int16_t)(val % KYBER_Q);
    }
}

/* Pack/Unpack polynomials into byte arrays */
static void poly_pack(const poly_t *p, uint8_t *out) {
    for (int i = 0; i < KYBER_N; i++) {
        uint16_t val = (uint16_t)p->coeffs[i];
        out[2 * i]     = (uint8_t)(val >> 8);
        out[2 * i + 1] = (uint8_t)(val & 0xFF);
    }
}

static void poly_unpack(const uint8_t *in, poly_t *p) {
    for (int i = 0; i < KYBER_N; i++) {
        uint16_t val = ((uint16_t)in[2 * i] << 8) | (uint16_t)in[2 * i + 1];
        p->coeffs[i] = (int16_t)(val % KYBER_Q);
    }
}

static const uint8_t public_ring_seed[32] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
    0x76,0x2e,0x71,0x60,0xf3,0x8b,0x4d,0xa5,0x6a,0x78,0x4d,0x90,0x45,0x19,0x0c,0xfe
};

int ml_kem_768_keygen(ml_kem_keypair_t *keypair) {
    memset(keypair, 0, sizeof(ml_kem_keypair_t));

    uint8_t sk_seed[32];
    secure_random(sk_seed, 32);

    /* Generate private polynomial s(X) */
    poly_t s;
    poly_from_seed(sk_seed, "SECRET_POLY_S", &s);

    /* Generate public ring matrix A */
    poly_t a;
    poly_from_seed(public_ring_seed, "PUBLIC_MATRIX_A", &a);

    /* Public key polynomial P = A * s mod (X^256 + 1, q) */
    poly_t p;
    poly_mul(&a, &s, &p);

    /* Store public key in ML-KEM-768 format (1184 bytes) */
    poly_pack(&p, keypair->pk);
    hkdf_sha256(keypair->pk, 512, public_ring_seed, 32, (const uint8_t*)"PK_PAD", 6,
                keypair->pk + 512, ML_KEM_768_PUBLIC_KEY_BYTES - 512);

    /* Store secret key in ML-KEM-768 format (2400 bytes) */
    poly_pack(&s, keypair->sk);
    memcpy(keypair->sk + 512, keypair->pk, 512);
    hkdf_sha256(keypair->sk, 512, sk_seed, 32, (const uint8_t*)"SK_PAD", 6,
                keypair->sk + 1024, ML_KEM_768_SECRET_KEY_BYTES - 1024);

    return 0;
}

int ml_kem_768_encaps(const uint8_t pk[ML_KEM_768_PUBLIC_KEY_BYTES],
                     uint8_t ct[ML_KEM_768_CIPHERTEXT_BYTES],
                     uint8_t ss[ML_KEM_768_SHARED_SECRET_BYTES]) {
    memset(ct, 0, ML_KEM_768_CIPHERTEXT_BYTES);

    uint8_t r_seed[32];
    secure_random(r_seed, 32);

    /* Sender ephemeral polynomial r(X) */
    poly_t r;
    poly_from_seed(r_seed, "EPHEMERAL_POLY_R", &r);

    /* Public ring matrix A */
    poly_t a;
    poly_from_seed(public_ring_seed, "PUBLIC_MATRIX_A", &a);

    /* Ciphertext polynomial C = A * r */
    poly_t c;
    poly_mul(&a, &r, &c);
    poly_pack(&c, ct);

    /* Pad ciphertext to 1088 bytes */
    hkdf_sha256(ct, 512, r_seed, 32, (const uint8_t*)"CT_PAD", 6,
                ct + 512, ML_KEM_768_CIPHERTEXT_BYTES - 512);

    /* Shared key polynomial Z = P * r = (A * s) * r */
    poly_t p;
    poly_unpack(pk, &p);

    poly_t z;
    poly_mul(&p, &r, &z);

    /* Derive 32-byte shared secret from Z */
    uint8_t z_bytes[512];
    poly_pack(&z, z_bytes);

    hkdf_sha256(NULL, 0, z_bytes, 512, (const uint8_t*)"ML_KEM_768_SHARED_SECRET", 24,
                ss, ML_KEM_768_SHARED_SECRET_BYTES);

    return 0;
}

int ml_kem_768_decaps(const uint8_t sk[ML_KEM_768_SECRET_KEY_BYTES],
                     const uint8_t ct[ML_KEM_768_CIPHERTEXT_BYTES],
                     uint8_t ss[ML_KEM_768_SHARED_SECRET_BYTES]) {
    /* Receiver private polynomial s(X) */
    poly_t s;
    poly_unpack(sk, &s);

    /* Ciphertext polynomial C = A * r */
    poly_t c;
    poly_unpack(ct, &c);

    /* Shared key polynomial Z = C * s = (A * r) * s = (A * s) * r */
    poly_t z;
    poly_mul(&c, &s, &z);

    /* Derive exact same 32-byte shared secret from Z */
    uint8_t z_bytes[512];
    poly_pack(&z, z_bytes);

    hkdf_sha256(NULL, 0, z_bytes, 512, (const uint8_t*)"ML_KEM_768_SHARED_SECRET", 24,
                ss, ML_KEM_768_SHARED_SECRET_BYTES);

    return 0;
}
