#ifndef PQC_PAKE_KEM_H
#define PQC_PAKE_KEM_H

#include <oqs/kem.h>

#define PQC_PAKE_KEM_alg_kyber_512 "kyber-512"
#define PQC_PAKE_KEM_alg_kyber_768 "kyber-768"
#define PQC_PAKE_KEM_alg_kyber_1024 "kyber-1024"

typedef struct
{
    OQS_KEM *oqs_kem;
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *public_seed;
    uint8_t *public_poly;
    uint8_t *shared_secret;
    size_t len_public_key;
    size_t len_public_seed;
    size_t len_public_poly;
    size_t len_secret_key;
    size_t len_ciphertext;
    size_t len_shared_secret;
} PQC_PAKE_KEM_a;

PQC_PAKE_KEM_a *PQC_PAKE_KEM_a_new(const char *alg);

int PQC_PAKE_KEM_a_keygen(
    PQC_PAKE_KEM_a *kem,
    uint8_t **public_key,
    uint8_t **secret_key);

int PQC_PAKE_KEM_a_split(
    PQC_PAKE_KEM_a *kem,
    uint8_t **seed,
    uint8_t **poly,
    const uint8_t *public_key);

int PQC_PAKE_KEM_a_decaps(
    PQC_PAKE_KEM_a *kem,
    uint8_t **shared_secret,
    const uint8_t *ciphertext);

void PQC_PAKE_KEM_a_free(PQC_PAKE_KEM_a *kem);

typedef struct
{
    OQS_KEM *oqs_kem;
    uint8_t *public_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
    size_t len_public_key;
    size_t len_public_seed;
    size_t len_public_poly;
    size_t len_secret_key;
    size_t len_ciphertext;
    size_t len_shared_secret;
} PQC_PAKE_KEM_b;

PQC_PAKE_KEM_b *PQC_PAKE_KEM_b_new(const char *alg);

int PQC_PAKE_KEM_b_join(
    PQC_PAKE_KEM_b *kem,
    uint8_t **public_key,
    const uint8_t *seed,
    const uint8_t *poly);

int PQC_PAKE_KEM_b_encaps(
    PQC_PAKE_KEM_b *kem,
    uint8_t **ciphertext,
    uint8_t **shared_secret,
    const uint8_t *public_key);

void PQC_PAKE_KEM_b_free(PQC_PAKE_KEM_b *kem);

#endif
