#ifndef PQC_PAKE_KEM_H
#define PQC_PAKE_KEM_H

#define PQC_PAKE_KEM_len_public_key 1184
#define PQC_PAKE_KEM_len_public_seed 32
#define PQC_PAKE_KEM_len_public_poly 1152
#define PQC_PAKE_KEM_len_secret_key 2400
#define PQC_PAKE_KEM_len_ciphertext 1088
#define PQC_PAKE_KEM_len_shared_secret 32

typedef struct
{
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *public_seed;
    uint8_t *public_poly;
    uint8_t *shared_secret;
} PQC_PAKE_KEM_a;

PQC_PAKE_KEM_a *PQC_PAKE_KEM_a_new();

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
    uint8_t *public_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
} PQC_PAKE_KEM_b;

PQC_PAKE_KEM_b *PQC_PAKE_KEM_b_new();

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
