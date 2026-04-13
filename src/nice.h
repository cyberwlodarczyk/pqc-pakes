#ifndef PQC_PAKE_NICE_H
#define PQC_PAKE_NICE_H

#include "kem.h"

typedef struct
{
    PQC_PAKE_KEM_a *kem;
    uint8_t *password;
    size_t len_password;
} PQC_PAKE_NICE_a;

PQC_PAKE_NICE_a *PQC_PAKE_NICE_a_new(const char *alg, const char *pw);

int PQC_PAKE_NICE_a_keygen(
    PQC_PAKE_NICE_a *nice,
    uint8_t **seed,
    uint8_t **poly);

int PQC_PAKE_NICE_a_decaps(
    PQC_PAKE_NICE_a *nice,
    uint8_t **shared_secret,
    const uint8_t *ciphertext);

void PQC_PAKE_NICE_a_free(PQC_PAKE_NICE_a *nice);

typedef struct
{
    PQC_PAKE_KEM_b *kem;
    uint8_t *password;
    size_t len_password;
} PQC_PAKE_NICE_b;

PQC_PAKE_NICE_b *PQC_PAKE_NICE_b_new(const char *alg, const char *pw);

int PQC_PAKE_NICE_b_encaps(
    PQC_PAKE_NICE_b *nice,
    uint8_t **ciphertext,
    uint8_t **shared_secret,
    const uint8_t *seed,
    const uint8_t *poly);

void PQC_PAKE_NICE_b_free(PQC_PAKE_NICE_b *nice);

void PQC_PAKE_NICE_re_a_keygen();

void PQC_PAKE_NICE_re_a_decaps();

void PQC_PAKE_NICE_re_b_encaps();

#endif
