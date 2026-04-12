#ifndef PQC_PAKE_NICE_H
#define PQC_PAKE_NICE_H

#include "kem.h"

typedef struct
{
    PQC_PAKE_KEM *kem;
    uint8_t *password;
    uint8_t *secret_key;
} PQC_PAKE_NICE;

PQC_PAKE_NICE *PQC_PAKE_NICE_new(const char *alg, const char *pw);

int PQC_PAKE_NICE_a1(PQC_PAKE_NICE *nice, uint8_t **seed, uint8_t **poly);

int PQC_PAKE_NICE_b1(
    PQC_PAKE_NICE *nice,
    uint8_t **ciphertext,
    uint8_t **shared_secret,
    const uint8_t *seed,
    const uint8_t *poly);

int PQC_PAKE_NICE_a2(
    const PQC_PAKE_NICE *nice,
    uint8_t **shared_secret,
    const uint8_t *ciphertext);

void PQC_PAKE_NICE_free(PQC_PAKE_NICE *nice);

void PQC_PAKE_NICE_re_a1();

void PQC_PAKE_NICE_re_b1();

void PQC_PAKE_NICE_re_a2();

#endif
