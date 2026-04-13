#ifndef PQC_PAKE_TEMPO_H
#define PQC_PAKE_TEMPO_H

#include "kem.h"

typedef struct
{
    PQC_PAKE_KEM_a *kem;
    uint8_t *fsid;
    uint8_t *fpkey;
    uint8_t *password;
} PQC_PAKE_TEMPO_a;

PQC_PAKE_TEMPO_a *PQC_PAKE_TEMPO_a_new(
    const char *alg,
    const char *pw,
    uint64_t sid,
    uint64_t a,
    uint64_t b);

int PQC_PAKE_TEMPO_a_keygen(PQC_PAKE_TEMPO_a *tempo, uint8_t **apk);

int PQC_PAKE_TEMPO_a_decaps(
    PQC_PAKE_TEMPO_a *tempo,
    uint8_t **ciphertext,
    uint8_t **tag);

void PQC_PAKE_TEMPO_a_free(PQC_PAKE_TEMPO_a *tempo);

typedef struct
{
    PQC_PAKE_KEM_b *kem;
    uint8_t *fsid;
    uint8_t *fpkey;
    uint8_t *password;
} PQC_PAKE_TEMPO_b;

PQC_PAKE_TEMPO_b *PQC_PAKE_TEMPO_b_new(
    const char *alg,
    const char *pw,
    uint64_t sid,
    uint64_t a,
    uint64_t b);

int PQC_PAKE_TEMPO_b_encaps(PQC_PAKE_TEMPO_b *tempo, uint8_t *apk);

void PQC_PAKE_TEMPO_b_free(PQC_PAKE_TEMPO_b *tempo);

void PQC_PAKE_TEMPO_re_a_keygen();

void PQC_PAKE_TEMPO_re_a_decaps();

void PQC_PAKE_TEMPO_re_b_encaps();

#endif
