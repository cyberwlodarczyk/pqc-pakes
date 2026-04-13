#include "tempo.h"

PQC_PAKE_TEMPO_a *PQC_PAKE_TEMPO_a_new(
    const char *alg,
    const char *pw,
    uint64_t sid,
    uint64_t a,
    uint64_t b)
{
    return NULL;
}

int PQC_PAKE_TEMPO_a_keygen(PQC_PAKE_TEMPO_a *tempo, uint8_t **apk)
{
    return 0;
}

int PQC_PAKE_TEMPO_a_decaps(
    PQC_PAKE_TEMPO_a *tempo,
    uint8_t **ciphertext,
    uint8_t **tag)
{
    return 0;
}

void PQC_PAKE_TEMPO_a_free(PQC_PAKE_TEMPO_a *tempo)
{
}

PQC_PAKE_TEMPO_b *PQC_PAKE_TEMPO_b_new(
    const char *alg,
    const char *pw,
    uint64_t sid,
    uint64_t a,
    uint64_t b)
{
    return NULL;
}

int PQC_PAKE_TEMPO_b_encaps(PQC_PAKE_TEMPO_b *tempo, uint8_t *apk)
{
    return 0;
}

void PQC_PAKE_TEMPO_b_free(PQC_PAKE_TEMPO_b *tempo)
{
}

void PQC_PAKE_TEMPO_re_a_keygen()
{
}

void PQC_PAKE_TEMPO_re_a_decaps()
{
}

void PQC_PAKE_TEMPO_re_b_encaps()
{
}
