#include <string.h>
#include <oqs/oqs.h>
#include <oqs/kem.h>
#include "kem.h"

#define LEN_PUBLIC_SEED 32

const char *to_oqs_alg(const char *alg)
{
    const char *oqs_alg = NULL;
    if (strcmp(alg, PQC_PAKE_KEM_alg_kyber_512) == 0)
    {
        oqs_alg = OQS_KEM_alg_ml_kem_512;
    }
    else if (strcmp(alg, PQC_PAKE_KEM_alg_kyber_768) == 0)
    {
        oqs_alg = OQS_KEM_alg_ml_kem_768;
    }
    else if (strcmp(alg, PQC_PAKE_KEM_alg_kyber_1024) == 0)
    {
        oqs_alg = OQS_KEM_alg_ml_kem_1024;
    }
    else
    {
        return NULL;
    }
}

PQC_PAKE_KEM_a *PQC_PAKE_KEM_a_new(const char *alg)
{
    const char *oqs_alg = to_oqs_alg(alg);
    if (oqs_alg == NULL)
    {
        return NULL;
    }
    PQC_PAKE_KEM_a *kem = OQS_MEM_malloc(sizeof(PQC_PAKE_KEM_a));
    if (kem == NULL)
    {
        return NULL;
    }
    OQS_KEM *oqs_kem = OQS_KEM_new(oqs_alg);
    if (oqs_kem == NULL)
    {
        OQS_MEM_secure_free(kem, sizeof(PQC_PAKE_KEM_a));
        return NULL;
    }
    kem->oqs_kem = oqs_kem;
    kem->public_key = NULL;
    kem->secret_key = NULL;
    kem->public_seed = NULL;
    kem->public_poly = NULL;
    kem->shared_secret = NULL;
    kem->len_public_key = oqs_kem->length_public_key;
    kem->len_public_seed = LEN_PUBLIC_SEED;
    kem->len_public_poly = kem->len_public_key - kem->len_public_seed;
    kem->len_secret_key = oqs_kem->length_secret_key;
    kem->len_ciphertext = oqs_kem->length_ciphertext;
    kem->len_shared_secret = oqs_kem->length_shared_secret;
    return kem;
}

int PQC_PAKE_KEM_a_keygen(
    PQC_PAKE_KEM_a *kem,
    uint8_t **public_key,
    uint8_t **secret_key)
{
    *public_key = OQS_MEM_malloc(kem->len_public_key);
    if (*public_key == NULL)
    {
        return 0;
    }
    *secret_key = OQS_MEM_malloc(kem->len_secret_key);
    if (*secret_key == NULL)
    {
        OQS_MEM_secure_free(*public_key, kem->len_public_key);
        return 0;
    }
    if (OQS_KEM_keypair(kem->oqs_kem, *public_key, *secret_key) !=
        OQS_SUCCESS)
    {
        OQS_MEM_secure_free(*public_key, kem->len_public_key);
        OQS_MEM_secure_free(*secret_key, kem->len_secret_key);
        return 0;
    }
    kem->public_key = *public_key;
    kem->secret_key = *secret_key;
    return 1;
}

int PQC_PAKE_KEM_a_split(
    PQC_PAKE_KEM_a *kem,
    uint8_t **seed,
    uint8_t **poly,
    const uint8_t *public_key)
{
    *seed = OQS_MEM_malloc(kem->len_public_seed);
    if (*seed == NULL)
    {
        return 0;
    }
    *poly = OQS_MEM_malloc(kem->len_public_poly);
    if (*poly == NULL)
    {
        OQS_MEM_secure_free(*seed, kem->len_public_seed);
        return 0;
    }
    memcpy(*seed, public_key + kem->len_public_poly, kem->len_public_seed);
    memcpy(*poly, public_key, kem->len_public_poly);
    kem->public_seed = *seed;
    kem->public_poly = *poly;
    return 1;
}

int PQC_PAKE_KEM_a_decaps(
    PQC_PAKE_KEM_a *kem,
    uint8_t **shared_secret,
    const uint8_t *ciphertext)
{
    if (kem->secret_key == NULL)
    {
        return 0;
    }
    *shared_secret = OQS_MEM_malloc(kem->len_shared_secret);
    if (*shared_secret == NULL)
    {
        return 0;
    }
    if (OQS_KEM_decaps(
            kem->oqs_kem,
            *shared_secret,
            ciphertext,
            kem->secret_key) != OQS_SUCCESS)
    {
        OQS_MEM_secure_free(*shared_secret, kem->len_shared_secret);
        return 0;
    }
    kem->shared_secret = *shared_secret;
    return 1;
}

void PQC_PAKE_KEM_a_free(PQC_PAKE_KEM_a *kem)
{
    if (kem->public_key != NULL)
    {
        OQS_MEM_secure_free(kem->public_key, kem->len_public_key);
    }
    if (kem->secret_key != NULL)
    {
        OQS_MEM_secure_free(kem->secret_key, kem->len_secret_key);
    }
    if (kem->public_seed != NULL)
    {
        OQS_MEM_secure_free(kem->public_seed, kem->len_public_seed);
    }
    if (kem->public_poly != NULL)
    {
        OQS_MEM_secure_free(kem->public_poly, kem->len_public_poly);
    }
    if (kem->shared_secret != NULL)
    {
        OQS_MEM_secure_free(kem->shared_secret, kem->len_shared_secret);
    }
    OQS_KEM_free(kem->oqs_kem);
    OQS_MEM_secure_free(kem, sizeof(PQC_PAKE_KEM_a));
}

PQC_PAKE_KEM_b *PQC_PAKE_KEM_b_new(const char *alg)
{
    const char *oqs_alg = to_oqs_alg(alg);
    if (oqs_alg == NULL)
    {
        return NULL;
    }
    PQC_PAKE_KEM_b *kem = OQS_MEM_malloc(sizeof(PQC_PAKE_KEM_b));
    if (kem == NULL)
    {
        return NULL;
    }
    OQS_KEM *oqs_kem = OQS_KEM_new(oqs_alg);
    if (oqs_kem == NULL)
    {
        OQS_MEM_secure_free(kem, sizeof(PQC_PAKE_KEM_b));
        return NULL;
    }
    kem->oqs_kem = oqs_kem;
    kem->public_key = NULL;
    kem->ciphertext = NULL;
    kem->shared_secret = NULL;
    kem->len_public_key = oqs_kem->length_public_key;
    kem->len_public_seed = LEN_PUBLIC_SEED;
    kem->len_public_poly = kem->len_public_key - kem->len_public_seed;
    kem->len_secret_key = oqs_kem->length_secret_key;
    kem->len_ciphertext = oqs_kem->length_ciphertext;
    kem->len_shared_secret = oqs_kem->length_shared_secret;
    return kem;
}

int PQC_PAKE_KEM_b_join(
    PQC_PAKE_KEM_b *kem,
    uint8_t **public_key,
    const uint8_t *seed,
    const uint8_t *poly)
{
    *public_key = OQS_MEM_malloc(kem->len_public_key);
    if (*public_key == NULL)
    {
        return 0;
    }
    memcpy(*public_key + kem->len_public_poly, seed, kem->len_public_seed);
    memcpy(*public_key, poly, kem->len_public_poly);
    kem->public_key = *public_key;
    return 1;
}

int PQC_PAKE_KEM_b_encaps(
    PQC_PAKE_KEM_b *kem,
    uint8_t **ciphertext,
    uint8_t **shared_secret,
    const uint8_t *public_key)
{
    *ciphertext = OQS_MEM_malloc(kem->len_ciphertext);
    if (*ciphertext == NULL)
    {
        return 0;
    }
    *shared_secret = OQS_MEM_malloc(kem->len_shared_secret);
    if (*shared_secret == NULL)
    {
        OQS_MEM_secure_free(*ciphertext, kem->len_ciphertext);
        return 0;
    }
    if (OQS_KEM_encaps(
            kem->oqs_kem,
            *ciphertext,
            *shared_secret,
            public_key) != OQS_SUCCESS)
    {
        OQS_MEM_secure_free(*ciphertext, kem->len_ciphertext);
        OQS_MEM_secure_free(*shared_secret, kem->len_shared_secret);
        return 0;
    }
    kem->ciphertext = *ciphertext;
    kem->shared_secret = *shared_secret;
    return 1;
}

void PQC_PAKE_KEM_b_free(PQC_PAKE_KEM_b *kem)
{
    if (kem->public_key != NULL)
    {
        OQS_MEM_secure_free(kem->public_key, kem->len_public_key);
    }
    if (kem->ciphertext != NULL)
    {
        OQS_MEM_secure_free(kem->ciphertext, kem->len_ciphertext);
    }
    if (kem->shared_secret != NULL)
    {
        OQS_MEM_secure_free(kem->shared_secret, kem->len_shared_secret);
    }
    OQS_KEM_free(kem->oqs_kem);
    OQS_MEM_secure_free(kem, sizeof(PQC_PAKE_KEM_b));
}
