#include <string.h>
#include <openssl/crypto.h>
#include <kyber/kem.h>
#include <kyber/params.h>
#include "kem.h"

#define LEN_PUBLIC_KEY PQC_PAKE_KEM_len_public_key
#define LEN_PUBLIC_SEED PQC_PAKE_KEM_len_public_seed
#define LEN_PUBLIC_POLY PQC_PAKE_KEM_len_public_poly
#define LEN_SECRET_KEY PQC_PAKE_KEM_len_secret_key
#define LEN_CIPHERTEXT PQC_PAKE_KEM_len_ciphertext
#define LEN_SHARED_SECRET PQC_PAKE_KEM_len_shared_secret

PQC_PAKE_KEM_a *PQC_PAKE_KEM_a_new()
{
    PQC_PAKE_KEM_a *kem = OPENSSL_malloc(sizeof(PQC_PAKE_KEM_a));
    if (kem == NULL)
    {
        return NULL;
    }
    kem->public_key = NULL;
    kem->secret_key = NULL;
    kem->public_seed = NULL;
    kem->public_poly = NULL;
    kem->shared_secret = NULL;
    return kem;
}

int PQC_PAKE_KEM_a_keygen(
    PQC_PAKE_KEM_a *kem,
    uint8_t **public_key,
    uint8_t **secret_key)
{
    *public_key = OPENSSL_malloc(LEN_PUBLIC_KEY);
    if (*public_key == NULL)
    {
        return 0;
    }
    *secret_key = OPENSSL_malloc(LEN_SECRET_KEY);
    if (*secret_key == NULL)
    {
        OPENSSL_clear_free(*public_key, LEN_PUBLIC_KEY);
        return 0;
    }
    pqcrystals_kyber768_ref_keypair(*public_key, *secret_key);
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
    *seed = OPENSSL_malloc(LEN_PUBLIC_SEED);
    if (*seed == NULL)
    {
        return 0;
    }
    *poly = OPENSSL_malloc(LEN_PUBLIC_POLY);
    if (*poly == NULL)
    {
        OPENSSL_clear_free(*seed, LEN_PUBLIC_SEED);
        return 0;
    }
    memcpy(*seed, public_key + LEN_PUBLIC_POLY, LEN_PUBLIC_SEED);
    memcpy(*poly, public_key, LEN_PUBLIC_POLY);
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
    *shared_secret = OPENSSL_malloc(LEN_SHARED_SECRET);
    if (*shared_secret == NULL)
    {
        return 0;
    }
    pqcrystals_kyber768_ref_dec(*shared_secret, ciphertext, kem->secret_key);
    kem->shared_secret = *shared_secret;
    return 1;
}

void PQC_PAKE_KEM_a_free(PQC_PAKE_KEM_a *kem)
{
    if (kem->public_key != NULL)
    {
        OPENSSL_clear_free(kem->public_key, LEN_PUBLIC_KEY);
    }
    if (kem->secret_key != NULL)
    {
        OPENSSL_clear_free(kem->secret_key, LEN_SECRET_KEY);
    }
    if (kem->public_seed != NULL)
    {
        OPENSSL_clear_free(kem->public_seed, LEN_PUBLIC_SEED);
    }
    if (kem->public_poly != NULL)
    {
        OPENSSL_clear_free(kem->public_poly, LEN_PUBLIC_POLY);
    }
    if (kem->shared_secret != NULL)
    {
        OPENSSL_clear_free(kem->shared_secret, LEN_SHARED_SECRET);
    }
    OPENSSL_clear_free(kem, sizeof(PQC_PAKE_KEM_a));
}

PQC_PAKE_KEM_b *PQC_PAKE_KEM_b_new()
{
    PQC_PAKE_KEM_b *kem = OPENSSL_malloc(sizeof(PQC_PAKE_KEM_b));
    if (kem == NULL)
    {
        return NULL;
    }
    kem->public_key = NULL;
    kem->ciphertext = NULL;
    kem->shared_secret = NULL;
    return kem;
}

int PQC_PAKE_KEM_b_join(
    PQC_PAKE_KEM_b *kem,
    uint8_t **public_key,
    const uint8_t *seed,
    const uint8_t *poly)
{
    *public_key = OPENSSL_malloc(LEN_PUBLIC_KEY);
    if (*public_key == NULL)
    {
        return 0;
    }
    memcpy(*public_key + LEN_PUBLIC_POLY, seed, LEN_PUBLIC_SEED);
    memcpy(*public_key, poly, LEN_PUBLIC_POLY);
    kem->public_key = *public_key;
    return 1;
}

int PQC_PAKE_KEM_b_encaps(
    PQC_PAKE_KEM_b *kem,
    uint8_t **ciphertext,
    uint8_t **shared_secret,
    const uint8_t *public_key)
{
    *ciphertext = OPENSSL_malloc(LEN_CIPHERTEXT);
    if (*ciphertext == NULL)
    {
        return 0;
    }
    *shared_secret = OPENSSL_malloc(LEN_SHARED_SECRET);
    if (*shared_secret == NULL)
    {
        OPENSSL_clear_free(*ciphertext, LEN_CIPHERTEXT);
        return 0;
    }
    pqcrystals_kyber768_ref_enc(*ciphertext, *shared_secret, public_key);
    kem->ciphertext = *ciphertext;
    kem->shared_secret = *shared_secret;
    return 1;
}

void PQC_PAKE_KEM_b_free(PQC_PAKE_KEM_b *kem)
{
    if (kem->public_key != NULL)
    {
        OPENSSL_clear_free(kem->public_key, LEN_PUBLIC_KEY);
    }
    if (kem->ciphertext != NULL)
    {
        OPENSSL_clear_free(kem->ciphertext, LEN_CIPHERTEXT);
    }
    if (kem->shared_secret != NULL)
    {
        OPENSSL_clear_free(kem->shared_secret, LEN_SHARED_SECRET);
    }
    OPENSSL_clear_free(kem, sizeof(PQC_PAKE_KEM_b));
}
