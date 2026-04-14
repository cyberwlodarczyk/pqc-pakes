#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "nice.h"

#define ALG_PASSWORD_HASH "SHA256"
#define LEN_PASSWORD_HASH 32
#define LEN_PUBLIC_SEED PQC_PAKE_KEM_len_public_seed

int hash_password(uint8_t **hash, const char *pw)
{
    *hash = OPENSSL_malloc(LEN_PASSWORD_HASH);
    if (*hash == NULL)
    {
        return 0;
    }
    if (!EVP_Q_digest(
            NULL,
            ALG_PASSWORD_HASH,
            NULL,
            pw,
            strlen(pw),
            *hash,
            NULL))
    {
        OPENSSL_clear_free(*hash, LEN_PASSWORD_HASH);
        return 0;
    }
    return 1;
}

PQC_PAKE_NICE_a *PQC_PAKE_NICE_a_new(const char *pw)
{
    uint8_t *password;
    if (!hash_password(&password, pw))
    {
        return NULL;
    }
    PQC_PAKE_NICE_a *nice = OPENSSL_malloc(sizeof(PQC_PAKE_NICE_a));
    if (nice == NULL)
    {
        OPENSSL_clear_free(password, LEN_PASSWORD_HASH);
        return NULL;
    }
    PQC_PAKE_KEM_a *kem = PQC_PAKE_KEM_a_new();
    if (kem == NULL)
    {
        OPENSSL_clear_free(password, LEN_PASSWORD_HASH);
        OPENSSL_clear_free(nice, sizeof(PQC_PAKE_NICE_a));
        return NULL;
    }
    nice->kem = kem;
    nice->password = password;
    return nice;
}

int PQC_PAKE_NICE_a_keygen(
    PQC_PAKE_NICE_a *nice,
    uint8_t **seed,
    uint8_t **poly)
{
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    if (!PQC_PAKE_KEM_a_keygen(nice->kem, &public_key, &secret_key))
    {
        return 0;
    }
    if (!PQC_PAKE_KEM_a_split(nice->kem, seed, poly, public_key))
    {
        return 0;
    }
    for (size_t i = 0; i < LEN_PUBLIC_SEED; i++)
    {
        (*seed)[i] ^= nice->password[i];
    }
    return 1;
}

int PQC_PAKE_NICE_a_decaps(
    PQC_PAKE_NICE_a *nice,
    uint8_t **shared_secret,
    const uint8_t *ciphertext)
{
    return PQC_PAKE_KEM_a_decaps(
        nice->kem,
        shared_secret,
        ciphertext);
}

void PQC_PAKE_NICE_a_free(PQC_PAKE_NICE_a *nice)
{
    OPENSSL_clear_free(nice->password, LEN_PASSWORD_HASH);
    PQC_PAKE_KEM_a_free(nice->kem);
    OPENSSL_clear_free(nice, sizeof(PQC_PAKE_NICE_a));
}

PQC_PAKE_NICE_b *PQC_PAKE_NICE_b_new(const char *pw)
{
    uint8_t *password;
    if (!hash_password(&password, pw))
    {
        return NULL;
    }
    PQC_PAKE_NICE_b *nice = OPENSSL_malloc(sizeof(PQC_PAKE_NICE_b));
    if (nice == NULL)
    {
        OPENSSL_clear_free(password, LEN_PASSWORD_HASH);
        return NULL;
    }
    PQC_PAKE_KEM_b *kem = PQC_PAKE_KEM_b_new();
    if (kem == NULL)
    {
        OPENSSL_clear_free(password, LEN_PASSWORD_HASH);
        OPENSSL_clear_free(nice, sizeof(PQC_PAKE_NICE_b));
        return NULL;
    }
    nice->kem = kem;
    nice->password = password;
    return nice;
}

int PQC_PAKE_NICE_b_encaps(
    PQC_PAKE_NICE_b *nice,
    uint8_t **ciphertext,
    uint8_t **shared_secret,
    const uint8_t *seed,
    const uint8_t *poly)
{
    uint8_t *seed_copy = OPENSSL_malloc(LEN_PUBLIC_SEED);
    if (seed_copy == NULL)
    {
        return 0;
    }
    memcpy(seed_copy, seed, LEN_PUBLIC_SEED);
    for (size_t i = 0; i < LEN_PUBLIC_SEED; i++)
    {
        seed_copy[i] ^= nice->password[i];
    }
    uint8_t *public_key = NULL;
    if (!PQC_PAKE_KEM_b_join(nice->kem, &public_key, seed_copy, poly))
    {
        OPENSSL_clear_free(seed_copy, LEN_PUBLIC_SEED);
        return 0;
    }
    OPENSSL_clear_free(seed_copy, LEN_PUBLIC_SEED);
    return PQC_PAKE_KEM_b_encaps(
        nice->kem,
        ciphertext,
        shared_secret,
        public_key);
}

void PQC_PAKE_NICE_b_free(PQC_PAKE_NICE_b *nice)
{
    OPENSSL_clear_free(nice->password, LEN_PASSWORD_HASH);
    PQC_PAKE_KEM_b_free(nice->kem);
    OPENSSL_clear_free(nice, sizeof(PQC_PAKE_NICE_b));
}

void PQC_PAKE_NICE_re_a_keygen()
{
}

void PQC_PAKE_NICE_re_a_decaps()
{
}

void PQC_PAKE_NICE_re_b_encaps()
{
}
