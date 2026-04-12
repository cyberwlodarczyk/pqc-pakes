#include <string.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include "nice.h"

#define ALG_PASSWORD_HASH "SHA256"
#define LEN_PASSWORD_HASH 32

PQC_PAKE_NICE *PQC_PAKE_NICE_new(const char *alg, const char *pw)
{
    uint8_t *hash = OQS_MEM_malloc(LEN_PASSWORD_HASH);
    if (hash == NULL)
    {
        return NULL;
    }
    if (!EVP_Q_digest(
            NULL,
            ALG_PASSWORD_HASH,
            NULL,
            pw,
            strlen(pw),
            hash,
            NULL))
    {
        OQS_MEM_secure_free(hash, LEN_PASSWORD_HASH);
        return NULL;
    }
    PQC_PAKE_NICE *nice = OQS_MEM_malloc(sizeof(PQC_PAKE_NICE));
    if (nice == NULL)
    {
        OQS_MEM_secure_free(hash, LEN_PASSWORD_HASH);
        return NULL;
    }
    PQC_PAKE_KEM *kem = PQC_PAKE_KEM_new(alg);
    if (kem == NULL)
    {
        OQS_MEM_secure_free(hash, LEN_PASSWORD_HASH);
        OQS_MEM_secure_free(nice, sizeof(PQC_PAKE_NICE));
        return NULL;
    }
    nice->kem = kem;
    nice->password = hash;
    nice->secret_key = NULL;
    return nice;
}

int PQC_PAKE_NICE_a1(PQC_PAKE_NICE *nice, uint8_t **seed, uint8_t **poly)
{
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    if (!PQC_PAKE_KEM_keygen(nice->kem, &public_key, &secret_key))
    {
        return 0;
    }
    if (!PQC_PAKE_KEM_split(nice->kem, seed, poly, public_key))
    {
        OQS_MEM_secure_free(public_key, nice->kem->len_public_key);
        OQS_MEM_secure_free(secret_key, nice->kem->len_secret_key);
        return 0;
    }
    OQS_MEM_secure_free(public_key, nice->kem->len_public_key);
    for (size_t i = 0; i < nice->kem->len_public_seed; i++)
    {
        (*seed)[i] ^= nice->password[i];
    }
    nice->secret_key = secret_key;
    return 1;
}

int PQC_PAKE_NICE_b1(
    PQC_PAKE_NICE *nice,
    uint8_t **ciphertext,
    uint8_t **shared_secret,
    const uint8_t *seed,
    const uint8_t *poly)
{
    uint8_t *seed_copy = OQS_MEM_malloc(nice->kem->len_public_seed);
    if (seed_copy == NULL)
    {
        return 0;
    }
    memcpy(seed_copy, seed, nice->kem->len_public_seed);
    for (size_t i = 0; i < nice->kem->len_public_seed; i++)
    {
        seed_copy[i] ^= nice->password[i];
    }
    uint8_t *public_key = NULL;
    if (!PQC_PAKE_KEM_join(nice->kem, &public_key, seed_copy, poly))
    {
        OQS_MEM_secure_free(seed_copy, nice->kem->len_public_seed);
        return 0;
    }
    int ok = PQC_PAKE_KEM_encaps(nice->kem, ciphertext, shared_secret, public_key);
    OQS_MEM_secure_free(seed_copy, nice->kem->len_public_seed);
    OQS_MEM_secure_free(public_key, nice->kem->len_public_key);
    return ok;
}

int PQC_PAKE_NICE_a2(
    const PQC_PAKE_NICE *nice,
    uint8_t **shared_secret,
    const uint8_t *ciphertext)
{
    return PQC_PAKE_KEM_decaps(
        nice->kem,
        shared_secret,
        ciphertext,
        nice->secret_key);
}

void PQC_PAKE_NICE_free(PQC_PAKE_NICE *nice)
{
    OQS_MEM_secure_free(nice->password, LEN_PASSWORD_HASH);
    if (nice->secret_key != NULL)
    {
        OQS_MEM_secure_free(nice->secret_key, nice->kem->len_secret_key);
    }
    PQC_PAKE_KEM_free(nice->kem);
    OQS_MEM_secure_free(nice, sizeof(nice));
}

void PQC_PAKE_NICE_re_a1()
{
}

void PQC_PAKE_NICE_re_b1()
{
}

void PQC_PAKE_NICE_re_a2()
{
}
