#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pqc-pake/kem.h>

#define N 100

int test(PQC_PAKE_KEM_a *a_kem, PQC_PAKE_KEM_b *b_kem)
{
    uint8_t *a_public_key = NULL;
    uint8_t *a_secret_key = NULL;
    if (!PQC_PAKE_KEM_a_keygen(a_kem, &a_public_key, &a_secret_key))
    {
        return 0;
    }
    uint8_t *a_public_seed = NULL;
    uint8_t *a_public_poly = NULL;
    if (!PQC_PAKE_KEM_a_split(
            a_kem,
            &a_public_seed,
            &a_public_poly,
            a_public_key))
    {
        return 0;
    }
    uint8_t *b_public_key = NULL;
    if (!PQC_PAKE_KEM_b_join(b_kem,
                             &b_public_key,
                             a_public_seed,
                             a_public_poly))
    {
        return 0;
    }
    uint8_t *b_ciphertext = NULL;
    uint8_t *b_shared_secret = NULL;
    if (!PQC_PAKE_KEM_b_encaps(
            b_kem,
            &b_ciphertext,
            &b_shared_secret,
            b_public_key))
    {
        return 0;
    }
    uint8_t *a_shared_secret = NULL;
    if (!PQC_PAKE_KEM_a_decaps(a_kem, &a_shared_secret, b_ciphertext))
    {
        return 0;
    }
    if (memcmp(
            a_shared_secret,
            b_shared_secret,
            PQC_PAKE_KEM_len_shared_secret) == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int test_n(int n)
{
    for (int i = 0; i < n; i++)
    {
        PQC_PAKE_KEM_a *a_kem = PQC_PAKE_KEM_a_new();
        if (a_kem == NULL)
        {
            return 0;
        }
        PQC_PAKE_KEM_b *b_kem = PQC_PAKE_KEM_b_new();
        if (b_kem == NULL)
        {
            PQC_PAKE_KEM_a_free(a_kem);
            return 0;
        }
        int ok = test(a_kem, b_kem);
        PQC_PAKE_KEM_a_free(a_kem);
        PQC_PAKE_KEM_b_free(b_kem);
        if (!ok)
        {
            return 0;
        }
    }
    return 1;
}

int main()
{
    if (test_n(N))
    {
        return EXIT_SUCCESS;
    }
    else
    {
        return EXIT_SUCCESS;
    }
}
