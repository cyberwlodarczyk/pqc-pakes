#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pqc-pake/nice.h>

#define N 100
#define PASSWORD "secret"

int test(PQC_PAKE_NICE_a *a_nice, PQC_PAKE_NICE_b *b_nice)
{
    uint8_t *a_public_seed = NULL;
    uint8_t *a_public_poly = NULL;
    if (!PQC_PAKE_NICE_a_keygen(a_nice, &a_public_seed, &a_public_poly))
    {
        return 0;
    }
    uint8_t *b_ciphertext = NULL;
    uint8_t *b_shared_secret = NULL;
    if (!PQC_PAKE_NICE_b_encaps(
            b_nice,
            &b_ciphertext,
            &b_shared_secret,
            a_public_seed,
            a_public_poly))
    {
        return 0;
    }
    uint8_t *a_shared_secret = NULL;
    if (!PQC_PAKE_NICE_a_decaps(a_nice, &a_shared_secret, b_ciphertext))
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

int test_n(const char *pw, int n)
{
    for (int i = 0; i < n; i++)
    {
        PQC_PAKE_NICE_a *a_nice = PQC_PAKE_NICE_a_new(pw);
        if (a_nice == NULL)
        {
            return 0;
        }
        PQC_PAKE_NICE_b *b_nice = PQC_PAKE_NICE_b_new(pw);
        if (b_nice == NULL)
        {
            PQC_PAKE_NICE_a_free(a_nice);
            return 0;
        }
        int ok = test(a_nice, b_nice);
        PQC_PAKE_NICE_a_free(a_nice);
        PQC_PAKE_NICE_b_free(b_nice);
        if (!ok)
        {
            return 0;
        }
    }
    return 1;
}

int main()
{
    if (test_n(PASSWORD, N))
    {
        return EXIT_SUCCESS;
    }
    else
    {
        return EXIT_SUCCESS;
    }
}
