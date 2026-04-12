#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pqc-pake/nice.h>

int main()
{
    const char *pw = "secret";
    PQC_PAKE_NICE *nice = PQC_PAKE_NICE_new(PQC_PAKE_KEM_alg_kyber_768, pw);
    if (nice == NULL)
    {
        return EXIT_FAILURE;
    }
    uint8_t *seed = NULL;
    uint8_t *poly = NULL;
    if (!PQC_PAKE_NICE_a1(nice, &seed, &poly))
    {
        PQC_PAKE_NICE_free(nice);
        return EXIT_FAILURE;
    }
    uint8_t *ciphertext = NULL;
    uint8_t *a_shared_secret = NULL;
    if (!PQC_PAKE_NICE_b1(
            nice,
            &ciphertext,
            &a_shared_secret,
            seed,
            poly))
    {
        OQS_MEM_secure_free(seed, nice->kem->len_public_seed);
        OQS_MEM_secure_free(poly, nice->kem->len_public_poly);
        PQC_PAKE_NICE_free(nice);
        return EXIT_FAILURE;
    }
    OQS_MEM_secure_free(seed, nice->kem->len_public_seed);
    OQS_MEM_secure_free(poly, nice->kem->len_public_poly);
    uint8_t *b_shared_secret = NULL;
    if (!PQC_PAKE_NICE_a2(nice, &b_shared_secret, ciphertext))
    {
        OQS_MEM_secure_free(a_shared_secret, nice->kem->len_shared_secret);
        OQS_MEM_secure_free(ciphertext, nice->kem->len_ciphertext);
        PQC_PAKE_NICE_free(nice);
        return EXIT_FAILURE;
    }
    OQS_MEM_secure_free(ciphertext, nice->kem->len_ciphertext);
    int cmp = memcmp(a_shared_secret, b_shared_secret, nice->kem->len_shared_secret);
    OQS_MEM_secure_free(a_shared_secret, nice->kem->len_shared_secret);
    OQS_MEM_secure_free(b_shared_secret, nice->kem->len_shared_secret);
    PQC_PAKE_NICE_free(nice);
    if (cmp == 0)
    {
        return EXIT_SUCCESS;
    }
    else
    {
        return EXIT_FAILURE;
    }
}
