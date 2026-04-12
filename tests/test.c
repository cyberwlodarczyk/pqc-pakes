#include <stdlib.h>
#include <stdio.h>
#include <pqc-pake/kem.h>
#include <pqc-pake/nice_pake.h>
#include <pqc-pake/rkem.h>
#include <pqc-pake/tempo.h>

int main()
{
    void PQC_PAKE_KEM_keygen();
    void PQC_PAKE_KEM_encaps();
    void PQC_PAKE_KEM_decaps();
    void PQC_PAKE_KEM_split();
    void PQC_PAKE_KEM_join();
    void PQC_PAKE_NICE_PAKE_A1();
    void PQC_PAKE_NICE_PAKE_B1();
    void PQC_PAKE_NICE_PAKE_A2();
    void PQC_PAKE_NICE_PAKE_RE_A1();
    void PQC_PAKE_NICE_PAKE_RE_B1();
    void PQC_PAKE_NICE_PAKE_RE_A2();
    void PQC_PAKE_RKEM_decaps();
    void PQC_PAKE_RKEM_rand();
    void PQC_PAKE_RKEM_derand();
    void PQC_PAKE_TEMPO_A1();
    void PQC_PAKE_TEMPO_B1();
    void PQC_PAKE_TEMPO_A2();
    void PQC_PAKE_TEMPO_RE_A1();
    void PQC_PAKE_TEMPO_RE_B1();
    void PQC_PAKE_TEMPO_RE_A2();
    return EXIT_SUCCESS;
}
