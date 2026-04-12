cmake_minimum_required(VERSION 3.28)

project(pqc-pake C)

add_library(pqc-pake SHARED)

set(CMAKE_INSTALL_PREFIX $ENV{PQC_PAKE_DIR})

target_sources(
    pqc-pake
    PRIVATE
        src/kem.c
        src/nice_pake.c
        src/rkem.c
        src/tempo.c
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS
            src
        FILES
            src/kem.h
            src/nice_pake.h
            src/rkem.h
            src/tempo.h
)

install(
    TARGETS pqc-pake
    FILE_SET HEADERS
        DESTINATION include/pqc-pake
)