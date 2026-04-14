add_library(pqc-pake SHARED
    kem.c
    nice.c
    rkem.c
    tempo.c
)

target_link_libraries(pqc-pake PUBLIC kyber)

target_include_directories(pqc-pake
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
        $<INSTALL_INTERFACE:include/pqc-pake>
)

install(TARGETS pqc-pake
    LIBRARY DESTINATION lib
    INCLUDES DESTINATION include
)

install(FILES
    kem.h nice.h rkem.h tempo.h
    DESTINATION include/pqc-pake
)