add_library(
    crypto
    STATIC
    crypto.cpp
    aead/AEAD.cpp
    codec/base64.cpp
    codec/base64url.cpp
    codec/codec.cpp
    md/SHA256.cpp)

target_include_directories(crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
target_link_libraries(crypto PRIVATE MbedTLS::mbedcrypto)

add_library(ocfbnj::crypto ALIAS crypto)
