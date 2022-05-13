add_library(
    crypto
    STATIC
    aead.cpp
    crypto.cpp
    codec/base64.cpp
    codec/base64url.cpp
    codec/codec.cpp
    md/sha256.cpp)

target_include_directories(crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
target_link_libraries(crypto PRIVATE MbedTLS::mbedcrypto)

add_library(ocfbnj::crypto ALIAS crypto)
