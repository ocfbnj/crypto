add_library(
    ${CMAKE_PROJECT_NAME}
    STATIC
    crypto.cpp
    aead/AEAD.cpp
    codec/base64.cpp
    codec/codec.cpp
    md/SHA256.cpp)

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE MbedTLS::mbedcrypto)

add_library(ocfbnj::${CMAKE_PROJECT_NAME} ALIAS ${CMAKE_PROJECT_NAME})
