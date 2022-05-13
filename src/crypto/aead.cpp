#include <cassert>
#include <cstdlib>
#include <cstring>

#include <mbedtls/cipher.h>

#include <crypto/aead.h>

namespace crypto {
aead::aead(method m) : m(m) {
    ptr = malloc(sizeof(mbedtls_cipher_context_t));
    assert(ptr != nullptr);
    memset(ptr, 0, sizeof(mbedtls_cipher_context_t));

    auto ctx = static_cast<mbedtls_cipher_context_t*>(ptr);

    mbedtls_cipher_init(ctx);

    mbedtls_cipher_type_t cipherType;
    switch (m) {
    case chacha20_poly1305:
        cipherType = MBEDTLS_CIPHER_CHACHA20_POLY1305;
        break;
    case aes_128_gcm:
        cipherType = MBEDTLS_CIPHER_AES_128_GCM;
        break;
    case aes_256_gcm:
        cipherType = MBEDTLS_CIPHER_AES_256_GCM;
        break;
    default:
        assert(0);
        break;
    }

    const mbedtls_cipher_info_t* info = mbedtls_cipher_info_from_type(cipherType);
    int ret = mbedtls_cipher_setup(ctx, info);
    assert(ret == 0);
}

aead::~aead() {
    auto ctx = static_cast<mbedtls_cipher_context_t*>(ptr);
    assert(ctx != nullptr);

    mbedtls_cipher_free(ctx);
    free(ctx);
}

std::size_t aead::encrypt(std::span<const std::uint8_t> key,
                          std::span<const std::uint8_t> iv,
                          std::span<const std::uint8_t> ad,
                          std::span<const std::uint8_t> plaintext,
                          std::span<std::uint8_t> ciphertext) {
    assert(key.size() == key_size(m));
    assert(iv.size() == iv_size(m));
    assert(ciphertext.size() == plaintext.size() + tag_size(m));

    auto ctx = static_cast<mbedtls_cipher_context_t*>(ptr);
    assert(ctx != nullptr);

    int ret = mbedtls_cipher_setkey(ctx, key.data(), key.size() * 8, MBEDTLS_ENCRYPT);
    assert(ret == 0);

    std::size_t olen = 0;
    ret = mbedtls_cipher_auth_encrypt_ext(ctx,
                                          iv.data(), iv.size(),
                                          ad.data(), ad.size(),
                                          plaintext.data(), plaintext.size(),
                                          ciphertext.data(), ciphertext.size(),
                                          &olen,
                                          tag_size(m));
    assert(ret == 0);

    return olen;
}

std::size_t aead::decrypt(std::span<const std::uint8_t> key,
                          std::span<const std::uint8_t> iv,
                          std::span<const std::uint8_t> ad,
                          std::span<const std::uint8_t> ciphertext,
                          std::span<std::uint8_t> plaintext) {
    assert(key.size() == key_size(m));
    assert(iv.size() == iv_size(m));
    assert(ciphertext.size() == plaintext.size() + tag_size(m));

    auto ctx = static_cast<mbedtls_cipher_context_t*>(ptr);
    assert(ctx != nullptr);

    int ret = mbedtls_cipher_setkey(ctx, key.data(), key.size() * 8, MBEDTLS_DECRYPT);
    assert(ret == 0);

    std::size_t olen = 0;
    ret = mbedtls_cipher_auth_decrypt_ext(ctx,
                                          iv.data(), iv.size(),
                                          ad.data(), ad.size(),
                                          ciphertext.data(), ciphertext.size(),
                                          plaintext.data(), plaintext.size(),
                                          &olen,
                                          tag_size(m));
    if (ret != 0) {
        throw decryption_error{"Decryption error"};
    }

    return olen;
}

std::size_t aead::get_key_size() const {
    return key_size(m);
}

std::size_t aead::get_iv_size() const {
    return iv_size(m);
}

std::size_t aead::get_tag_size() const {
    return tag_size(m);
}

aead::method aead::get_method() const {
    return m;
}
} // namespace crypto
