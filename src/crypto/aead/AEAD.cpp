#include <cassert>

#include <crypto/aead/AEAD.h>
#include <crypto/aead/AES128GCM.h>
#include <crypto/aead/AES256GCM.h>
#include <crypto/aead/ChaCha20Poly1305.h>

namespace ocfbnj {
namespace crypto {
inline namespace aead {
std::unique_ptr<AEAD> AEAD::create(Method method) {
    switch (method) {
    case Method::ChaCha20Poly1305:
        return std::make_unique<ChaCha20Poly1305>();
    case Method::AES128GCM:
        return std::make_unique<AES128GCM>();
    case Method::AES256GCM:
        return std::make_unique<AES256GCM>();
    default:
        assert(0);
        break;
    }

    return {};
}

AEAD::AEAD(Method method) {
    mbedtls_cipher_init(&ctx);

    mbedtls_cipher_type_t cipherType;
    switch (method) {
    case Method::ChaCha20Poly1305:
        cipherType = MBEDTLS_CIPHER_CHACHA20_POLY1305;
        break;
    case Method::AES128GCM:
        cipherType = MBEDTLS_CIPHER_AES_128_GCM;
        break;
    case Method::AES256GCM:
        cipherType = MBEDTLS_CIPHER_AES_256_GCM;
        break;
    default:
        assert(0);
        break;
    }

    const mbedtls_cipher_info_t* info = mbedtls_cipher_info_from_type(cipherType);
    int ret = mbedtls_cipher_setup(&ctx, info);
    assert(ret == 0);
}

AEAD::~AEAD() {
    mbedtls_cipher_free(&ctx);
}

std::size_t AEAD::encrypt(std::span<const std::uint8_t> key,
                          std::span<const std::uint8_t> iv,
                          std::span<const std::uint8_t> ad,
                          std::span<const std::uint8_t> plaintext,
                          std::span<std::uint8_t> ciphertext) {
    assert(key.size() == keySize());
    assert(iv.size() == ivSize());
    assert(ciphertext.size() == plaintext.size() + tagSize());

    int ret = mbedtls_cipher_setkey(&ctx, key.data(), key.size() * 8, MBEDTLS_ENCRYPT);
    assert(ret == 0);

    std::size_t olen = 0;
    ret = mbedtls_cipher_auth_encrypt_ext(&ctx,
                                          iv.data(), iv.size(),
                                          ad.data(), ad.size(),
                                          plaintext.data(), plaintext.size(),
                                          ciphertext.data(), ciphertext.size(),
                                          &olen,
                                          tagSize());
    assert(ret == 0);

    return olen;
}

std::size_t AEAD::decrypt(std::span<const std::uint8_t> key,
                          std::span<const std::uint8_t> iv,
                          std::span<const std::uint8_t> ad,
                          std::span<const std::uint8_t> ciphertext,
                          std::span<std::uint8_t> plaintext) {
    assert(key.size() == keySize());
    assert(iv.size() == ivSize());
    assert(ciphertext.size() == plaintext.size() + tagSize());

    int ret = mbedtls_cipher_setkey(&ctx, key.data(), key.size() * 8, MBEDTLS_DECRYPT);
    assert(ret == 0);

    std::size_t olen = 0;
    ret = mbedtls_cipher_auth_decrypt_ext(&ctx,
                                          iv.data(), iv.size(),
                                          ad.data(), ad.size(),
                                          ciphertext.data(), ciphertext.size(),
                                          plaintext.data(), plaintext.size(),
                                          &olen,
                                          tagSize());
    assert(ret == 0);

    return olen;
}
} // namespace aead
} // namespace crypto
} // namespace ocfbnj
