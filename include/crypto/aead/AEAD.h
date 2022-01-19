#ifndef OCFBNJ_CRYPTO_AEAD_H
#define OCFBNJ_CRYPTO_AEAD_H

#include <cstdint>
#include <memory>
#include <span>

#include <mbedtls/cipher.h>

namespace ocfbnj {
namespace crypto {
inline namespace aead {
class AEAD {
public:
    enum class Method {
        ChaCha20Poly1305,
        AES128GCM,
        AES256GCM,
        Invalid
    };

    static std::unique_ptr<AEAD> create(Method method);

    AEAD(Method method);
    virtual ~AEAD();

    std::size_t encrypt(std::span<const std::uint8_t> key,
                        std::span<const std::uint8_t> iv,
                        std::span<const std::uint8_t> ad,
                        std::span<const std::uint8_t> plaintext,
                        std::span<std::uint8_t> ciphertext);

    std::size_t decrypt(std::span<const std::uint8_t> key,
                        std::span<const std::uint8_t> iv,
                        std::span<const std::uint8_t> ad,
                        std::span<const std::uint8_t> ciphertext,
                        std::span<std::uint8_t> plaintext);

    virtual std::size_t keySize() const = 0;
    virtual std::size_t ivSize() const = 0;
    virtual std::size_t tagSize() const = 0;

private:
    mbedtls_cipher_context_t ctx;
};
} // namespace aead
} // namespace crypto
} // namespace ocfbnj

#endif
