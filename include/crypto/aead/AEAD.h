#ifndef OCFBNJ_CRYPTO_AEAD_H
#define OCFBNJ_CRYPTO_AEAD_H

#include <cstdint>
#include <memory>
#include <span>

namespace crypto {
inline namespace aead {
class AEAD {
public:
    enum Method {
        ChaCha20Poly1305,
        AES128GCM,
        AES256GCM,
        Invalid
    };

    AEAD(Method method);
    ~AEAD();

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

    static constexpr std::size_t keySize(Method method) {
        switch (method) {
        case ChaCha20Poly1305:
        case AES256GCM:
            return 32;
        case AES128GCM:
            return 16;
        default:
            return 0;
        }
    }

    static constexpr std::size_t ivSize(Method method) {
        switch (method) {
        case ChaCha20Poly1305:
        case AES256GCM:
        case AES128GCM:
            return 12;
        default:
            return 0;
        }
    }

    static constexpr std::size_t tagSize(Method method) {
        switch (method) {
        case ChaCha20Poly1305:
        case AES256GCM:
        case AES128GCM:
            return 16;
        default:
            return 0;
        }
    }

private:
    Method method;
    void* ptr;
};
} // namespace aead
} // namespace crypto

#endif
