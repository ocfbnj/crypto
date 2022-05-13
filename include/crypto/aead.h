#ifndef OCFBNJ_CRYPTO_AEAD_H
#define OCFBNJ_CRYPTO_AEAD_H

#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>

namespace crypto {
class aead {
public:
    enum method {
        chacha20_poly1305,
        aes_128_gcm,
        aes_256_gcm,
        invalid
    };

    class decryption_error : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    aead(method method);
    ~aead();

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

    std::size_t get_key_size() const;
    std::size_t get_iv_size() const;
    std::size_t get_tag_size() const;

    method get_method() const;

    static constexpr std::size_t key_size(method method) {
        switch (method) {
        case chacha20_poly1305:
        case aes_256_gcm:
            return 32;
        case aes_128_gcm:
            return 16;
        default:
            return 0;
        }
    }

    static constexpr std::size_t iv_size(method method) {
        switch (method) {
        case chacha20_poly1305:
        case aes_256_gcm:
        case aes_128_gcm:
            return 12;
        default:
            return 0;
        }
    }

    static constexpr std::size_t tag_size(method method) {
        switch (method) {
        case chacha20_poly1305:
        case aes_256_gcm:
        case aes_128_gcm:
            return 16;
        default:
            return 0;
        }
    }

private:
    method m;
    void* ptr;
};
} // namespace crypto

#endif
