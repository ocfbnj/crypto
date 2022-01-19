#ifndef OCFBNJ_CRYPTO_CHACHA20POLY1305_H
#define OCFBNJ_CRYPTO_CHACHA20POLY1305_H

#include <crypto/aead/AEAD.h>

namespace ocfbnj {
namespace crypto {
inline namespace aead {
class ChaCha20Poly1305 : public AEAD {
public:
    ChaCha20Poly1305();

    std::size_t keySize() const override;
    std::size_t ivSize() const override;
    std::size_t tagSize() const override;

    static constexpr std::size_t KeySize = 32;
    static constexpr std::size_t IvSize = 12;
    static constexpr std::size_t TagSize = 16;
};
} // namespace aead
} // namespace crypto
} // namespace ocfbnj

#endif
