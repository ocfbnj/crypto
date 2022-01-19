#ifndef OCFBNJ_CRYPTO_AES256GCM_H
#define OCFBNJ_CRYPTO_AES256GCM_H

#include <crypto/aead/AEAD.h>

namespace ocfbnj {
namespace crypto {
inline namespace aead {
class AES256GCM : public AEAD {
public:
    AES256GCM();

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
