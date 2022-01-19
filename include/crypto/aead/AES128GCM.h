#ifndef OCFBNJ_CRYPTO_AES128GCM_H
#define OCFBNJ_CRYPTO_AES128GCM_H

#include <crypto/aead/AEAD.h>

namespace ocfbnj {
namespace crypto {
inline namespace aead {
class AES128GCM : public AEAD {
public:
    AES128GCM();

    std::size_t keySize() const override;
    std::size_t ivSize() const override;
    std::size_t tagSize() const override;

    static constexpr std::size_t KeySize = 16;
    static constexpr std::size_t IvSize = 12;
    static constexpr std::size_t TagSize = 16;
};
} // namespace aead
} // namespace crypto
} // namespace ocfbnj

#endif
