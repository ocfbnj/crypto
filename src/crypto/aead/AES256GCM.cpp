#include <crypto/aead/AES256GCM.h>

namespace ocfbnj {
namespace crypto {
inline namespace aead {
AES256GCM::AES256GCM() : AEAD(Method::AES256GCM) {}

std::size_t AES256GCM::keySize() const {
    return KeySize;
}

std::size_t AES256GCM::ivSize() const {
    return IvSize;
}

std::size_t AES256GCM::tagSize() const {
    return TagSize;
}
} // namespace aead
} // namespace crypto
} // namespace ocfbnj
