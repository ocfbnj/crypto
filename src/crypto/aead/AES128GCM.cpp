#include <crypto/aead/AES128GCM.h>

namespace ocfbnj {
namespace crypto {
inline namespace aead {
AES128GCM::AES128GCM() : AEAD(Method::AES128GCM) {}

std::size_t AES128GCM::keySize() const {
    return KeySize;
}

std::size_t AES128GCM::ivSize() const {
    return IvSize;
}

std::size_t AES128GCM::tagSize() const {
    return TagSize;
}
} // namespace aead
} // namespace crypto
} // namespace ocfbnj
