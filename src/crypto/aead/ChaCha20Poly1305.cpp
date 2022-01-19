#include <crypto/aead/ChaCha20Poly1305.h>

namespace ocfbnj {
namespace crypto {
inline namespace aead {
ChaCha20Poly1305::ChaCha20Poly1305() : AEAD(Method::ChaCha20Poly1305) {}

std::size_t ChaCha20Poly1305::keySize() const {
    return KeySize;
}

std::size_t ChaCha20Poly1305::ivSize() const {
    return IvSize;
}

std::size_t ChaCha20Poly1305::tagSize() const {
    return TagSize;
}
} // namespace aead
} // namespace crypto
} // namespace ocfbnj
