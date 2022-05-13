#include <cstdint>
#include <span>
#include <vector>

namespace crypto {
namespace codec {
namespace experimental {
namespace base64url {
// encode encode src to base64 format.
std::vector<std::uint8_t> encode(std::span<const std::uint8_t> src);

// decode decode base64 encoded src to original format.
// throw `decoding_error` if the base64 characters are invalid.
std::vector<std::uint8_t> decode(std::span<const std::uint8_t> src);
} // namespace base64url
} // namespace experimental
} // namespace codec
} // namespace crypto
