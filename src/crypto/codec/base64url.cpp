#include <algorithm>

#include <crypto/codec/base64.h>
#include <crypto/codec/base64url.h>
#include <crypto/codec/codec.h>

namespace crypto {
namespace codec {
namespace experimental {
namespace base64url {
// encode encode src to base64url format.
std::vector<std::uint8_t> encode(std::span<const std::uint8_t> src) {
    std::vector<std::uint8_t> res = crypto::codec::base64::encode(src);

    res.erase(std::find_if(res.rbegin(), res.rend(), [](std::uint8_t c) { return c != '='; }).base(), res.end());
    for (std::uint8_t& c : res) {
        if (c == '+') {
            c = '-';
        } else if (c == '/') {
            c = '_';
        }
    }

    return res;
}

// decode decode base64url encoded src to original format.
// throw `decoding_error` if the base64url characters are invalid.
std::vector<std::uint8_t> decode(std::span<const std::uint8_t> src) {
    std::vector<std::uint8_t> data{src.begin(), src.end()};
    if (auto m = data.size() % 4; m != 0) {
        if (m == 1) {
            throw crypto::codec::decoding_error{"base64url invalid input"};
        }

        if (m == 2) {
            data.emplace_back('=');
        }
        data.emplace_back('=');
    }

    for (std::uint8_t& c : data) {
        if (c == '-') {
            c = '+';
        } else if (c == '_') {
            c = '/';
        }
    }

    std::vector<std::uint8_t> res = crypto::codec::base64::decode(data);

    return res;
}
} // namespace base64url
} // namespace experimental
} // namespace codec
} // namespace crypto
