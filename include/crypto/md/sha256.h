#ifndef OCFBNJ_CRYPTO_SHA256_H
#define OCFBNJ_CRYPTO_SHA256_H

#include <cstdint>
#include <span>
#include <vector>

namespace crypto {
namespace md {
class sha256 {
public:
    static constexpr std::size_t size = 32;

    static std::vector<std::uint8_t> get(std::span<const std::uint8_t> msg);

    sha256();
    ~sha256();

    void starts();
    void update(std::span<const std::uint8_t> msg);
    std::vector<std::uint8_t> finish();

private:
    void* ptr;
};
} // namespace md
} // namespace crypto

#endif
