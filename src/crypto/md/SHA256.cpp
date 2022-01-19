#include <crypto/md/SHA256.h>

namespace ocfbnj {
namespace crypto {
namespace md {
std::vector<std::uint8_t> SHA256::get(std::span<const std::uint8_t> msg) {
    std::vector<std::uint8_t> digest(Size);

    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md(info, msg.data(), msg.size(), digest.data());

    return digest;
}

SHA256::SHA256() {
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    int ret = mbedtls_md_setup(&ctx, info, 0);
    assert(ret == 0);

    starts();
}

SHA256::~SHA256() {
    mbedtls_md_free(&ctx);
}

void SHA256::starts() {
    int ret = mbedtls_md_starts(&ctx);
    assert(ret == 0);
}

void SHA256::update(std::span<const std::uint8_t> msg) {
    int ret = mbedtls_md_update(&ctx, msg.data(), msg.size());
    assert(ret == 0);
}

std::vector<std::uint8_t> SHA256::finish() {
    std::vector<std::uint8_t> digest(32);
    int ret = mbedtls_md_finish(&ctx, digest.data());
    assert(ret == 0);

    return digest;
}
} // namespace md
} // namespace crypto
} // namespace ocfbnj
