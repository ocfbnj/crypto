#include <cassert>
#include <cstdlib>
#include <cstring>

#include <mbedtls/md.h>

#include <crypto/md/sha256.h>

namespace crypto {
namespace md {
std::vector<std::uint8_t> sha256::get(std::span<const std::uint8_t> msg) {
    std::vector<std::uint8_t> digest(size);

    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md(info, msg.data(), msg.size(), digest.data());

    return digest;
}

sha256::sha256() {
    ptr = malloc(sizeof(mbedtls_md_context_t));
    assert(ptr != NULL);
    memset(ptr, 0, sizeof(mbedtls_md_context_t));

    auto ctx = static_cast<mbedtls_md_context_t*>(ptr);

    mbedtls_md_init(ctx);
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    int ret = mbedtls_md_setup(ctx, info, 0);
    assert(ret == 0);

    starts();
}

sha256::~sha256() {
    auto ctx = static_cast<mbedtls_md_context_t*>(ptr);
    assert(ctx != nullptr);

    mbedtls_md_free(ctx);
    free(ctx);
}

void sha256::starts() {
    auto ctx = static_cast<mbedtls_md_context_t*>(ptr);
    assert(ctx != nullptr);

    int ret = mbedtls_md_starts(ctx);
    assert(ret == 0);
}

void sha256::update(std::span<const std::uint8_t> msg) {
    auto ctx = static_cast<mbedtls_md_context_t*>(ptr);
    assert(ctx != nullptr);

    int ret = mbedtls_md_update(ctx, msg.data(), msg.size());
    assert(ret == 0);
}

std::vector<std::uint8_t> sha256::finish() {
    auto ctx = static_cast<mbedtls_md_context_t*>(ptr);
    assert(ctx != nullptr);

    std::vector<std::uint8_t> digest(size);
    int ret = mbedtls_md_finish(ctx, digest.data());
    assert(ret == 0);

    return digest;
}
} // namespace md
} // namespace crypto
