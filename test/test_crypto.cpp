#include <array>

#include <gtest/gtest.h>

#include <crypto/aead.h>
#include <crypto/codec/base64.h>
#include <crypto/codec/base64url.h>
#include <crypto/codec/codec.h>
#include <crypto/crypto.h>
#include <crypto/md/sha256.h>

using namespace crypto;

TEST(increment, num0) {
    std::array<std::uint8_t, 2> num{0, 0};
    std::array<std::uint8_t, 2> expect_num{1, 0};

    increment(num);
    ASSERT_EQ(num, expect_num);
}

TEST(increment, num1) {
    std::array<std::uint8_t, 2> num{1, 0};
    std::array<std::uint8_t, 2> expect_num{2, 0};

    increment(num);
    ASSERT_EQ(num, expect_num);
}

TEST(increment, num255) {
    std::array<std::uint8_t, 2> num{255, 0};
    std::array<std::uint8_t, 2> expect_num{0, 1};

    increment(num);
    ASSERT_EQ(num, expect_num);
}

TEST(increment, num256) {
    std::array<std::uint8_t, 2> num{0, 1};
    std::array<std::uint8_t, 2> expect_num{1, 1};

    increment(num);
    ASSERT_EQ(num, expect_num);
}

TEST(to_hex_stream, empty) {
    ASSERT_EQ(to_hex_stream({}), "");
}

TEST(to_hex_stream, size16) {
    std::array<std::uint8_t, 16> bytes{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    ASSERT_EQ(to_hex_stream(bytes), "000102030405060708090a0b0c0d0e0f");
}

TEST(base64, encode) {
    ASSERT_EQ(to_string(codec::base64::encode(to_span(""))), "");
    ASSERT_EQ(to_string(codec::base64::encode(to_span("hello worl"))), "aGVsbG8gd29ybA==");
    ASSERT_EQ(to_string(codec::base64::encode(to_span("hello world"))), "aGVsbG8gd29ybGQ=");
    ASSERT_EQ(to_string(codec::base64::encode(to_span("hello world!"))), "aGVsbG8gd29ybGQh");
    ASSERT_EQ(to_string(codec::base64::encode(to_span("<<???>>"))), "PDw/Pz8+Pg==");
}

TEST(base64, decode) {
    ASSERT_EQ(to_string(codec::base64::decode(to_span(""))), "");
    ASSERT_EQ(to_string(codec::base64::decode(to_span("aGVsbG8gd29ybA=="))), "hello worl");
    ASSERT_EQ(to_string(codec::base64::decode(to_span("aGVsbG8gd29ybGQ="))), "hello world");
    ASSERT_EQ(to_string(codec::base64::decode(to_span("aGVsbG8gd29ybGQh"))), "hello world!");
    ASSERT_EQ(to_string(codec::base64::decode(to_span("PDw/Pz8+Pg=="))), "<<???>>");
}

TEST(base64, invalid_character) {
    try {
        codec::base64::decode(to_span("a`"));
    } catch (const codec::decoding_error& e) {
        EXPECT_EQ(e.what(), std::string{"base64 invalid character"});
        return;
    }

    FAIL() << "Expected crypto::codec::decoding_error";
}

TEST(base64url, encode) {
    ASSERT_EQ(to_string(codec::experimental::base64url::encode(to_span(""))), "");
    ASSERT_EQ(to_string(codec::experimental::base64url::encode(to_span("hello worl"))), "aGVsbG8gd29ybA");
    ASSERT_EQ(to_string(codec::experimental::base64url::encode(to_span("hello world"))), "aGVsbG8gd29ybGQ");
    ASSERT_EQ(to_string(codec::experimental::base64url::encode(to_span("hello world!"))), "aGVsbG8gd29ybGQh");
    ASSERT_EQ(to_string(codec::experimental::base64url::encode(to_span("<<???>>"))), "PDw_Pz8-Pg");
}

TEST(base64url, decode) {
    ASSERT_EQ(to_string(codec::experimental::base64url::decode(to_span(""))), "");
    ASSERT_EQ(to_string(codec::experimental::base64url::decode(to_span("aGVsbG8gd29ybA"))), "hello worl");
    ASSERT_EQ(to_string(codec::experimental::base64url::decode(to_span("aGVsbG8gd29ybGQ"))), "hello world");
    ASSERT_EQ(to_string(codec::experimental::base64url::decode(to_span("aGVsbG8gd29ybGQh"))), "hello world!");
    ASSERT_EQ(to_string(codec::experimental::base64url::decode(to_span("PDw_Pz8-Pg"))), "<<???>>");
}

TEST(base64url, invalid_input) {
    try {
        codec::experimental::base64url::decode(to_span("aGVsbG8gd29yb"));
    } catch (const codec::decoding_error& e) {
        EXPECT_EQ(e.what(), std::string{"base64url invalid input"});
        return;
    }

    FAIL() << "Expected crypto::codec::decoding_error";
}

TEST(sha256, get) {
    ASSERT_EQ(to_hex_stream(md::sha256::get(to_span("hello world"))), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

TEST(sha256, partial) {
    md::sha256 sha256;

    sha256.update(to_span("hello"));
    sha256.update(to_span(" "));
    sha256.update(to_span("world"));

    ASSERT_EQ(to_hex_stream(sha256.finish()), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

TEST(chacha20_poly1305, encrypt) {
    constexpr std::size_t key_size = aead::key_size(aead::chacha20_poly1305);
    constexpr std::size_t tag_size = aead::tag_size(aead::chacha20_poly1305);
    constexpr std::size_t iv_size = aead::iv_size(aead::chacha20_poly1305);

    std::array<std::uint8_t, key_size> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<std::uint8_t, 5> message{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 5 + tag_size> ciphertext;
    std::array<std::uint8_t, 5 + tag_size> expect_ciphertext{
        105, 66, 33, 189, 129, 203, 219, 231, 140, 85, 21,
        136, 140, 75, 200, 219, 165, 104, 17, 161, 79};

    aead enc{aead::chacha20_poly1305};
    std::array<std::uint8_t, iv_size> iv{};

    enc.encrypt(key, iv, {}, message, ciphertext);
    ASSERT_EQ(ciphertext, expect_ciphertext);
}

TEST(chacha20_poly1305, decrypt) {
    constexpr std::size_t key_size = aead::key_size(aead::chacha20_poly1305);
    constexpr std::size_t tag_size = aead::tag_size(aead::chacha20_poly1305);
    constexpr std::size_t iv_size = aead::iv_size(aead::chacha20_poly1305);

    std::array<uint8_t, key_size> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<uint8_t, 5 + tag_size> ciphertext{
        105, 66, 33, 189, 129, 203, 219, 231, 140, 85, 21,
        136, 140, 75, 200, 219, 165, 104, 17, 161, 79};
    std::array<uint8_t, 5> message;
    std::array<uint8_t, 5> expect_message{'h', 'e', 'l', 'l', 'o'};

    aead dec{aead::chacha20_poly1305};
    std::array<std::uint8_t, iv_size> iv{};

    dec.decrypt(key, iv, {}, ciphertext, message);
    ASSERT_EQ(message, expect_message);
}

TEST(aes_128_gcm, encrypt) {
    constexpr std::size_t key_size = aead::key_size(aead::aes_128_gcm);
    constexpr std::size_t tag_size = aead::tag_size(aead::aes_128_gcm);
    constexpr std::size_t iv_size = aead::iv_size(aead::aes_128_gcm);

    std::array<std::uint8_t, key_size> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<std::uint8_t, 5> message{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 5 + tag_size> ciphertext;
    std::array<std::uint8_t, 5 + tag_size> expect_ciphertext{
        155, 81, 62, 31, 73, 81, 203, 33, 80, 20, 82,
        166, 186, 215, 189, 136, 234, 215, 88, 8, 172};

    aead enc{aead::aes_128_gcm};
    std::array<std::uint8_t, iv_size> iv{};

    enc.encrypt(key, iv, {}, message, ciphertext);
    ASSERT_EQ(ciphertext, expect_ciphertext);
}

TEST(aes_128_gcm, decrypt) {
    constexpr std::size_t key_size = aead::key_size(aead::aes_128_gcm);
    constexpr std::size_t tag_size = aead::tag_size(aead::aes_128_gcm);
    constexpr std::size_t iv_size = aead::iv_size(aead::aes_128_gcm);

    std::array<uint8_t, key_size> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<uint8_t, 5 + tag_size> ciphertext{
        155, 81, 62, 31, 73, 81, 203, 33, 80, 20, 82,
        166, 186, 215, 189, 136, 234, 215, 88, 8, 172};
    std::array<uint8_t, 5> message;
    std::array<uint8_t, 5> expect_message{'h', 'e', 'l', 'l', 'o'};

    aead dec{aead::aes_128_gcm};
    std::array<std::uint8_t, iv_size> iv{};

    dec.decrypt(key, iv, {}, ciphertext, message);
    ASSERT_EQ(message, expect_message);
}

TEST(aes_256_gcm, encrypt) {
    constexpr std::size_t key_size = aead::key_size(aead::aes_256_gcm);
    constexpr std::size_t tag_size = aead::tag_size(aead::aes_256_gcm);
    constexpr std::size_t iv_size = aead::iv_size(aead::aes_256_gcm);

    std::array<std::uint8_t, key_size> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<std::uint8_t, 5> message{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 5 + tag_size> ciphertext;
    std::array<std::uint8_t, 5 + tag_size> expect_ciphertext{
        215, 80, 244, 176, 26, 211, 81, 171, 33, 189, 255,
        36, 184, 218, 230, 78, 146, 114, 221, 155, 24};

    aead enc{aead::aes_256_gcm};
    std::array<std::uint8_t, iv_size> iv{};

    enc.encrypt(key, iv, {}, message, ciphertext);
    ASSERT_EQ(ciphertext, expect_ciphertext);
}

TEST(aes_256_gcm, decrypt) {
    constexpr std::size_t key_size = aead::key_size(aead::aes_256_gcm);
    constexpr std::size_t tag_size = aead::tag_size(aead::aes_256_gcm);
    constexpr std::size_t iv_size = aead::iv_size(aead::aes_256_gcm);

    std::array<uint8_t, key_size> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<uint8_t, 5 + tag_size> ciphertext{
        215, 80, 244, 176, 26, 211, 81, 171, 33, 189, 255,
        36, 184, 218, 230, 78, 146, 114, 221, 155, 24};
    std::array<uint8_t, 5> message;
    std::array<uint8_t, 5> expect_message{'h', 'e', 'l', 'l', 'o'};

    aead dec{aead::aes_256_gcm};
    std::array<std::uint8_t, iv_size> iv{};

    dec.decrypt(key, iv, {}, ciphertext, message);
    ASSERT_EQ(message, expect_message);
}

TEST(deriveKey, key128) {
    std::array<std::uint8_t, 4> password{'h', 'e', 'h', 'e'};
    std::array<std::uint8_t, 16> key;
    std::array<std::uint8_t, 16> expectKey{82, 156, 168, 5, 10, 0, 24, 7, 144, 207, 136, 182, 52, 104, 130, 106};

    deriveKey(password, key);
    ASSERT_EQ(key, expectKey);
}

TEST(deriveKey, key256) {
    std::array<std::uint8_t, 4> password{'h', 'e', 'h', 'e'};
    std::array<std::uint8_t, 32> key;
    std::array<std::uint8_t, 32> expectKey{82, 156, 168, 5, 10, 0, 24, 7, 144, 207, 136, 182, 52, 104, 130, 106,
                                           109, 81, 225, 207, 24, 87, 148, 16, 101, 57, 172, 239, 219, 100, 183, 95};

    deriveKey(password, key);
    ASSERT_EQ(key, expectKey);
}

TEST(hkdf_sha1, key128) {
    std::array<std::uint8_t, 16> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<std::uint8_t, 16> salt{'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
    std::array<std::uint8_t, 16> subkey;
    std::array<std::uint8_t, 16> expect_subkey{176, 72, 135, 140, 255, 57, 14, 7, 193, 98, 58, 118, 112, 42, 119, 97};

    hkdf_sha1(key, salt, to_span("ss-subkey"), subkey);
    ASSERT_EQ(subkey, expect_subkey);
}

TEST(hkdf_sha1, key256) {
    std::array<std::uint8_t, 32> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<std::uint8_t, 32> salt{'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8',
                                      '1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
    std::array<std::uint8_t, 32> subkey;
    std::array<std::uint8_t, 32> expect_subkey{128, 145, 113, 44, 108, 52, 99, 117, 243, 229, 199, 245, 55, 99, 251, 53,
                                              56, 225, 92, 92, 5, 94, 252, 21, 4, 211, 164, 43, 251, 44, 61, 208};

    hkdf_sha1(key, salt, to_span("ss-subkey"), subkey);
    ASSERT_EQ(subkey, expect_subkey);
}

TEST(random, generate) {
    std::array<std::uint8_t, 32> bytes;
    random_bytes(bytes);
}
