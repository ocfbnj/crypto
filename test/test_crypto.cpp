#include <gtest/gtest.h>

#include <crypto/aead/AES128GCM.h>
#include <crypto/aead/AES256GCM.h>
#include <crypto/aead/ChaCha20Poly1305.h>
#include <crypto/codec/base64.h>
#include <crypto/crypto.h>
#include <crypto/md/SHA256.h>

using namespace ocfbnj::crypto;

TEST(increment, num0) {
    std::array<std::uint8_t, 2> num{0, 0};
    std::array<std::uint8_t, 2> expectNum{1, 0};

    increment(num);
    ASSERT_EQ(num, expectNum);
}

TEST(increment, num1) {
    std::array<std::uint8_t, 2> num{1, 0};
    std::array<std::uint8_t, 2> expectNum{2, 0};

    increment(num);
    ASSERT_EQ(num, expectNum);
}

TEST(increment, num255) {
    std::array<std::uint8_t, 2> num{255, 0};
    std::array<std::uint8_t, 2> expectNum{0, 1};

    increment(num);
    ASSERT_EQ(num, expectNum);
}

TEST(increment, num256) {
    std::array<std::uint8_t, 2> num{0, 1};
    std::array<std::uint8_t, 2> expectNum{1, 1};

    increment(num);
    ASSERT_EQ(num, expectNum);
}

TEST(toHexStream, empty) {
    ASSERT_EQ(toHexStream({}), "");
}

TEST(toHexStream, size16) {
    std::array<std::uint8_t, 16> bytes{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    ASSERT_EQ(toHexStream(bytes), "000102030405060708090a0b0c0d0e0f");
}

TEST(base64, encode) {
    ASSERT_EQ(toString(codec::base64::encode(toSpan("hello world"))), "aGVsbG8gd29ybGQ=");
}

TEST(base64, decode) {
    ASSERT_EQ(toString(codec::base64::decode(toSpan("aGVsbG8gd29ybGQ="))), "hello world");
}

TEST(sha256, get) {
    ASSERT_EQ(toHexStream(md::SHA256::get(toSpan("hello world"))), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

TEST(sha256, partial) {
    md::SHA256 sha256;

    sha256.update(toSpan("hello"));
    sha256.update(toSpan(" "));
    sha256.update(toSpan("world"));

    ASSERT_EQ(toHexStream(sha256.finish()), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

TEST(ChaCha20Poly1305, encrypt) {
    std::array<std::uint8_t, ChaCha20Poly1305::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<std::uint8_t, 5> message{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 5 + ChaCha20Poly1305::TagSize> ciphertext;
    std::array<std::uint8_t, 5 + ChaCha20Poly1305::TagSize> expectCiphertext{
        105, 66, 33, 189, 129, 203, 219, 231, 140, 85, 21,
        136, 140, 75, 200, 219, 165, 104, 17, 161, 79};

    std::unique_ptr<AEAD> enc = AEAD::create(AEAD::Method::ChaCha20Poly1305);
    std::array<std::uint8_t, aead::ChaCha20Poly1305::IvSize> iv{};

    enc->encrypt(key, iv, {}, message, ciphertext);
    ASSERT_EQ(ciphertext, expectCiphertext);
}

TEST(ChaCha20Poly1305, decrypt) {
    std::array<uint8_t, ChaCha20Poly1305::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<uint8_t, 5 + ChaCha20Poly1305::TagSize> ciphertext{
        105, 66, 33, 189, 129, 203, 219, 231, 140, 85, 21,
        136, 140, 75, 200, 219, 165, 104, 17, 161, 79};
    std::array<uint8_t, 5> message;
    std::array<uint8_t, 5> expectMessage{'h', 'e', 'l', 'l', 'o'};

    std::unique_ptr<AEAD> dec = AEAD::create(AEAD::Method::ChaCha20Poly1305);
    std::array<std::uint8_t, aead::ChaCha20Poly1305::IvSize> iv{};

    dec->decrypt(key, iv, {}, ciphertext, message);
    ASSERT_EQ(message, expectMessage);
}

TEST(AES128GCM, encrypt) {
    std::array<std::uint8_t, AES128GCM::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<std::uint8_t, 5> message{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 5 + AES128GCM::TagSize> ciphertext;
    std::array<std::uint8_t, 5 + AES128GCM::TagSize> expectCiphertext{
        155, 81, 62, 31, 73, 81, 203, 33, 80, 20, 82,
        166, 186, 215, 189, 136, 234, 215, 88, 8, 172};

    std::unique_ptr<AEAD> enc = AEAD::create(AEAD::Method::AES128GCM);
    std::array<std::uint8_t, aead::AES128GCM::IvSize> iv{};

    enc->encrypt(key, iv, {}, message, ciphertext);
    ASSERT_EQ(ciphertext, expectCiphertext);
}

TEST(AES128GCM, decrypt) {
    std::array<uint8_t, AES128GCM::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<uint8_t, 5 + AES128GCM::TagSize> ciphertext{
        155, 81, 62, 31, 73, 81, 203, 33, 80, 20, 82,
        166, 186, 215, 189, 136, 234, 215, 88, 8, 172};
    std::array<uint8_t, 5> message;
    std::array<uint8_t, 5> expectMessage{'h', 'e', 'l', 'l', 'o'};

    std::unique_ptr<AEAD> dec = AEAD::create(AEAD::Method::AES128GCM);
    std::array<std::uint8_t, aead::AES128GCM::IvSize> iv{};

    dec->decrypt(key, iv, {}, ciphertext, message);
    ASSERT_EQ(message, expectMessage);
}

TEST(AES256GCM, encrypt) {
    std::array<std::uint8_t, AES256GCM::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<std::uint8_t, 5> message{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 5 + AES256GCM::TagSize> ciphertext;
    std::array<std::uint8_t, 5 + AES256GCM::TagSize> expectCiphertext{
        215, 80, 244, 176, 26, 211, 81, 171, 33, 189, 255,
        36, 184, 218, 230, 78, 146, 114, 221, 155, 24};

    std::unique_ptr<AEAD> enc = AEAD::create(AEAD::Method::AES256GCM);
    std::array<std::uint8_t, aead::AES256GCM::IvSize> iv{};

    enc->encrypt(key, iv, {}, message, ciphertext);
    ASSERT_EQ(ciphertext, expectCiphertext);
}

TEST(AES256GCM, decrypt) {
    std::array<uint8_t, AES256GCM::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<uint8_t, 5 + AES256GCM::TagSize> ciphertext{
        215, 80, 244, 176, 26, 211, 81, 171, 33, 189, 255,
        36, 184, 218, 230, 78, 146, 114, 221, 155, 24};
    std::array<uint8_t, 5> message;
    std::array<uint8_t, 5> expectMessage{'h', 'e', 'l', 'l', 'o'};

    std::unique_ptr<AEAD> dec = AEAD::create(AEAD::Method::AES256GCM);
    std::array<std::uint8_t, aead::AES256GCM::IvSize> iv{};

    dec->decrypt(key, iv, {}, ciphertext, message);
    ASSERT_EQ(message, expectMessage);
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

TEST(hkdfSha1, key128) {
    std::array<std::uint8_t, 16> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<std::uint8_t, 16> salt{'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
    std::array<std::uint8_t, 16> subkey;
    std::array<std::uint8_t, 16> expectSubkey{176, 72, 135, 140, 255, 57, 14, 7, 193, 98, 58, 118, 112, 42, 119, 97};

    hkdfSha1(key, salt, toSpan("ss-subkey"), subkey);
    ASSERT_EQ(subkey, expectSubkey);
}

TEST(hkdfSha1, key256) {
    std::array<std::uint8_t, 32> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<std::uint8_t, 32> salt{'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8',
                                      '1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
    std::array<std::uint8_t, 32> subkey;
    std::array<std::uint8_t, 32> expectSubkey{128, 145, 113, 44, 108, 52, 99, 117, 243, 229, 199, 245, 55, 99, 251, 53,
                                              56, 225, 92, 92, 5, 94, 252, 21, 4, 211, 164, 43, 251, 44, 61, 208};

    hkdfSha1(key, salt, toSpan("ss-subkey"), subkey);
    ASSERT_EQ(subkey, expectSubkey);
}
