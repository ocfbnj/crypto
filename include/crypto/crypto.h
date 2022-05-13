#ifndef OCFBNJ_CYRPTO_CRYPTO_H
#define OCFBNJ_CYRPTO_CRYPTO_H

#include <cstdint>
#include <span>
#include <string>

namespace crypto {
// increment increment the number (little endian) by one.
void increment(std::span<std::uint8_t> num);

// to_hex_stream converts a bytes sequence to hex representation (lowercase).
std::string to_hex_stream(std::span<const std::uint8_t> str);

// to_span converts a std::string to std::span
std::span<const std::uint8_t> to_span(const std::string& str);

// to_string converts a std::span to std::string
std::string to_string(std::span<const std::uint8_t> str);

// deriveKey generate the master key from a password.
void deriveKey(std::span<const std::uint8_t> password, std::span<std::uint8_t> key);

// hkdf_sha1 produces a subkey that is cryptographically strong even if the input secret key is weak.
void hkdf_sha1(std::span<const std::uint8_t> key,
               std::span<const std::uint8_t> salt,
               std::span<const std::uint8_t> info,
               std::span<std::uint8_t> subkey);

// random_bytes generate random bytes.
void random_bytes(std::span<std::uint8_t> bytes);
} // namespace crypto

#endif
