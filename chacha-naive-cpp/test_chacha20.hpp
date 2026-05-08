#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include <string>

class TestChaCha20 {
public:
    // RFC 8439 §2.4.2 Test Vector
    static void testRFC8439_Vector1();

    // RFC 8439 §2.8.2 AEAD Test Vector
    static void testRFC8439_AEAD_Vector();

    // property-based tests:
    static void testEncryptDecryptRoundtrip();
    static void testAuthenticationFailureOnModifiedCiphertext();
    static void testAuthenticationFailureOnModifiedTag();
    static void testDifferentNoncesProduceDifferentCiphertexts();

    // edge case tests
    static void testEmptyPlaintext();
    static void testEmptyAAD();
    static void testLongMessage();
    static void testSingleByteMessage();

    // helpers:
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);
    static std::string bytesToHex(const std::array<uint8_t, 16>& bytes);
    static std::string bytesToHex(const std::array<uint8_t, 32>& bytes);
    static std::string bytesToHex(const std::array<uint8_t, 12>& bytes);

    static std::vector<uint8_t> hexToBytes(const std::string& hex);
};
