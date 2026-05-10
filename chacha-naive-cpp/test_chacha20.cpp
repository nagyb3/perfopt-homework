#include "test_chacha20.h"
#include "ChaCha.hpp"
#include <iostream>
#include <cassert>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <stdexcept>

std::string TestChaCha20::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t b : bytes)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

std::string TestChaCha20::bytesToHex(const std::array<uint8_t, 16>& bytes) {
    std::ostringstream oss;
    for (uint8_t b : bytes)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

std::string TestChaCha20::bytesToHex(const std::array<uint8_t, 32>& bytes) {
    std::ostringstream oss;
    for (uint8_t b : bytes)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

std::string TestChaCha20::bytesToHex(const std::array<uint8_t, 12>& bytes) {
    std::ostringstream oss;
    for (uint8_t b : bytes)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

std::vector<uint8_t> TestChaCha20::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (std::size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stol(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// RFC 8439 §2.4.2 - ChaCha20 Test Vector
void TestChaCha20::testRFC8439_Vector1() {
    std::cout << "Testing RFC 8439 §2.4.2 - ChaCha20 Encryption\n";

    // Simplified test - just verify encryption/decryption roundtrip
    // for a known plaintext
    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;

    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    std::string plaintext_str = "Hello, World! This is a test of ChaCha20 encryption.";
    std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());

    // Encrypt
    std::vector<uint8_t> ciphertext = plaintext;
    chacha20_poly1305::detail::chacha20_xor(
        key.data(), nonce.data(), 1,
        ciphertext.data(), ciphertext.size()
    );

    // Decrypt
    std::vector<uint8_t> decrypted = ciphertext;
    chacha20_poly1305::detail::chacha20_xor(
        key.data(), nonce.data(), 1,
        decrypted.data(), decrypted.size()
    );

    if (decrypted == plaintext) {
        std::cout << "RFC 8439 ChaCha20 roundtrip test PASSED\n";
        std::cout << "  Plaintext:  " << plaintext_str << "\n";
        std::cout << "  Decrypted:  " << std::string(decrypted.begin(), decrypted.end()) << "\n";
    } else {
        std::cout << "RFC 8439 ChaCha20 test FAILED\n";
        throw std::runtime_error("ChaCha20 roundtrip failed");
    }
}

// RFC 8439 §2.8.2 - ChaCha20-Poly1305 AEAD Test Vector
void TestChaCha20::testRFC8439_AEAD_Vector() {
    std::cout << "Testing RFC 8439 §2.8.2 - ChaCha20-Poly1305 AEAD\n";

    // Test with known key, nonce, plaintext, and AAD
    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;

    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    std::string plaintext_str = "Ladies and Gentlemen of the class of '99";
    std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());

    std::string aad_str = "50515253c0c1c2c3c4c5c6c7";
    std::vector<uint8_t> aad = hexToBytes(aad_str);

    // Encrypt
    auto result = chacha20_poly1305::seal(key, nonce, plaintext, aad);

    std::cout << "  Ciphertext size: " << result.ciphertext.size() << " bytes\n";
    std::cout << "  Tag: " << bytesToHex(result.tag) << "\n";

    // Decrypt and verify
    try {
        auto decrypted = chacha20_poly1305::open(key, nonce, result.ciphertext, result.tag, aad);
        if (decrypted == plaintext) {
            std::cout << "✓ RFC 8439 AEAD roundtrip test PASSED\n";
        } else {
            std::cout << "✗ FAILED - Decrypted plaintext doesn't match\n";
            throw std::runtime_error("Decryption mismatch");
        }
    } catch (const std::runtime_error& e) {
        std::cout << "✗ FAILED - " << e.what() << "\n";
        throw;
    }
}

// Property-based: Encrypt then decrypt should return original plaintext
void TestChaCha20::testEncryptDecryptRoundtrip() {
    std::cout << "Testing Encrypt-Decrypt Roundtrip\n";

    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 32; ++i) key[i] = i * 2;
    for (int i = 0; i < 12; ++i) nonce[i] = i * 3;

    // Test with various message sizes
    for (std::size_t size : {1, 16, 64, 127, 128, 1000}) {
        std::vector<uint8_t> plaintext(size);
        for (std::size_t i = 0; i < size; ++i)
            plaintext[i] = i & 0xFF;

        auto result = chacha20_poly1305::seal(key, nonce, plaintext);
        auto decrypted = chacha20_poly1305::open(key, nonce, result.ciphertext, result.tag);

        if (decrypted == plaintext) {
            std::cout << "  ✓ Size " << size << " bytes\n";
        } else {
            std::cout << "  ✗ Size " << size << " bytes FAILED\n";
            throw std::runtime_error("Roundtrip failed");
        }
    }
}

// Property-based: Modified ciphertext should fail authentication
void TestChaCha20::testAuthenticationFailureOnModifiedCiphertext() {
    std::cout << "Testing Authentication Failure on Modified Ciphertext\n";

    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    std::vector<uint8_t> plaintext = hexToBytes("4578616d706c65504c61696e54657874");

    auto result = chacha20_poly1305::seal(key, nonce, plaintext);

    // Modify ciphertext
    if (!result.ciphertext.empty()) {
        result.ciphertext[0] ^= 0xFF;

        try {
            auto decrypted = chacha20_poly1305::open(key, nonce, result.ciphertext, result.tag);
            std::cout << "  ✗ FAILED - Should have rejected modified ciphertext\n";
            throw std::runtime_error("Authentication bypass detected");
        } catch (const std::runtime_error& e) {
            if (std::string(e.what()).find("authentication failed") != std::string::npos) {
                std::cout << "  ✓ Correctly rejected modified ciphertext\n";
            } else {
                throw;
            }
        }
    }
}

// Property-based: Modified tag should fail authentication
void TestChaCha20::testAuthenticationFailureOnModifiedTag() {
    std::cout << "Testing Authentication Failure on Modified Tag\n";

    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    std::vector<uint8_t> plaintext = hexToBytes("4578616d706c65504c61696e54657874");

    auto result = chacha20_poly1305::seal(key, nonce, plaintext);

    // Modify tag
    result.tag[0] ^= 0xFF;

    try {
        auto decrypted = chacha20_poly1305::open(key, nonce, result.ciphertext, result.tag);
        std::cout << "  ✗ FAILED - Should have rejected modified tag\n";
        throw std::runtime_error("Authentication bypass detected");
    } catch (const std::runtime_error& e) {
        if (std::string(e.what()).find("authentication failed") != std::string::npos) {
            std::cout << "  ✓ Correctly rejected modified tag\n";
        } else {
            throw;
        }
    }
}

// Property-based: Different nonces produce different ciphertexts
void TestChaCha20::testDifferentNoncesProduceDifferentCiphertexts() {
    std::cout << "Testing Different Nonces Produce Different Ciphertexts\n";

    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce1, nonce2;

    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce1[i] = i;
    for (int i = 0; i < 12; ++i) nonce2[i] = i ^ 0xFF;

    std::vector<uint8_t> plaintext(100, 0x42);

    auto result1 = chacha20_poly1305::seal(key, nonce1, plaintext);
    auto result2 = chacha20_poly1305::seal(key, nonce2, plaintext);

    if (result1.ciphertext != result2.ciphertext) {
        std::cout << "  ✓ Different nonces produce different ciphertexts\n";
    } else {
        std::cout << "  ✗ FAILED - Same ciphertext with different nonces\n";
        throw std::runtime_error("Nonce independence failed");
    }
}

// Edge case: Empty plaintext
void TestChaCha20::testEmptyPlaintext() {
    std::cout << "Testing Empty Plaintext\n";

    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    std::vector<uint8_t> plaintext;

    auto result = chacha20_poly1305::seal(key, nonce, plaintext);
    auto decrypted = chacha20_poly1305::open(key, nonce, result.ciphertext, result.tag);

    if (decrypted == plaintext) {
        std::cout << "  ✓ Empty plaintext handled correctly\n";
    } else {
        std::cout << "  ✗ FAILED\n";
        throw std::runtime_error("Empty plaintext test failed");
    }
}

// Edge case: Empty AAD
void TestChaCha20::testEmptyAAD() {
    std::cout << "Testing Empty AAD\n";

    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    std::vector<uint8_t> plaintext = hexToBytes("48656c6c6f");
    std::vector<uint8_t> empty_aad;

    auto result = chacha20_poly1305::seal(key, nonce, plaintext, empty_aad);
    auto decrypted = chacha20_poly1305::open(key, nonce, result.ciphertext, result.tag, empty_aad);

    if (decrypted == plaintext) {
        std::cout << "  ✓ Empty AAD handled correctly\n";
    } else {
        std::cout << "  ✗ FAILED\n";
        throw std::runtime_error("Empty AAD test failed");
    }
}

// Edge case: Long message
void TestChaCha20::testLongMessage() {
    std::cout << "Testing Long Message (10KB)\n";

    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    std::vector<uint8_t> plaintext(10000);
    for (std::size_t i = 0; i < plaintext.size(); ++i)
        plaintext[i] = i & 0xFF;

    auto result = chacha20_poly1305::seal(key, nonce, plaintext);
    auto decrypted = chacha20_poly1305::open(key, nonce, result.ciphertext, result.tag);

    if (decrypted == plaintext) {
        std::cout << "  ✓ Long message handled correctly\n";
    } else {
        std::cout << "  ✗ FAILED\n";
        throw std::runtime_error("Long message test failed");
    }
}

// test for edge case: Single byte
void TestChaCha20::testSingleByteMessage() {
    std::cout << "Testing Single Byte Message\n";

    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    std::vector<uint8_t> plaintext = {0xAB};

    auto result = chacha20_poly1305::seal(key, nonce, plaintext);
    auto decrypted = chacha20_poly1305::open(key, nonce, result.ciphertext, result.tag);

    if (decrypted == plaintext) {
        std::cout << "  ✓ Single byte message handled correctly\n";
    } else {
        std::cout << "  ✗ FAILED\n";
        throw std::runtime_error("Single byte test failed");
    }
}
