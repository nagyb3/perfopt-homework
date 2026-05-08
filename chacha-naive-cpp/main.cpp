#include "test_chacha20.h"
#include "ChaCha.hpp"
#include <iostream>
#include <benchmark/benchmark.h>

void runAllTests() {
    std::cout << "=" << std::string(60, '=') << "\n";
    std::cout << "Running ChaCha20-Poly1305 Test Suite\n";
    std::cout << "=" << std::string(60, '=') << "\n\n";

    try {
        // RFC 8439 test vectors
        TestChaCha20::testRFC8439_Vector1();
        std::cout << "\n";

        TestChaCha20::testRFC8439_AEAD_Vector();
        std::cout << "\n";

        // Property-based tests
        TestChaCha20::testEncryptDecryptRoundtrip();
        std::cout << "\n";

        TestChaCha20::testAuthenticationFailureOnModifiedCiphertext();
        std::cout << "\n";

        TestChaCha20::testAuthenticationFailureOnModifiedTag();
        std::cout << "\n";

        TestChaCha20::testDifferentNoncesProduceDifferentCiphertexts();
        std::cout << "\n";

        // Edge cases
        TestChaCha20::testEmptyPlaintext();
        std::cout << "\n";

        TestChaCha20::testEmptyAAD();
        std::cout << "\n";

        TestChaCha20::testLongMessage();
        std::cout << "\n";

        TestChaCha20::testSingleByteMessage();
        std::cout << "\n";

        std::cout << "=" << std::string(60, '=') << "\n";
        std::cout << "✓ All tests passed!\n";
        std::cout << "=" << std::string(60, '=') << "\n\n";

    } catch (const std::exception& e) {
        std::cout << "\n" << "=" << std::string(60, '=') << "\n";
        std::cout << "✗ Test failed: " << e.what() << "\n";
        std::cout << "=" << std::string(60, '=') << "\n";
        exit(1);
    }
}

static void BM_ChaCha20Encrypt(benchmark::State& state) {
    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    std::size_t msg_size = state.range(0);
    std::vector<uint8_t> plaintext(msg_size, 0x42);

    for (auto _ : state) {
        auto result = chacha20_poly1305::seal(key, nonce, plaintext);
        benchmark::DoNotOptimize(result);
    }

    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(msg_size));
}

static void BM_ChaCha20Decrypt(benchmark::State& state) {
    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    std::size_t msg_size = state.range(0);
    std::vector<uint8_t> plaintext(msg_size, 0x42);

    // Pre-generate ciphertext
    auto result = chacha20_poly1305::seal(key, nonce, plaintext);

    for (auto _ : state) {
        auto decrypted = chacha20_poly1305::open(key, nonce, result.ciphertext, result.tag);
        benchmark::DoNotOptimize(decrypted);
    }

    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(msg_size));
}

BENCHMARK(BM_ChaCha20Encrypt)->Arg(1024);
BENCHMARK(BM_ChaCha20Decrypt)->Arg(1024);

int main(int argc, char** argv) {
    runAllTests();

    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}


