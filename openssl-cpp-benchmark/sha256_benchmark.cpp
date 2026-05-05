#include <benchmark/benchmark.h>

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <random>
#include <stdexcept>

namespace {

constexpr std::size_t DATA_SIZE = 1024;
constexpr std::size_t DIGEST_SIZE = 32;

template <std::size_t N>
void FillRandomBytes(std::array<unsigned char, N>& buffer) {
    std::random_device device;
    std::mt19937_64 rng(device());
    std::uniform_int_distribution dist(0, 255);
    for (auto &b : buffer) b = static_cast<unsigned char>(dist(rng));
}

class SHA256Benchmark : public benchmark::Fixture {
protected:
    std::array<unsigned char, DATA_SIZE> plaintext_{};
    std::array<unsigned char, DIGEST_SIZE> baseline_single_{};
    std::array<unsigned char, DIGEST_SIZE> baseline_stream_{};

    void SetUp(const ::benchmark::State&) override {
        FillRandomBytes(plaintext_);

        unsigned int outlen = 0;

        if (EVP_Digest(plaintext_.data(), plaintext_.size(), baseline_single_.data(), &outlen, EVP_sha256(), nullptr) != 1) {
            throw std::runtime_error("EVP_Digest single-shot failed");
        }
        if (outlen != DIGEST_SIZE) throw std::runtime_error("Unexpected digest length (single-shot)");
        
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestInit_ex failed");
        }
        if (EVP_DigestUpdate(ctx, plaintext_.data(), plaintext_.size()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
        if (EVP_DigestFinal_ex(ctx, baseline_stream_.data(), &outlen) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestFinal_ex failed");
        }
        EVP_MD_CTX_free(ctx);
        if (outlen != DIGEST_SIZE) throw std::runtime_error("Unexpected digest length (stream)");

        if (baseline_single_ != baseline_stream_) throw std::runtime_error("SHA256 setup verification failed: digests differ");
    }
};

BENCHMARK_DEFINE_F(SHA256Benchmark, SingleShot)(benchmark::State& state) {
    std::array<unsigned char, DIGEST_SIZE> out{};
    unsigned int outlen = 0;
    for ([[maybe_unused]] auto _ : state) {
        if (EVP_Digest(plaintext_.data(), plaintext_.size(), out.data(), &outlen, EVP_sha256(), nullptr) != 1) {
            state.SkipWithError("EVP_Digest single-shot failed");
            break;
        }
        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(plaintext_.size()));
}

BENCHMARK_DEFINE_F(SHA256Benchmark, Streaming)(benchmark::State& state) {
    std::array<unsigned char, DIGEST_SIZE> out{};
    unsigned int outlen = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        state.SkipWithError("EVP_MD_CTX_new failed");
        return;
    }

    for ([[maybe_unused]] auto _ : state) {
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            state.SkipWithError("EVP_DigestInit_ex failed");
            break;
        }
        if (EVP_DigestUpdate(ctx, plaintext_.data(), plaintext_.size()) != 1) {
            state.SkipWithError("EVP_DigestUpdate failed");
            break;
        }
        if (EVP_DigestFinal_ex(ctx, out.data(), &outlen) != 1) {
            state.SkipWithError("EVP_DigestFinal_ex failed");
            break;
        }

        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }

    EVP_MD_CTX_free(ctx);
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(plaintext_.size()));
}

BENCHMARK_REGISTER_F(SHA256Benchmark, SingleShot);
BENCHMARK_REGISTER_F(SHA256Benchmark, Streaming);

} // namespace

