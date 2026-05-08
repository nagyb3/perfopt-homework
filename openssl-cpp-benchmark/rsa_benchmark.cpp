#include <benchmark/benchmark.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <random>
#include <stdexcept>
#include <vector>

namespace {

constexpr int kKeyBits = 2048;
constexpr std::size_t kDataSize = 32;

template <std::size_t N>
void FillRandomBytes(std::array<unsigned char, N>& buffer) {
	std::random_device device;
	std::mt19937_64 rng(device());
	std::uniform_int_distribution dist(0, 255);
	for (auto &b : buffer) b = static_cast<unsigned char>(dist(rng));
}

class RSABenchmark : public benchmark::Fixture {
protected:
	EVP_PKEY* pkey_ = nullptr;
	EVP_PKEY_CTX* encrypt_ctx_ = nullptr;
	EVP_PKEY_CTX* decrypt_ctx_ = nullptr;
	std::array<unsigned char, kDataSize> plaintext_{};
	std::vector<unsigned char> ciphertext_{};

	void SetUp(const ::benchmark::State&) override {
		FillRandomBytes(plaintext_);

		EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
		if (!kctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
		if (EVP_PKEY_keygen_init(kctx) <= 0) {
			EVP_PKEY_CTX_free(kctx);
			throw std::runtime_error("EVP_PKEY_keygen_init failed");
		}
		if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, kKeyBits) <= 0) {
			EVP_PKEY_CTX_free(kctx);
			throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
		}
		if (EVP_PKEY_keygen(kctx, &pkey_) <= 0 || pkey_ == nullptr) {
			EVP_PKEY_CTX_free(kctx);
			throw std::runtime_error("EVP_PKEY_keygen failed");
		}
		EVP_PKEY_CTX_free(kctx);

		EVP_PKEY_CTX* ectx = EVP_PKEY_CTX_new(pkey_, nullptr);
		if (!ectx) throw std::runtime_error("EVP_PKEY_CTX_new encrypt failed");
		if (EVP_PKEY_encrypt_init(ectx) <= 0) {
			EVP_PKEY_CTX_free(ectx);
			throw std::runtime_error("EVP_PKEY_encrypt_init failed");
		}
		if (EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_PKCS1_OAEP_PADDING) <= 0) {
			EVP_PKEY_CTX_free(ectx);
			throw std::runtime_error("Setting RSA OAEP padding failed");
		}
		if (EVP_PKEY_CTX_set_rsa_oaep_md(ectx, EVP_sha256()) <= 0) {
			EVP_PKEY_CTX_free(ectx);
			throw std::runtime_error("Setting OAEP MD failed");
		}
		if (EVP_PKEY_CTX_set_rsa_mgf1_md(ectx, EVP_sha256()) <= 0) {
			EVP_PKEY_CTX_free(ectx);
			throw std::runtime_error("Setting MGF1 MD failed");
		}

		size_t outlen = 0;
		if (EVP_PKEY_encrypt(ectx, nullptr, &outlen, plaintext_.data(), static_cast<size_t>(plaintext_.size())) <= 0) {
			EVP_PKEY_CTX_free(ectx);
			throw std::runtime_error("EVP_PKEY_encrypt sizing failed");
		}
		ciphertext_.resize(outlen);
		if (EVP_PKEY_encrypt(ectx, ciphertext_.data(), &outlen, plaintext_.data(), static_cast<size_t>(plaintext_.size())) <= 0) {
			EVP_PKEY_CTX_free(ectx);
			throw std::runtime_error("EVP_PKEY_encrypt failed");
		}
		ciphertext_.resize(outlen);
		EVP_PKEY_CTX_free(ectx);


		EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(pkey_, nullptr);
		if (!dctx) throw std::runtime_error("EVP_PKEY_CTX_new decrypt failed");
		if (EVP_PKEY_decrypt_init(dctx) <= 0) {
			EVP_PKEY_CTX_free(dctx);
			throw std::runtime_error("EVP_PKEY_decrypt_init failed");
		}
		if (EVP_PKEY_CTX_set_rsa_padding(dctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
			EVP_PKEY_CTX_free(dctx);
			throw std::runtime_error("Setting RSA OAEP padding failed (decrypt)");
		}
		if (EVP_PKEY_CTX_set_rsa_oaep_md(dctx, EVP_sha256()) <= 0) {
			EVP_PKEY_CTX_free(dctx);
			throw std::runtime_error("Setting OAEP MD failed (decrypt)");
		}
		if (EVP_PKEY_CTX_set_rsa_mgf1_md(dctx, EVP_sha256()) <= 0) {
			EVP_PKEY_CTX_free(dctx);
			throw std::runtime_error("Setting MGF1 MD failed (decrypt)");
		}

		size_t declen = 0;
		if (EVP_PKEY_decrypt(dctx, nullptr, &declen, ciphertext_.data(), ciphertext_.size()) <= 0) {
			EVP_PKEY_CTX_free(dctx);
			throw std::runtime_error("EVP_PKEY_decrypt sizing failed");
		}
		std::vector<unsigned char> decrypted(declen);
		if (EVP_PKEY_decrypt(dctx, decrypted.data(), &declen, ciphertext_.data(), ciphertext_.size()) <= 0) {
			EVP_PKEY_CTX_free(dctx);
			throw std::runtime_error("EVP_PKEY_decrypt failed");
		}
		decrypted.resize(declen);
		EVP_PKEY_CTX_free(dctx);

		if (decrypted.size() != plaintext_.size() || std::memcmp(decrypted.data(), plaintext_.data(), plaintext_.size()) != 0) {
			throw std::runtime_error("RSA setup verification failed");
		}

		// create persistent encryption context:
		encrypt_ctx_ = EVP_PKEY_CTX_new(pkey_, nullptr);
		if (!encrypt_ctx_) throw std::runtime_error("EVP_PKEY_CTX_new encrypt failed (persistent)");
		if (EVP_PKEY_encrypt_init(encrypt_ctx_) <= 0) {
			EVP_PKEY_CTX_free(encrypt_ctx_);
			throw std::runtime_error("EVP_PKEY_encrypt_init failed (persistent)");
		}
		if (EVP_PKEY_CTX_set_rsa_padding(encrypt_ctx_, RSA_PKCS1_OAEP_PADDING) <= 0 ||
			EVP_PKEY_CTX_set_rsa_oaep_md(encrypt_ctx_, EVP_sha256()) <= 0 ||
			EVP_PKEY_CTX_set_rsa_mgf1_md(encrypt_ctx_, EVP_sha256()) <= 0) {
			EVP_PKEY_CTX_free(encrypt_ctx_);
			throw std::runtime_error("Setting OAEP params failed (persistent encrypt)");
		}

		// create persistent decryption context:
		decrypt_ctx_ = EVP_PKEY_CTX_new(pkey_, nullptr);
		if (!decrypt_ctx_) throw std::runtime_error("EVP_PKEY_CTX_new decrypt failed (persistent)");
		if (EVP_PKEY_decrypt_init(decrypt_ctx_) <= 0) {
			EVP_PKEY_CTX_free(decrypt_ctx_);
			throw std::runtime_error("EVP_PKEY_decrypt_init failed (persistent)");
		}
		if (EVP_PKEY_CTX_set_rsa_padding(decrypt_ctx_, RSA_PKCS1_OAEP_PADDING) <= 0 ||
			EVP_PKEY_CTX_set_rsa_oaep_md(decrypt_ctx_, EVP_sha256()) <= 0 ||
			EVP_PKEY_CTX_set_rsa_mgf1_md(decrypt_ctx_, EVP_sha256()) <= 0) {
			EVP_PKEY_CTX_free(decrypt_ctx_);
			throw std::runtime_error("Setting OAEP params failed (persistent decrypt)");
		}
	}

	void TearDown(const ::benchmark::State&) override {
		if (encrypt_ctx_) {
			EVP_PKEY_CTX_free(encrypt_ctx_);
			encrypt_ctx_ = nullptr;
		}
		if (decrypt_ctx_) {
			EVP_PKEY_CTX_free(decrypt_ctx_);
			decrypt_ctx_ = nullptr;
		}
		if (pkey_) {
			EVP_PKEY_free(pkey_);
			pkey_ = nullptr;
		}
	}
};

BENCHMARK_DEFINE_F(RSABenchmark, Encrypt)(benchmark::State& state) {
	std::vector<unsigned char> outbuf(EVP_PKEY_size(pkey_));
	size_t outlen = outbuf.size();

	for (auto _ : state) {
		outlen = outbuf.size();
		if (EVP_PKEY_encrypt(encrypt_ctx_, outbuf.data(), &outlen, plaintext_.data(), plaintext_.size()) <= 0) {
			state.SkipWithError("EVP_PKEY_encrypt failed in benchmark");
			break;
		}
		benchmark::DoNotOptimize(outbuf.data());
		benchmark::ClobberMemory();
	}

	state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(plaintext_.size()));
}

BENCHMARK_DEFINE_F(RSABenchmark, Decrypt)(benchmark::State& state) {
	std::vector<unsigned char> outbuf(EVP_PKEY_size(pkey_));
	size_t outlen = outbuf.size();

	for (auto _ : state) {
		outlen = outbuf.size();
		if (EVP_PKEY_decrypt(decrypt_ctx_, outbuf.data(), &outlen, ciphertext_.data(), ciphertext_.size()) <= 0) {
			state.SkipWithError("EVP_PKEY_decrypt failed in benchmark");
			break;
		}
		benchmark::DoNotOptimize(outbuf.data());
		benchmark::ClobberMemory();
	}

	state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(kDataSize));
}

BENCHMARK_REGISTER_F(RSABenchmark, Encrypt);
BENCHMARK_REGISTER_F(RSABenchmark, Decrypt);

} // namespace

