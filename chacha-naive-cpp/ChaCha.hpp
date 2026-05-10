#pragma once

#include <array>
#include <cstring>
#include <span>

// quarter round operations:
#define QR(a,b,c,d) \
a += b; d ^= a; d = rotl32(d,16); \
c += d; b ^= c; b = rotl32(b,12); \
a += b; d ^= a; d = rotl32(d, 8); \
c += d; b ^= c; b = rotl32(b, 7)


namespace chacha20_poly1305 {
    namespace detail {
        inline uint32_t load32_le(const uint8_t *p) noexcept {
            return static_cast<uint32_t>(p[0])
                   | static_cast<uint32_t>(p[1]) << 8
                   | static_cast<uint32_t>(p[2]) << 16
                   | static_cast<uint32_t>(p[3]) << 24;
        }

        inline uint64_t load64_le(const uint8_t *p) noexcept {
            return static_cast<uint64_t>(load32_le(p))
                   | static_cast<uint64_t>(load32_le(p + 4)) << 32;
        }

        inline void store32_le(uint8_t *p, uint32_t v) noexcept {
            p[0] = static_cast<uint8_t>(v);
            p[1] = static_cast<uint8_t>(v >> 8);
            p[2] = static_cast<uint8_t>(v >> 16);
            p[3] = static_cast<uint8_t>(v >> 24);
        }

        inline void store64_le(uint8_t *p, uint64_t v) noexcept {
            store32_le(p, static_cast<uint32_t>(v));
            store32_le(p + 4, static_cast<uint32_t>(v >> 32));
        }

        inline uint32_t rotl32(uint32_t v, int n) noexcept {
            return (v << n) | (v >> (32 - n));
        }

        // Produce one 64-byte ChaCha20 block into `out[64]`.
        inline void chacha20_block(const uint32_t state[16], uint8_t out[64]) noexcept {
            uint32_t x[16];
            std::memcpy(x, state, 64);

            for (int i = 0; i < 10; ++i) {
                // Column rounds
                QR(x[0], x[4], x[8], x[12]);
                QR(x[1], x[5], x[9], x[13]);
                QR(x[2], x[6], x[10], x[14]);
                QR(x[3], x[7], x[11], x[15]);
                // Diagonal rounds
                QR(x[0], x[5], x[10], x[15]);
                QR(x[1], x[6], x[11], x[12]);
                QR(x[2], x[7], x[ 8], x[13]);
                QR(x[3], x[4], x[ 9], x[14]);
            }

            for (int i = 0; i < 16; ++i)
                store32_le(out + 4 * i, x[i] + state[i]);
        }

#undef QR

        // key: 32 bytes, nonce: 12 bytes, counter: block counter (0 for keystream gen)
        inline void chacha20_init(uint32_t state[16],
                                  const uint8_t key[32],
                                  const uint8_t nonce[12],
                                  uint32_t counter) noexcept {
            // the first row is the constants:
            // "expa", "nd 3", "2-by", "te k"
            state[0] = 0x61707865u;
            state[1] = 0x3320646eu;
            state[2] = 0x79622d32u;
            state[3] = 0x6b206574u;
            for (int i = 0; i < 8; ++i)
                state[4 + i] = load32_le(key + 4 * i);
            state[12] = counter;
            state[13] = load32_le(nonce);
            state[14] = load32_le(nonce + 4);
            state[15] = load32_le(nonce + 8);
        }

        // xor the data with ChaCha20 keystream.
        // counter starts at 1 for message encryption; 0 for Poly1305 key generation.
        inline void chacha20_xor(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 uint32_t counter,
                                 uint8_t *data,
                                 std::size_t len) noexcept {
            uint32_t state[16];
            chacha20_init(state, key, nonce, counter);

            uint8_t block[64];
            std::size_t offset = 0;

            while (offset < len) {
                chacha20_block(state, block);
                ++state[12]; // increment block counter

                std::size_t chunk = std::min<std::size_t>(64, len - offset);
                for (std::size_t i = 0; i < chunk; ++i)
                    data[offset + i] ^= block[i];
                offset += chunk;
            }
            // Zeroize sensitive block data
            std::memset(block, 0, sizeof(block));
        }

        // Poly1305 state uses 130-bit accumulator stored in five 26-bit limbs.
        struct Poly1305 {
            uint32_t h[5]{0};
            uint32_t r[5]{0};
            uint32_t s[4]{0}; // Pad stored as four 32-bit words for easier addition

            void init(const uint8_t key[32]) noexcept {
                // 1. Clamp the 'r' part of the key (first 16 bytes) per RFC 8439
                uint8_t clamped_r[16];
                std::memcpy(clamped_r, key, 16);
                clamped_r[3] &= 15;
                clamped_r[7] &= 15;
                clamped_r[11] &= 15;
                clamped_r[15] &= 15;
                clamped_r[4] &= 252;
                clamped_r[8] &= 252;
                clamped_r[12] &= 252;

                // 2. Load clamped 'r' into 26-bit limbs
                uint64_t r0 = load64_le(clamped_r);
                uint64_t r1 = load64_le(clamped_r + 8);
                r[0] = static_cast<uint32_t>(r0) & 0x3ffffff;
                r[1] = static_cast<uint32_t>(r0 >> 26) & 0x3ffffff;
                r[2] = static_cast<uint32_t>((r0 >> 52) | (r1 << 12)) & 0x3ffffff;
                r[3] = static_cast<uint32_t>(r1 >> 14) & 0x3ffffff;
                r[4] = static_cast<uint32_t>(r1 >> 40) & 0x3ffffff;

                // 3. Store the 's' part (the pad)
                s[0] = load32_le(key + 16);
                s[1] = load32_le(key + 20);
                s[2] = load32_le(key + 24);
                s[3] = load32_le(key + 28);

                std::memset(h, 0, sizeof(h));
            }

            void block(const uint8_t *msg, bool pad_bit) noexcept {
                uint64_t t0 = load64_le(msg);
                uint64_t t1 = load64_le(msg + 8);

                uint32_t m[5];
                m[0] = static_cast<uint32_t>(t0) & 0x3ffffff;
                m[1] = static_cast<uint32_t>(t0 >> 26) & 0x3ffffff;
                m[2] = static_cast<uint32_t>((t0 >> 52) | (t1 << 12)) & 0x3ffffff;
                m[3] = static_cast<uint32_t>(t1 >> 14) & 0x3ffffff;
                m[4] = static_cast<uint32_t>(t1 >> 40) | (pad_bit ? (1u << 24) : 0u);

                for (int i = 0; i < 5; ++i) h[i] += m[i];

                uint32_t r5[5] = {r[0], r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5};

                uint64_t d0 = (uint64_t) h[0] * r5[0] + (uint64_t) h[1] * r5[4] + (uint64_t) h[2] * r5[3] + (uint64_t) h
                              [3] * r5[2] + (uint64_t) h[4] * r5[1];
                uint64_t d1 = (uint64_t) h[0] * r[1] + (uint64_t) h[1] * r[0] + (uint64_t) h[2] * r5[4] + (uint64_t) h[
                                  3] * r5[3] + (uint64_t) h[4] * r5[2];
                uint64_t d2 = (uint64_t) h[0] * r[2] + (uint64_t) h[1] * r[1] + (uint64_t) h[2] * r[0] + (uint64_t) h[3]
                              * r5[4] + (uint64_t) h[4] * r5[3];
                uint64_t d3 = (uint64_t) h[0] * r[3] + (uint64_t) h[1] * r[2] + (uint64_t) h[2] * r[1] + (uint64_t) h[3]
                              * r[0] + (uint64_t) h[4] * r5[4];
                uint64_t d4 = (uint64_t) h[0] * r[4] + (uint64_t) h[1] * r[3] + (uint64_t) h[2] * r[2] + (uint64_t) h[3]
                              * r[1] + (uint64_t) h[4] * r[0];

                uint64_t c;
                c = d0 >> 26;
                h[0] = static_cast<uint32_t>(d0) & 0x3ffffff;
                d1 += c;
                c = d1 >> 26;
                h[1] = static_cast<uint32_t>(d1) & 0x3ffffff;
                d2 += c;
                c = d2 >> 26;
                h[2] = static_cast<uint32_t>(d2) & 0x3ffffff;
                d3 += c;
                c = d3 >> 26;
                h[3] = static_cast<uint32_t>(d3) & 0x3ffffff;
                d4 += c;
                c = d4 >> 26;
                h[4] = static_cast<uint32_t>(d4) & 0x3ffffff;
                h[0] += static_cast<uint32_t>(c * 5);
                c = h[0] >> 26;
                h[0] &= 0x3ffffff;
                h[1] += static_cast<uint32_t>(c);
            }

            std::array<uint8_t, 16> finish() noexcept {
                // 1. Final reduction
                uint32_t c;
                c = h[1] >> 26;
                h[1] &= 0x3ffffff;
                h[2] += c;
                c = h[2] >> 26;
                h[2] &= 0x3ffffff;
                h[3] += c;
                c = h[3] >> 26;
                h[3] &= 0x3ffffff;
                h[4] += c;
                c = h[4] >> 26;
                h[4] &= 0x3ffffff;
                h[0] += c * 5;
                c = h[0] >> 26;
                h[0] &= 0x3ffffff;
                h[1] += c;

                // 2. Compute h - p to check if we need to subtract the prime
                uint32_t g[5];
                g[0] = h[0] + 5;
                c = g[0] >> 26;
                g[0] &= 0x3ffffff;
                g[1] = h[1] + c;
                c = g[1] >> 26;
                g[1] &= 0x3ffffff;
                g[2] = h[2] + c;
                c = g[2] >> 26;
                g[2] &= 0x3ffffff;
                g[3] = h[3] + c;
                c = g[3] >> 26;
                g[3] &= 0x3ffffff;
                g[4] = h[4] + c - (1u << 26);

                uint32_t mask = 0 - (g[4] >> 31); // 0 if h >= p, else 0xFFFFFFFF
                for (int i = 0; i < 5; ++i) h[i] = (h[i] & mask) | (g[i] & ~mask);

                // 3. Pack 26-bit limbs back to 128-bit
                uint32_t final_h[4];
                final_h[0] = h[0] | (h[1] << 26);
                final_h[1] = (h[1] >> 6) | (h[2] << 20);
                final_h[2] = (h[2] >> 12) | (h[3] << 14);
                final_h[3] = (h[3] >> 18) | (h[4] << 8);

                // 4. Add the pad 's' with 64-bit carry propagation
                uint64_t sum;
                std::array<uint8_t, 16> tag;
                sum = (uint64_t) final_h[0] + s[0];
                store32_le(tag.data(), (uint32_t) sum);
                sum = (uint64_t) final_h[1] + s[1] + (sum >> 32);
                store32_le(tag.data() + 4, (uint32_t) sum);
                sum = (uint64_t) final_h[2] + s[2] + (sum >> 32);
                store32_le(tag.data() + 8, (uint32_t) sum);
                sum = (uint64_t) final_h[3] + s[3] + (sum >> 32);
                store32_le(tag.data() + 12, (uint32_t) sum);

                return tag;
            }
        };

        // Compute Poly1305 MAC over `aad || ciphertext` with the given one-time key.
        inline std::array<uint8_t, 16> poly1305_mac(const uint8_t otk[32],
                                                    std::span<const uint8_t> aad,
                                                    std::span<const uint8_t> ciphertext) noexcept {
            Poly1305 ctx;
            ctx.init(otk);

            auto process = [&](std::span<const uint8_t> data) {
                std::size_t i = 0;
                for (; i + 16 <= data.size(); i += 16) {
                    ctx.block(data.data() + i, true);
                }
                if (i < data.size()) {
                    uint8_t partial[16] = {0};
                    std::memcpy(partial, data.data() + i, data.size() - i);
                    ctx.block(partial, true); // Padding bit is still true for partial blocks
                }
            };

            process(aad);
            process(ciphertext);

            uint8_t len_block[16];
            store64_le(len_block, aad.size());
            store64_le(len_block + 8, ciphertext.size());
            ctx.block(len_block, true);

            return ctx.finish();
        }

        // Constant-time 16-byte comparison.
        inline bool ct_equal_16(const uint8_t *a, const uint8_t *b) noexcept {
            uint8_t diff = 0;
            for (int i = 0; i < 16; ++i) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    } // namespace detail

    // Encrypt plaintext and produce an authentication tag (aad = additional authenticated data)
    inline void seal(const std::array<uint8_t, 32> &key,
                     const std::array<uint8_t, 12> &nonce,
                     std::span<const uint8_t> plaintext,
                     std::span<uint8_t> out_ciphertext,
                     std::span<uint8_t> out_tag,
                     std::span<const uint8_t> aad = {}) {
        if (out_ciphertext.size() < plaintext.size()) {
            std::memset(out_tag.data(), 0, std::min(out_tag.size(), size_t(16)));
            return;
        }
        if (out_tag.size() < 16) {
            return;
        }

        uint8_t otk[64]{};
        uint32_t state[16];
        detail::chacha20_init(state, key.data(), nonce.data(), 0);
        detail::chacha20_block(state, otk);

        // Step 2: Copy and Encrypt in-place
        // We copy plaintext to output buffer first, then XOR it.
        std::copy(plaintext.begin(), plaintext.end(), out_ciphertext.begin());
        detail::chacha20_xor(key.data(), nonce.data(), 1,
                             out_ciphertext.data(), out_ciphertext.size());

        // Step 3: Compute Poly1305 tag
        auto tag = detail::poly1305_mac(otk, aad, out_ciphertext);
        std::copy(tag.begin(), tag.end(), out_tag.begin());

        std::memset(otk, 0, sizeof(otk));
        std::memset(state, 0, sizeof(state));
    }

    // decryption:
    inline bool open(const std::array<uint8_t, 32> &key,
                     const std::array<uint8_t, 12> &nonce,
                     std::span<const uint8_t> ciphertext,
                     std::span<uint8_t> out_plaintext,
                     const std::array<uint8_t, 16> &tag,
                     std::span<const uint8_t> aad = {}) {
        // Validate output buffer size
        if (out_plaintext.size() < ciphertext.size()) {
            return false;
        }

        uint8_t otk[64]{};
        uint32_t state[16];
        detail::chacha20_init(state, key.data(), nonce.data(), 0);
        detail::chacha20_block(state, otk);

        // Step 2: Verify tag BEFORE decryption (authenticate-then-decrypt)
        auto expected_tag = detail::poly1305_mac(otk, aad, ciphertext);
        std::memset(otk, 0, sizeof(otk));

        if (!detail::ct_equal_16(expected_tag.data(), tag.data()))
            return false;

        // Step 3: Decrypt
        std::copy(ciphertext.begin(), ciphertext.end(), out_plaintext.begin());
        detail::chacha20_xor(key.data(), nonce.data(), 1,
                             out_plaintext.data(), out_plaintext.size());

        std::memset(state, 0, sizeof(state));
        return true;
    }
} // namespace chacha20_poly1305
