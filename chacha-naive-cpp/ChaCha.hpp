#pragma once

#include <array>
#include <cstring>
#include <span>

namespace chacha20_poly1305 {

namespace detail {

inline uint32_t load32_le(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0])
         | static_cast<uint32_t>(p[1]) << 8
         | static_cast<uint32_t>(p[2]) << 16
         | static_cast<uint32_t>(p[3]) << 24;
}

inline uint64_t load64_le(const uint8_t* p) noexcept {
    return static_cast<uint64_t>(load32_le(p))
         | static_cast<uint64_t>(load32_le(p + 4)) << 32;
}

inline void store32_le(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

inline void store64_le(uint8_t* p, uint64_t v) noexcept {
    store32_le(p,     static_cast<uint32_t>(v));
    store32_le(p + 4, static_cast<uint32_t>(v >> 32));
}

inline uint32_t rotl32(uint32_t v, int n) noexcept {
    return (v << n) | (v >> (32 - n));
}

// quarter round operations:
#define QR(a,b,c,d) \
    a += b; d ^= a; d = rotl32(d,16); \
    c += d; b ^= c; b = rotl32(b,12); \
    a += b; d ^= a; d = rotl32(d, 8); \
    c += d; b ^= c; b = rotl32(b, 7)

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
    state[0]  = 0x61707865u;
    state[1]  = 0x3320646eu;
    state[2]  = 0x79622d32u;
    state[3]  = 0x6b206574u;
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
                         uint32_t      counter,
                         uint8_t*      data,
                         std::size_t   len) noexcept {
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
    // Accumulator: h[0..4] (26 bits each, little-endian, base 2^26)
    uint32_t h[5]{};
    // r (clamped) and s (pad), stored as limbs
    uint32_t r[5]{};
    uint64_t s[2]{};   // raw 128-bit pad (little-endian pair of uint64)

    void init(const uint8_t key[32]) noexcept {
        // Clamp r (RFC 8439 §2.5.1)
        uint64_t t0 = load64_le(key);
        uint64_t t1 = load64_le(key + 8);

        // Clamp mask: 0x0ffffffc0fffffff / 0x0ffffffc0ffffffc
        r[0] = static_cast<uint32_t>( t0)        & 0x3ffffff;
        r[1] = static_cast<uint32_t>( t0 >> 26)  & 0x3ffff03;
        r[2] = static_cast<uint32_t>((t0 >> 52) | (t1 << 12)) & 0x3ffc0ff;
        r[3] = static_cast<uint32_t>( t1 >> 14)  & 0x3f03fff;
        r[4] = static_cast<uint32_t>( t1 >> 40)  & 0x00fffff;

        s[0] = load64_le(key + 16);
        s[1] = load64_le(key + 24);

        h[0] = h[1] = h[2] = h[3] = h[4] = 0;
    }

    void block(const uint8_t* msg, bool pad_bit) noexcept {
        // Load 16-byte message block as five 26-bit limbs + optional high bit
        uint64_t t0 = load64_le(msg);
        uint64_t t1 = load64_le(msg + 8);

        uint32_t m[5];
        m[0] = static_cast<uint32_t>( t0)       & 0x3ffffff;
        m[1] = static_cast<uint32_t>( t0 >> 26) & 0x3ffffff;
        m[2] = static_cast<uint32_t>((t0 >> 52) | (t1 << 12)) & 0x3ffffff;
        m[3] = static_cast<uint32_t>( t1 >> 14) & 0x3ffffff;
        m[4] = static_cast<uint32_t>( t1 >> 40) | (pad_bit ? (1u << 24) : 0u);

        // h += m
        uint32_t hh[5];
        for (int i = 0; i < 5; ++i) hh[i] = h[i] + m[i];

        // h = h * r  (mod 2^130 - 5)
        // Using 64-bit intermediate products
        uint64_t d[5]{};
        for (int i = 0; i < 5; ++i) {
            for (int j = 0; j < 5; ++j) {
                uint64_t prod = static_cast<uint64_t>(hh[i]) * r[j];
                int pos = i + j;
                if (pos >= 5) {
                    // 2^130 ≡ 5 (mod 2^130-5), so multiply by 5
                    d[pos - 5] += prod * 5;
                } else {
                    d[pos] += prod;
                }
            }
        }

        // Propagate carries and reduce mod 2^130-5
        uint64_t c = 0;
        for (int i = 0; i < 5; ++i) {
            d[i] += c;
            h[i]  = static_cast<uint32_t>(d[i]) & 0x3ffffff;
            c     = d[i] >> 26;
        }
        // Final carry wraps: c * (2^130) ≡ c * 5 (mod 2^130-5)
        h[0] += static_cast<uint32_t>(c * 5);
        h[1] += h[0] >> 26;
        h[0] &= 0x3ffffff;
    }

    // Finalise: return 16-byte tag.
    std::array<uint8_t, 16> finish() noexcept {
        // Fully reduce h mod 2^130-5
        uint32_t c = h[1] >> 26; h[1] &= 0x3ffffff;
        h[2] += c; c = h[2] >> 26; h[2] &= 0x3ffffff;
        h[3] += c; c = h[3] >> 26; h[3] &= 0x3ffffff;
        h[4] += c; c = h[4] >> 26; h[4] &= 0x3ffffff;
        h[0] += c * 5; c = h[0] >> 26; h[0] &= 0x3ffffff;
        h[1] += c;

        // Compute h + (-p) = h - (2^130 - 5) to check if h >= p
        uint32_t g[5];
        uint32_t b;
        g[0] = h[0] + 5; b = g[0] >> 26; g[0] &= 0x3ffffff;
        g[1] = h[1] + b; b = g[1] >> 26; g[1] &= 0x3ffffff;
        g[2] = h[2] + b; b = g[2] >> 26; g[2] &= 0x3ffffff;
        g[3] = h[3] + b; b = g[3] >> 26; g[3] &= 0x3ffffff;
        g[4] = h[4] + b - (1u << 26);    // overflow flag

        // Constant-time select: if g[4] carries (h >= p), use g; else use h
        uint32_t mask = static_cast<uint32_t>(static_cast<int32_t>(g[4]) >> 31);
        // mask = 0xFFFFFFFF if h < p, 0 if h >= p
        for (int i = 0; i < 5; ++i)
            h[i] = (h[i] & mask) | (g[i] & ~mask);

        // Pack h into 128-bit little-endian integer
        uint64_t f0 = (static_cast<uint64_t>(h[0]))
                    | (static_cast<uint64_t>(h[1]) << 26)
                    | (static_cast<uint64_t>(h[2]) << 52);
        uint64_t f1 = (static_cast<uint64_t>(h[2]) >> 12)
                    | (static_cast<uint64_t>(h[3]) << 14)
                    | (static_cast<uint64_t>(h[4]) << 40);

        // Add pad s
        uint64_t carry;
        f0   += s[0];
        carry = (f0 < s[0]) ? 1u : 0u;   // detect overflow
        f1   += s[1] + carry;

        std::array<uint8_t, 16> tag{};
        store64_le(tag.data(),     f0);
        store64_le(tag.data() + 8, f1);
        return tag;
    }
};

// Compute Poly1305 MAC over `aad || ciphertext` with the given one-time key.
inline std::array<uint8_t, 16>
poly1305_mac(const uint8_t otk[32],
             std::span<const uint8_t> aad,
             std::span<const uint8_t> ciphertext) noexcept {
    Poly1305 ctx;
    ctx.init(otk);

    uint8_t buf[16];

    // Helper: process a padded span
    auto process = [&](std::span<const uint8_t> data) {
        std::size_t full = data.size() / 16;
        for (std::size_t i = 0; i < full; ++i)
            ctx.block(data.data() + i * 16, true);
        std::size_t rem = data.size() % 16;
        if (rem) {
            std::memset(buf, 0, 16);
            std::memcpy(buf, data.data() + full * 16, rem);
            buf[rem] = 0x01; // pad byte placed after data
            ctx.block(buf, false); // high bit already in buf[rem]
        }
    };

    process(aad);
    process(ciphertext);

    // Append lengths (little-endian 64-bit each)
    std::memset(buf, 0, 16);
    store64_le(buf,     static_cast<uint64_t>(aad.size()));
    store64_le(buf + 8, static_cast<uint64_t>(ciphertext.size()));
    ctx.block(buf, false);

    return ctx.finish();
}

// Constant-time 16-byte comparison.
inline bool ct_equal_16(const uint8_t* a, const uint8_t* b) noexcept {
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

} // namespace detail

// Encrypt plaintext and produce an authentication tag (aad = additional authenticated data)
inline void seal(const std::array<uint8_t, 32>& key,
                const std::array<uint8_t, 12>& nonce,
                std::span<const uint8_t> plaintext,
                std::span<uint8_t> out_ciphertext,
                std::span<uint8_t> out_tag,
                std::span<const uint8_t> aad = {}) {
    // Step 1: Generate Poly1305 one-time key (block 0)
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
inline bool open(const std::array<uint8_t, 32>& key,
                const std::array<uint8_t, 12>& nonce,
                std::span<const uint8_t> ciphertext,
                std::span<uint8_t> out_plaintext,
                const std::array<uint8_t, 16>& tag,
                std::span<const uint8_t> aad = {}) {
    // Step 1: Generate Poly1305 one-time key
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