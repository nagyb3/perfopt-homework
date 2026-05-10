#include <iostream>
#include <vector>
#include <array>
#include <iomanip>
#include <span>
#include <string>
#include <openssl/evp.h>
#include <openssl/err.h>

std::string to_base64(std::span<const uint8_t> data) {
    static const char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c: data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(lookup[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(lookup[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

int main() {
    std::string plaintextMessage = "Hello World";
    std::array<uint8_t, 32> key = {0};
    key[1] = 1;
    std::array<uint8_t, 12> nonce = {0};

    std::vector<uint8_t> plaintext(plaintextMessage.begin(), plaintextMessage.end());
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::array<uint8_t, 16> tag = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce.size(), nullptr);

    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data());

    EVP_CIPHER_CTX_free(ctx);

    std::cout << "Key (in Hex): ";
    for (auto a: key) std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(a);
    std::cout << std::dec << "\n";

    std::cout << "Nonce (in Hex): ";
    for (auto n: nonce) std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(n);
    std::cout << std::dec << "\n";

    std::cout << "Plaintext: " << plaintextMessage << "\n";

    std::cout << "Ciphertext (in Base64): " << to_base64(ciphertext) << "\n";

    std::cout << "Auth Tag (in Base64): " << to_base64(tag) << "\n";

    return 0;
}
