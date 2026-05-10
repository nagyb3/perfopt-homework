#include <iostream>
#include "ChaCha.hpp"
#include <array>
#include <chrono>
#include <iomanip>
#include <vector>
#include <span>
#include <string>

std::string to_base64(std::span<const uint8_t> data) {
    static const char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
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


    // output buffers
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::array<uint8_t, 16> tag = {0};

    chacha20_poly1305::seal(key, nonce, plaintext, ciphertext, tag);

    std::cout << "Key (in Hex): ";
    for (auto a : key) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(a);
    }
    std::cout << std::dec << std::endl;

    std::cout << "Nonce (in Hex): ";
    for (auto n : nonce) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(n);
    }
    std::cout << std::dec << std::endl;

    std::cout << "Plaintext:\n";
    for (auto p : plaintext) {
        std::cout << p;
    }
    std::cout << std::endl;

    std::cout << "Ciphertext (in Base64):\n";
    std::cout << to_base64(ciphertext) << std::endl;

    std::cout << "Auth Tag (in Base64):\n";
    std::cout << to_base64(tag) << std::endl;

    return 0;
}