#include <iostream>
#include "ChaCha.hpp"
#include <array>
#include <chrono>
#include <iomanip>
#include <vector>
#include <span>

int main() {
    std::array<uint8_t, 32> key = {0};
    std::array<uint8_t, 12> nonce = {0};
    std::vector<uint8_t> plaintext(1024, 'A');

    // output buffers
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::array<uint8_t, 16> tag = {0};

    chacha20_poly1305::seal(key, nonce, plaintext, ciphertext, tag);

    std::cout << "Key (in Hex): ";
    for (auto a : key) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(a);
    }
    std::cout << std::dec << std::endl;

    std::cout << "Plaintext:\n";
    for (auto p : plaintext) {
        std::cout << p;
    }
    std::cout << std::endl;

    std::cout << "Ciphertext (in Hex):\n";
    for (auto a : ciphertext) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(a);
    }
    std::cout << std::dec << "\n\n";

    std::cout << "Auth Tag: ";
    for (auto a : tag) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(a);
    }
    std::cout << std::dec << "\n\n";

    std::cout << "Encryption finished.\n";
    std::cout << "Size: " << plaintext.size() << " bytes\n";

    return 0;
}