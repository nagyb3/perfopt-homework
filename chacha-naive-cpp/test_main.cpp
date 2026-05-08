#include <iostream>
#include "ChaCha.hpp"
#include <array>
#include <chrono>
#include <iomanip>
#include <vector>

// for testing the algo, on a given key, nonce and plaintext
int main() {
    std::array<uint8_t, 32> key = {0};
    std::array<uint8_t, 12> nonce = {0};
    std::vector<uint8_t> plaintext(1024, 'A');

    auto start = std::chrono::high_resolution_clock::now();

    auto sealed = chacha20_poly1305::seal(key, nonce, plaintext);

    auto end = std::chrono::high_resolution_clock::now();

    std::cout << "Key (in Hex): ";
    for (auto a : key) {
        std::cout << static_cast<int>(a);
    }
    std::cout << std::endl;

    std::cout << "Plaintext (in Hex):\n";
    for (auto a : plaintext) {
        std::cout << a;
    }
    std::cout << std::endl;

    std::cout << "Ciphertext (in Hex):\n";
    for (auto a : sealed.ciphertext) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(a);
    }
    std::cout << std::dec << "\n\n";

    std::cout << "Auth Tag: ";
    for (auto a : sealed.tag) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(a);
    }
    std::cout << std::dec << "\n\n";

    std::chrono::duration<double, std::milli> diff = end - start;
    std::cout << "Encryption finished.\n";
    std::cout << "Size: " << plaintext.size() << " bytes\n";
    std::cout << "Time: " << diff.count() << " ms\n";

    return 0;
}