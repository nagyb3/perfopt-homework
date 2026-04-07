#include <iostream>
#include <openssl/opensslv.h>
#include <benchmark/benchmark.h>

int main() {
    std::cout << "Hello, World!" << std::endl;
    std::cout << "OpenSSL version: " << OPENSSL_VERSION_MAJOR << "." << OPENSSL_VERSION_MINOR << std::endl;
    return 0;
}