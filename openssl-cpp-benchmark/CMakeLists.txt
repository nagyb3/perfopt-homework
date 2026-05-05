cmake_minimum_required(VERSION 4.1)
project(openssl_cpp_benchmark)

set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
set(CMAKE_CXX_STANDARD 23)

find_package(benchmark REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(openssl_cpp_benchmark
        main.cpp
        chacha20_benchmark.cpp
        rsa_benchmark.cpp
        sha256_benchmark.cpp
)

target_link_libraries(openssl_cpp_benchmark benchmark::benchmark OpenSSL::Crypto)

