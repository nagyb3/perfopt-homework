cmake_minimum_required(VERSION 4.1)
project(openssl_cpp_benchmark)

set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
set(CMAKE_CXX_STANDARD 20)

find_package(benchmark REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(openssl_cpp_benchmark
#        main.cpp
#        chacha20_benchmark.cpp
#        rsa_benchmark.cpp
#        sha256_benchmark.cpp
        scratch/test_chacha.cpp
)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3")
target_link_libraries(openssl_cpp_benchmark benchmark::benchmark OpenSSL::Crypto)

