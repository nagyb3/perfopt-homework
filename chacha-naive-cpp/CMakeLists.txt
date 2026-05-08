cmake_minimum_required(VERSION 3.10)
project(chacha_naive_cpp)

set(CMAKE_CXX_STANDARD 20)

find_package(benchmark REQUIRED)

add_executable(chacha_naive_cpp chacha_benchmark.cpp
)

target_link_libraries(chacha_naive_cpp benchmark::benchmark)
