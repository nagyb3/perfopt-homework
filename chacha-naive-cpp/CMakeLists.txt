cmake_minimum_required(VERSION 3.10)
project(chacha_naive_cpp)

set(CMAKE_CXX_STANDARD 20)

find_package(benchmark REQUIRED)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3")

add_executable(chacha_naive_cpp
    chacha_benchmark.cpp
#    test_main.cpp
)

target_link_libraries(chacha_naive_cpp benchmark::benchmark)
