# openssl_cpp_benchmark

## Dependencies

### Google Benchmark

Note: you need to have [Google Benchmark](https://github.com/google/benchmark) installed on your machine in order to run this.

You can also install it using homebrew if you are running macOS: https://formulae.brew.sh/formula/google-benchmark

### OpenSSL

Currently the cmake project is setup to look for OpenSSL as if it is installed as a homebrew package: https://formulae.brew.sh/formula/openssl@3.

## Building and Running
Build
```
cmake -S . -B cmake-build-debug
cmake --build cmake-build-debug --config Release -j
```

Run
```
./cmake-build-debug/openssl_cpp_benchmark \
    --benchmark_filter=".*" \
    --benchmark_repetitions=10 \
    --benchmark_min_warmup_time=1.0 \
    --benchmark_report_aggregates_only=false \
    --benchmark_format=json \
    --benchmark_out=results.json
```