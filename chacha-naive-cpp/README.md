# chacha_naive_cpp

A naive implementation of ChaCha20-Poly1305 meant to be compared against OpenSSL, Node crypto module and BouncyCastle.

## Building and Running
Build
```
cmake -S . -B cmake-build-debug
cmake --build cmake-build-debug --config Release -j
```

Run
```
./cmake-build-debug/chacha_naive_cpp \
    --benchmark_filter=".*" \
    --benchmark_repetitions=10 \
    --benchmark_min_warmup_time=1.0 \
    --benchmark_report_aggregates_only=false \
    --benchmark_format=json \
    --benchmark_out=results.json
```