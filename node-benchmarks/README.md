## RSA benchmark

`RsaBenchmark.ts` benchmarks Node's `crypto` RSA OAEP encrypt/decrypt path using `tinybench` and writes a JSON report to:

- `results/rsa-benchmark-results.json`

### Run

```bash
npm run bench:rsa
```

### Custom output path

```bash
npx tsx RsaBenchmark.ts --output results/rsa-report.json
```

## ChaCha20 benchmark

`ChaCha20Benchmark.ts` benchmarks Node's `crypto` ChaCha20-Poly1305 encrypt/decrypt path using `tinybench` and writes a JSON report to:

- `results/chacha20-benchmark-results.json`

### Run

```bash
npm run bench:chacha
```

### Custom output path

```bash
npx tsx ChaCha20Benchmark.ts --output results/chacha-report.json
```

## SHA-256 benchmark

`Sha256Benchmark.ts` benchmarks Node's `crypto` SHA-256 digest path using `tinybench` and writes a JSON report to:

- `results/sha256-report.json`

### Run

```bash
npm run bench:sha256
```

### Custom output path

```bash
npx tsx Sha256Benchmark.ts --output results/sha256-custom-report.json
```

