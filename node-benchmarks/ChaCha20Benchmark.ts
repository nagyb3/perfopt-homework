import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { resolve } from "node:path";
import { Bench } from "tinybench";
import { parseOutputPath, writeJsonReport, createBaseReport, type TaskResultJson } from "./benchmark-common.js";

const DATA_SIZE = 1024;
const KEY_SIZE = 32;
const NONCE_SIZE = 12;
const AUTH_TAG_SIZE = 16;
const ALGORITHM = "chacha20-poly1305";
const DEFAULT_OUTPUT_FILE = resolve(process.cwd(), "results", "chacha20-benchmark-results.json");

type BenchmarkReport = {
  generatedAt: string;
  benchmark: {
    name: string | undefined;
    runtime: string;
    runtimeVersion: string;
    iterations: number;
    warmup: boolean;
    warmupIterations: number;
    warmupTime: number;
    time: number;
    timestampProvider: string;
  };
  tasks: TaskResultJson[];
};

function encrypt(plaintext: Buffer, key: Buffer, nonce: Buffer): { ciphertext: Buffer; authTag: Buffer } {
  const cipher = createCipheriv(ALGORITHM, key, nonce, { authTagLength: AUTH_TAG_SIZE });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, authTag: cipher.getAuthTag() };
}

function decrypt(ciphertext: Buffer, authTag: Buffer, key: Buffer, nonce: Buffer): Buffer {
  const decipher = createDecipheriv(ALGORITHM, key, nonce, { authTagLength: AUTH_TAG_SIZE });
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

async function main() {
  const outputFile = parseOutputPath(process.argv.slice(2), DEFAULT_OUTPUT_FILE);
  const bench = new Bench({
    name: "node:crypto ChaCha20-Poly1305 benchmark",
    warmup: true,
    warmupIterations: 20,
    iterations: 10,
    retainSamples: false,
    timestampProvider: "hrtimeNow",
  });

  const key = randomBytes(KEY_SIZE);
  const nonce = randomBytes(NONCE_SIZE);
  const plaintext = randomBytes(DATA_SIZE);
  const { ciphertext, authTag } = encrypt(plaintext, key, nonce);
  const roundTrip = decrypt(ciphertext, authTag, key, nonce);

  if (!roundTrip.equals(plaintext)) {
    throw new Error("ChaCha20 setup verification failed");
  }

  bench.add("chacha20-encrypt", () => {
    return encrypt(plaintext, key, nonce).ciphertext;
  });

  bench.add("chacha20-decrypt", () => {
    return decrypt(ciphertext, authTag, key, nonce);
  });

  await bench.run();

  const report = createBaseReport(
    bench,
  ) as BenchmarkReport;
  await writeJsonReport(outputFile, report);

  console.table(bench.table());
  console.log(`JSON results written to ${outputFile}`);
}

await main();
