import { randomBytes, generateKeyPairSync, publicEncrypt, privateDecrypt, constants } from "node:crypto";
import { resolve } from "node:path";
import { Bench } from "tinybench";
import { parseOutputPath, writeJsonReport, createBaseReport, type TaskResultJson } from "./benchmark-common.js";

const KEY_SIZE = 2048;
const DATA_SIZE = 32;
const ALGORITHM = "RSA-OAEP-SHA256";
const DEFAULT_OUTPUT_FILE = resolve(process.cwd(), "results", "rsa-benchmark-results.json");

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
  rsa: {
    keySize: number;
    dataSize: number;
    algorithm: string;
    padding: string;
    oaepHash: string;
  };
  verification: {
    roundTripMatches: boolean;
  };
  tasks: TaskResultJson[];
};

async function main() {
  const outputFile = parseOutputPath(process.argv.slice(2), DEFAULT_OUTPUT_FILE);
  const bench = new Bench({
    name: "node:crypto RSA OAEP benchmark",
    time: Number(process.env.BENCH_TIME_MS ?? 750),
    warmup: true,
    warmupTime: Number(process.env.BENCH_WARMUP_MS ?? 250),
    warmupIterations: 10,
    iterations: 64,
    retainSamples: false,
    timestampProvider: "hrtimeNow",
  });

  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: KEY_SIZE,
    publicExponent: 0x10001,
  });

  const plaintext = randomBytes(DATA_SIZE);
  const ciphertext = publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    plaintext,
  );
  const roundTrip = privateDecrypt(
    {
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    ciphertext,
  );

  if (!roundTrip.equals(plaintext)) {
    throw new Error("RSA setup verification failed");
  }

  bench.add("rsa-encrypt", () => {
    return publicEncrypt(
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      plaintext,
    );
  });

  bench.add("rsa-decrypt", () => {
    return privateDecrypt(
      {
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      ciphertext,
    );
  });

  await bench.run();

  const report = createBaseReport(
    bench,
    {
      rsa: {
        keySize: KEY_SIZE,
        dataSize: DATA_SIZE,
        algorithm: ALGORITHM,
        padding: "RSA_PKCS1_OAEP_PADDING",
        oaepHash: "sha256",
      },
    },
    { roundTripMatches: true },
  ) as BenchmarkReport;
  await writeJsonReport(outputFile, report);

  console.table(bench.table());
  console.log(`JSON results written to ${outputFile}`);
}

await main();




