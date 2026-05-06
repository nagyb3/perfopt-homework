import { createHash, randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { Bench } from "tinybench";
import { parseOutputPath, writeJsonReport, createBaseReport, type TaskResultJson } from "./benchmark-common.js";

const DATA_SIZE = 1024;
const ALGORITHM = "sha256";
const OUTPUT_FILE = resolve(process.cwd(), "results", "sha256-report.json");

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
  sha256: {
    algorithm: string;
    dataSize: number;
  };
  tasks: TaskResultJson[];
};

function digest(data: Buffer): Buffer {
  return createHash(ALGORITHM).update(data).digest();
}

async function main() {
  const outputFile = parseOutputPath(process.argv.slice(2), OUTPUT_FILE);
  const bench = new Bench({
    name: "node:crypto SHA-256 benchmark",
    warmup: true,
    warmupIterations: 20,
    iterations: 10,
    retainSamples: false,
    timestampProvider: "hrtimeNow",
  });

  const data = randomBytes(DATA_SIZE);
  const expectedDigest = digest(data);
  const roundTrip = digest(data);

  if (!roundTrip.equals(expectedDigest)) {
    throw new Error("SHA-256 setup verification failed");
  }

  bench.add("sha256", () => {
    return digest(data);
  });

  await bench.run();

  const report = createBaseReport(
    bench
  ) as BenchmarkReport;
  await writeJsonReport(outputFile, report);

  console.table(bench.table());
  console.log(`JSON results written to ${outputFile}`);
}

await main();

