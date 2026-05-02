import { createHash, randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { Bench } from "tinybench";
import { parseOutputPath, writeJsonReport, createBaseReport, type TaskResultJson } from "./benchmark-common.js";

const DATA_SIZE = 1024;
const ALGORITHM = "sha256";
const DEFAULT_OUTPUT_FILE = resolve(process.cwd(), "results", "sha256-report.json");

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
  verification: {
    digestMatches: boolean;
  };
  tasks: TaskResultJson[];
};

function digest(data: Buffer): Buffer {
  return createHash(ALGORITHM).update(data).digest();
}

function createBenchmarkReport(bench: Bench, digestMatches: boolean): BenchmarkReport {
  return {
    generatedAt: new Date().toISOString(),
    benchmark: {
      name: bench.name,
      runtime: bench.runtime,
      runtimeVersion: bench.runtimeVersion,
      iterations: bench.iterations,
      warmup: bench.warmup,
      warmupIterations: bench.warmupIterations,
      warmupTime: bench.warmupTime,
      time: bench.time,
      timestampProvider: bench.timestampProvider.name,
    },
    sha256: {
      algorithm: ALGORITHM,
      dataSize: DATA_SIZE,
    },
    verification: {
      digestMatches,
    },
    tasks: bench.tasks.map((task) => serializeTaskResult({ name: task.name, runs: task.runs, result: task.result })),
  };
}

async function main() {
  const outputFile = parseOutputPath(process.argv.slice(2), DEFAULT_OUTPUT_FILE);
  const bench = new Bench({
    name: "node:crypto SHA-256 benchmark",
    time: Number(process.env.BENCH_TIME_MS ?? 750),
    warmup: true,
    warmupTime: Number(process.env.BENCH_WARMUP_MS ?? 250),
    warmupIterations: 10,
    iterations: 64,
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
    bench,
    {
      sha256: {
        algorithm: ALGORITHM,
        dataSize: DATA_SIZE,
      },
    },
    { digestMatches: true },
  ) as BenchmarkReport;
  await writeJsonReport(outputFile, report);

  console.table(bench.table());
  console.log(`JSON results written to ${outputFile}`);
}

await main();

