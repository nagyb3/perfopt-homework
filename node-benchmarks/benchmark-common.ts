import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { Bench } from "tinybench";

export type StatisticsJson = {
  mean: number;
  min: number;
  max: number;
  aad: number;
  critical: number;
  df: number;
  mad: number;
  moe: number;
  p50: number;
  p75: number;
  p99: number;
  p995: number;
  p999: number;
  rme: number;
  samplesCount: number;
  sd: number;
  sem: number;
  variance: number;
};

export type SerializableTaskResult = {
  state: string;
  runtime: string;
  runtimeVersion: string;
  timestampProviderName: string;
  error?: Error;
  period?: number;
  totalTime?: number;
  latency?: StatisticsJson;
  throughput?: StatisticsJson;
};

export type SerializableTask = {
  name: string;
  runs: number;
  result: SerializableTaskResult;
};

export type TaskResultJson = {
  name: string;
  runs: number;
  state: string;
  error?: { name: string; message: string; stack: string | undefined };
  period: number | undefined;
  totalTime: number | undefined;
  latency: StatisticsJson | undefined;
  throughput: StatisticsJson | undefined;
  runtime: string;
  runtimeVersion: string;
  timestampProviderName: string;
};

export function parseOutputPath(argv: string[], defaultFile: string): string {
  const exactMatch = argv.find((value) => value.startsWith("--output="));
  if (exactMatch) {
    const value = exactMatch.slice("--output=".length).trim();
    if (value) return resolve(process.cwd(), value);
  }

  const index = argv.findIndex((value) => value === "--output" || value === "-o");
  const outputArg = index >= 0 ? argv[index + 1] : undefined;
  if (typeof outputArg === "string" && outputArg.length > 0) {
    return resolve(process.cwd(), outputArg);
  }

  return defaultFile;
}

export function serializeStatistics(stats: StatisticsJson): StatisticsJson {
  return {
    mean: stats.mean,
    min: stats.min,
    max: stats.max,
    aad: stats.aad,
    critical: stats.critical,
    df: stats.df,
    mad: stats.mad,
    moe: stats.moe,
    p50: stats.p50,
    p75: stats.p75,
    p99: stats.p99,
    p995: stats.p995,
    p999: stats.p999,
    rme: stats.rme,
    samplesCount: stats.samplesCount,
    sd: stats.sd,
    sem: stats.sem,
    variance: stats.variance,
  };
}

export function serializeTaskResult(task: SerializableTask): TaskResultJson {
  const result = task.result;
  const base: TaskResultJson = {
    name: task.name,
    runs: task.runs,
    state: result.state,
    period: undefined,
    totalTime: undefined,
    latency: undefined,
    throughput: undefined,
    runtime: result.runtime,
    runtimeVersion: result.runtimeVersion,
    timestampProviderName: result.timestampProviderName,
  };

  if (result.state === "errored") {
    return {
      ...base,
      error: {
        name: result.error?.name ?? "Error",
        message: result.error?.message ?? String(result.error),
        stack: result.error?.stack,
      },
    };
  }

  if (result.state === "completed" || result.state === "aborted-with-statistics") {
    if (!result.latency || !result.throughput) {
      throw new Error(`missing statistics for task ${task.name}`);
    }

    return {
      ...base,
      period: result.period,
      totalTime: result.totalTime,
      latency: serializeStatistics(result.latency),
      throughput: serializeStatistics(result.throughput),
    };
  }

  return base;
}

export async function writeJsonReport(outputFile: string, report: unknown): Promise<void> {
  await mkdir(dirname(outputFile), { recursive: true });
  await writeFile(outputFile, `${JSON.stringify(report, null, 2)}\n`, "utf8");
}

export type BenchmarkMetadata = {
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

export function createBenchmarkMetadata(bench: Bench): BenchmarkMetadata {
  return {
    name: bench.name,
    runtime: bench.runtime,
    runtimeVersion: bench.runtimeVersion,
    iterations: bench.iterations,
    warmup: bench.warmup,
    warmupIterations: bench.warmupIterations,
    warmupTime: bench.warmupTime,
    time: bench.time,
    timestampProvider: bench.timestampProvider.name,
  };
}

export type BaseBenchmarkReport<AlgoMetadata extends Record<string, unknown>> = {
  generatedAt: string;
  benchmark: BenchmarkMetadata;
  verification: Record<string, unknown>;
  tasks: TaskResultJson[];
} & AlgoMetadata;

export function createBaseReport<AlgoMetadata extends Record<string, unknown>>(
  bench: Bench,
  algoMetadata: AlgoMetadata,
  verification: Record<string, unknown>,
): BaseBenchmarkReport<AlgoMetadata> {
  return {
    generatedAt: new Date().toISOString(),
    benchmark: createBenchmarkMetadata(bench),
    verification,
    tasks: bench.tasks.map((task) => serializeTaskResult({ name: task.name, runs: task.runs, result: task.result })),
    ...algoMetadata,
  };
}


