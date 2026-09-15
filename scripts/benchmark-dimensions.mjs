import { performance } from "node:perf_hooks";
import { DIMENSION_LIMITS } from "../src/constants.js";
import { scanImageDimensions } from "../src/dimensions.js";
import {
  createAvif,
  createGif,
  createJpeg,
  createPng,
  createSvg,
  createWebp,
} from "../test/helpers/image-fixtures.js";
import { MockR2Bucket } from "../test/helpers/mock-r2.js";

function percentile(values, ratio) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * ratio))];
}

async function mapWithConcurrency(items, concurrency, worker) {
  const results = new Array(items.length);
  let next = 0;
  async function run() {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: concurrency }, () => run()));
  return results;
}

function createObjects() {
  const records = [];
  for (let index = 0; index < 40; index += 1) {
    const group = index % 5;
    if (group === 0) {
      records.push({ key: `pics/pic/${index}.jpg`, bytes: createJpeg({ width: 2400, height: 1600, padding: 80 * 1024 }) });
    } else if (group === 1) {
      records.push({ key: `pics/pic/${index}.avif`, bytes: createAvif({ width: 2560, height: 1440, padding: 160 * 1024 }) });
    } else if (group === 2) {
      records.push({ key: `pics/pic/${index}.svg`, bytes: createSvg({ width: 1200, height: 800, prefix: " ".repeat(80 * 1024) }) });
    } else if (group === 3) {
      records.push({ key: `pics/pic/${index}.webp`, bytes: createWebp({ width: 1600, height: 1000 }) });
    } else if (group === 4) {
      records.push({ key: `pics/pic/${index}.png`, bytes: createPng({ width: 2048, height: 1365 }) });
    } else {
      records.push({ key: `pics/pic/${index}.gif`, bytes: createGif({ width: 800, height: 600 }) });
    }
  }
  return records.map((record, index) => ({ ...record, etag: `benchmark-etag-${index}` }));
}

function limitsWithInitial(initial) {
  return Object.fromEntries(
    Object.entries(DIMENSION_LIMITS).map(([format, plan]) => [
      format,
      {
        initial: Math.min(plan.max, initial),
        chunk: plan.chunk,
        max: plan.max,
      },
    ])
  );
}

function delayedBucket(records, latencyMs) {
  const bucket = new MockR2Bucket(records);
  return {
    get: async (...args) => {
      await new Promise((resolve) => setTimeout(resolve, latencyMs));
      return bucket.get(...args);
    },
    getCalls: bucket.getCalls,
  };
}

async function runScenario(records, concurrency, initial) {
  const bucket = delayedBucket(records, 2);
  const durations = [];
  let bytesRead = 0;
  let failures = 0;

  await mapWithConcurrency(records, concurrency, async (record) => {
    const started = performance.now();
    const result = await scanImageDimensions(record, bucket, {}, { limits: limitsWithInitial(initial) });
    durations.push(performance.now() - started);
    bytesRead += result.bytesRead;
    if (result.status !== "ok") failures += 1;
  });

  return {
    concurrency,
    initialKiB: initial / 1024,
    totalMs: Number(durations.reduce((sum, value) => sum + value, 0).toFixed(2)),
    p50Ms: Number(percentile(durations, 0.5).toFixed(2)),
    p95Ms: Number(percentile(durations, 0.95).toFixed(2)),
    bytesRead,
    failures,
  };
}

const records = createObjects();
const results = [];
for (const initial of [64 * 1024, 128 * 1024]) {
  for (const concurrency of [5, 8, 10]) {
    results.push(await runScenario(records, concurrency, initial));
  }
}

console.log(JSON.stringify({ generatedAt: new Date().toISOString(), results }, null, 2));
