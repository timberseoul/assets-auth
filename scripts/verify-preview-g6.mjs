import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import {
  createAvif,
  createGif,
  createJpeg,
  createPng,
  createSvg,
  createWebp,
} from "../test/helpers/image-fixtures.js";

const rootDir = resolve(process.cwd());
const baseUrl = String(process.env.PREVIEW_BASE_URL || "https://assets-auth-preview.needcancan.workers.dev").replace(/\/$/, "");
const token = process.env.GALLERY_API_TOKEN || "";
const secret = process.env.SIGNING_SECRET || "";
const bucket = "pictures-lib";
const runId = String(Date.now()) + "-" + String(process.pid);
const prefix = "pics/pic/__w6_g6__/" + runId + "/";
const workDir = resolve(rootDir, ".wrangler", "w6-g6-" + runId);

assert(token, "GALLERY_API_TOKEN is required");
assert(secret, "SIGNING_SECRET is required");
mkdirSync(workDir, { recursive: true });

const sleep = (ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
const hashBytes = (bytes) => createHash("sha256").update(bytes).digest("hex");
const hmac = (message) => createHmac("sha256", secret).update(message, "utf8").digest("hex");

function runProcess(command, args, { allowFailure = false } = {}) {
  return new Promise((resolvePromise, reject) => {
    const executable = command === "pnpm" && process.platform === "win32" ? "pnpm" : command;
    const child = spawn(executable, args, {
      cwd: rootDir,
      shell: command === "pnpm" && process.platform === "win32",
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.on("error", (error) => reject(error));
    child.on("close", (code) => {
      const result = { code: code ?? -1, stdout, stderr };
      if (!allowFailure && result.code !== 0) {
        reject(new Error(executable + " failed with exit " + result.code + ": " + stderr.slice(-500)));
      } else {
        resolvePromise(result);
      }
    });
  });
}

function wrangler(args, options = {}) {
  return runProcess("pnpm", ["exec", "wrangler", ...args], options);
}

async function putObject(file, key, contentType) {
  await wrangler([
    "r2", "object", "put", bucket + "/" + key,
    "--file", file,
    "--remote", "--force",
    "--content-type", contentType,
  ]);
}

async function deleteObject(key) {
  await wrangler(["r2", "object", "delete", bucket + "/" + key, "--remote", "--force"], { allowFailure: true });
}

let curlCounter = 0;
async function curlRequest(url, { headers = [], includeBody = false, label = "request", timeoutSeconds = 60 } = {}) {
  const id = ++curlCounter;
  const headerFile = join(workDir, "curl-" + id + ".headers");
  const bodyFile = join(workDir, "curl-" + id + ".body");
  try {
    const args = [
      "-sS", "--max-time", String(timeoutSeconds), "--connect-timeout", "15",
      "-D", headerFile, "-o", bodyFile, "-w", "%{http_code}\t%{time_total}",
    ];
    for (const header of headers) args.push("-H", header);
    args.push(url);
    const result = await runProcess("curl.exe", args, { allowFailure: true });
    if (result.code !== 0) throw new Error(label + " curl exit " + result.code);
    const parts = result.stdout.trim().split("\t");
    const status = Number(parts[0]);
    if (!Number.isInteger(status) || status < 100) throw new Error(label + " returned no HTTP status");
    const rawHeaders = readFileSync(headerFile, "utf8");
    const responseHeaders = {};
    for (const line of rawHeaders.split(/\r?\n/)) {
      const separator = line.indexOf(":");
      if (separator <= 0) continue;
      responseHeaders[line.slice(0, separator).trim().toLowerCase()] = line.slice(separator + 1).trim();
    }
    const bodySize = statSync(bodyFile).size;
    return {
      status,
      timeMs: Number(parts[1]) * 1000,
      bytes: bodySize,
      headers: responseHeaders,
      body: includeBody ? readFileSync(bodyFile) : undefined,
    };
  } finally {
    rmSync(headerFile, { force: true });
    rmSync(bodyFile, { force: true });
  }
}

async function trafficStatus() {
  const result = await wrangler(["deployments", "status", "--config", "wrangler.preview.toml", "--json"]);
  const clean = result.stdout.replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g, "");
  const jsonStart = clean.indexOf("{");
  assert(jsonStart >= 0, "deployment status JSON was not found");
  const status = JSON.parse(clean.slice(jsonStart));
  const current = status.versions?.find((entry) => entry.version_id === "b2f40144-73a1-4cf5-a291-9d185c544f34");
  assert.equal(current?.percentage, 100, "b2f traffic is not at 100%");
  return { deploymentId: status.id, versionId: current.version_id, percentage: current.percentage };
}

async function listPage(pagePrefix, limit = 50) {
  const url = new URL("/api/gallery", baseUrl);
  url.searchParams.set("prefix", pagePrefix);
  url.searchParams.set("limit", String(limit));
  const response = await curlRequest(url.href, {
    headers: ["Authorization: Bearer " + token],
    includeBody: true,
    label: "list " + pagePrefix,
  });
  assert.equal(response.status, 200, "list " + pagePrefix + " status");
  return { response, payload: JSON.parse(response.body.toString("utf8")) };
}

async function waitForObjects(pagePrefix, expectedCount, limit = 50) {
  let lastCount = 0;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const page = await listPage(pagePrefix, limit);
    lastCount = page.payload.items.length;
    if (lastCount >= expectedCount) return page;
    await sleep(1000);
  }
  throw new Error("remote list only exposed " + lastCount + "/" + expectedCount + " temporary objects");
}

function makeFixture(index) {
  if (index < 7) return { ext: "png", type: "image/png", bytes: createPng({ width: 800 + index, height: 500 + index }) };
  if (index < 14) return { ext: "gif", type: "image/gif", bytes: createGif({ width: 640 + index, height: 480 + index }) };
  if (index < 21) return { ext: "jpg", type: "image/jpeg", bytes: createJpeg({ width: 1600 + index, height: 900 + index, padding: index === 20 ? 384 * 1024 : 0 }) };
  if (index < 28) return { ext: "webp", type: "image/webp", bytes: createWebp({ width: 1024 + index, height: 768 + index }) };
  if (index < 35) return { ext: "svg", type: "image/svg+xml", bytes: createSvg({ width: 1200 + index, height: 800 + index, prefix: index === 34 ? " ".repeat(192 * 1024) : "" }) };
  return { ext: "avif", type: "image/avif", bytes: createAvif({ width: 1920 + index, height: 1080 + index, padding: index === 39 ? 700 * 1024 : 0 }) };
}

function percentile(values, fraction) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * fraction))];
}

function counts(values) {
  return Object.fromEntries([...new Set(values)].sort().map((key) => [key || "(none)", values.filter((value) => value === key).length]));
}

async function runBatch(label, urls, concurrency = 8) {
  const results = new Array(urls.length);
  let next = 0;
  async function worker() {
    while (true) {
      const index = next;
      next += 1;
      if (index >= urls.length) return;
      try {
        results[index] = await curlRequest(urls[index], { label: label + "-" + index });
      } catch (error) {
        results[index] = { status: 0, timeMs: null, bytes: 0, headers: {}, error: error.message };
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, urls.length) }, () => worker()));
  const successful = results.filter((result) => result.status === 200);
  const latencies = successful.map((result) => result.timeMs);
  return {
    label,
    requested: results.length,
    successful: successful.length,
    failed: results.length - successful.length,
    statuses: counts(results.map((result) => String(result.status))),
    totalBytes: results.reduce((sum, result) => sum + result.bytes, 0),
    p50Ms: Number(percentile(latencies, 0.5)?.toFixed(2) || 0),
    p95Ms: Number(percentile(latencies, 0.95)?.toFixed(2) || 0),
    maxMs: Number(Math.max(...latencies, 0).toFixed(2)),
    xWorkerCache: counts(results.map((result) => result.headers["x-worker-cache"] || "")),
    cfCacheStatus: counts(results.map((result) => result.headers["cf-cache-status"] || "")),
    ages: [...new Set(results.map((result) => result.headers.age).filter(Boolean))].slice(0, 8),
  };
}

async function verifyOverwrite() {
  const overwritePrefix = prefix + "overwrite/";
  const key = overwritePrefix + "same-key.png";
  const firstFile = join(workDir, "same-key-v1.png");
  const secondFile = join(workDir, "same-key-v2.png");
  const firstBytes = createPng({ width: 321, height: 123 });
  const secondBytes = createPng({ width: 654, height: 321 });
  writeFileSync(firstFile, firstBytes);
  writeFileSync(secondFile, secondBytes);
  try {
    await putObject(firstFile, key, "image/png");
    const firstPage = await waitForObjects(overwritePrefix, 1, 2);
    const first = firstPage.payload.items.find((item) => item.key === key);
    assert(first, "overwrite first version was not listed");
    await putObject(secondFile, key, "image/png");
    const secondPage = await waitForObjects(overwritePrefix, 1, 3);
    const second = secondPage.payload.items.find((item) => item.key === key);
    assert(second, "overwrite second version was not listed");
    assert.notEqual(second.etag, first.etag, "overwrite ETag did not change");
    const stale = await curlRequest(first.url, { includeBody: true, label: "overwrite-stale" });
    const current = await curlRequest(second.url, { includeBody: true, label: "overwrite-current" });
    assert.equal(stale.status, 410, "overwrite stale version status");
    assert.equal(current.status, 200, "overwrite current version status");
    assert.equal(hashBytes(current.body), hashBytes(secondBytes), "overwrite current body hash");
    return {
      key,
      firstEtag: first.etag,
      secondEtag: second.etag,
      etagChanged: first.etag !== second.etag,
      staleStatus: stale.status,
      currentStatus: current.status,
      bodyHashMatched: true,
    };
  } finally {
    await deleteObject(key);
  }
}

async function verifyCompatCandidate() {
  const compatBase = "https://8b986652-assets-auth-preview.needcancan.workers.dev";
  const url = new URL("/api/gallery?limit=49", compatBase);
  const list = await curlRequest(url.href, {
    headers: ["Authorization: Bearer " + token],
    includeBody: true,
    label: "compat-list",
  });
  assert.equal(list.status, 200, "compatibility candidate list status");
  const payload = JSON.parse(list.body.toString("utf8"));
  const first = payload.items[0];
  assert(first?.name, "compatibility candidate name field");
  const current = await curlRequest(first.url, { label: "compat-versioned-image" });
  assert.equal(current.status, 200, "compatibility candidate versioned image status");
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const legacyUrl = new URL("/api/image/" + encodeURIComponent(first.key) + "?exp=" + exp + "&sig=" + hmac(first.key + "." + exp), compatBase);
  const legacy = await curlRequest(legacyUrl.href, { label: "compat-legacy-image" });
  assert.equal(legacy.status, 200, "compatibility candidate legacy image status");
  return {
    previewBase: compatBase,
    listStatus: list.status,
    count: payload.count,
    firstName: first.name,
    versionedImageStatus: current.status,
    legacyImageStatus: legacy.status,
  };
}

const files = [];
const keys = [];
const summary = { runId, baseUrl, prefix, maxConcurrency: 8 };
let primaryError;
try {
  summary.trafficBefore = await trafficStatus();
  for (let index = 0; index < 40; index += 1) {
    const fixture = makeFixture(index);
    const number = String(index + 1).padStart(2, "0");
    const key = prefix + number + "." + fixture.ext;
    const file = join(workDir, number + "." + fixture.ext);
    writeFileSync(file, fixture.bytes);
    files.push({ file, key, type: fixture.type });
    keys.push(key);
  }
  for (const file of files) await putObject(file.file, file.key, file.type);
  const page = await waitForObjects(prefix, 40);
  assert.equal(page.payload.items.length, 40, "G6 temporary list count");
  const items = page.payload.items.slice(0, 40);
  const byKey = new Map(items.map((item) => [item.key, item]));
  assert.equal(byKey.size, 40, "G6 list has duplicate keys");
  const extensions = counts(items.map((item) => item.key.slice(item.key.lastIndexOf(".")).toLowerCase()));
  const largest = items.reduce((max, item) => (item.size > max.size ? item : max), items[0]);
  summary.list = {
    status: page.response.status,
    count: page.payload.count,
    truncated: page.payload.truncated,
    formats: extensions,
    firstServerTiming: page.response.headers["server-timing"] || null,
    totalBytes: items.reduce((sum, item) => sum + item.size, 0),
    largest: { name: largest.name, key: largest.key, size: largest.size, etag: largest.etag },
  };
  const urls = items.map((item) => item.url);
  summary.cold = await runBatch("cold", urls, 8);
  summary.hot = await runBatch("hot", urls, 8);
  assert.equal(summary.cold.failed, 0, "cold image batch had failures");
  assert.equal(summary.hot.failed, 0, "hot image batch had failures");

  const crossPop = [];
  for (let index = 0; index < 12; index += 1) {
    const response = await curlRequest(largest.url, { label: "cross-pop-" + index });
    crossPop.push({
      status: response.status,
      timeMs: Number(response.timeMs.toFixed(2)),
      xWorkerCache: response.headers["x-worker-cache"] || null,
      cfCacheStatus: response.headers["cf-cache-status"] || null,
      age: response.headers.age || null,
      cfRay: response.headers["cf-ray"] || null,
      colo: (response.headers["cf-ray"] || "").split("-").pop() || null,
    });
    assert.equal(response.status, 200, "cross POP probe " + index);
  }
  summary.crossPop = {
    requests: crossPop.length,
    statuses: counts(crossPop.map((entry) => String(entry.status))),
    colos: counts(crossPop.map((entry) => entry.colo || "(none)")),
    cache: counts(crossPop.map((entry) => entry.xWorkerCache || "(none)")),
    cfCache: counts(crossPop.map((entry) => entry.cfCacheStatus || "(none)")),
    observations: crossPop,
  };
  summary.overwrite = await verifyOverwrite();
  summary.compatibilityCandidate = await verifyCompatCandidate();
  summary.trafficAfter = await trafficStatus();
} catch (error) {
  primaryError = error;
} finally {
  for (const key of keys) await deleteObject(key);
  try {
    summary.temporaryObjectsRemoved = true;
    summary.trafficAfterCleanup = await trafficStatus();
  } catch (error) {
    summary.temporaryObjectsRemoved = false;
    summary.trafficAfterCleanupError = error.message;
    if (!primaryError) primaryError = error;
  }
  rmSync(workDir, { recursive: true, force: true });
}

if (primaryError) {
  console.error(JSON.stringify({ ...summary, error: primaryError.message }, null, 2));
  process.exitCode = 1;
} else {
  console.log(JSON.stringify(summary, null, 2));
}
