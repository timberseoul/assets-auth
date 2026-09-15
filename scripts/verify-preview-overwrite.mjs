import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { createPng } from "../test/helpers/image-fixtures.js";

const baseUrl = String(process.env.PREVIEW_BASE_URL || "").replace(/\/$/, "");
const token = process.env.GALLERY_API_TOKEN || "";
const secret = process.env.SIGNING_SECRET || "";
const bucket = "pictures-lib";
const key = "pics/pic/__w6_preview__/same-key.png";
const objectPath = `${bucket}/${key}`;
const tempDir = resolve(process.cwd(), ".wrangler");
const firstFile = resolve(tempDir, "w6-preview-v1.png");
const secondFile = resolve(tempDir, "w6-preview-v2.png");

assert(baseUrl, "PREVIEW_BASE_URL is required");
assert(token, "GALLERY_API_TOKEN is required");
assert(secret, "SIGNING_SECRET is required");

const firstBytes = createPng({ width: 321, height: 123 });
const secondBytes = createPng({ width: 654, height: 321 });
mkdirSync(tempDir, { recursive: true });
writeFileSync(firstFile, firstBytes);
writeFileSync(secondFile, secondBytes);

const sign = (message) => createHmac("sha256", secret).update(message, "utf8").digest("hex");
const hashCode = (bytes) => createHash("sha256").update(bytes).digest("hex");

function wrangler(args, allowFailure = false) {
  const result = spawnSync("pnpm", ["exec", "wrangler", ...args], {
    cwd: process.cwd(),
    shell: true,
    stdio: allowFailure ? "pipe" : "inherit",
    encoding: "utf8",
  });
  if (!allowFailure && result.status !== 0) {
    throw new Error(`wrangler failed: ${args.join(" ")}`);
  }
  return result;
}

function putObject(file) {
  wrangler([
    "r2",
    "object",
    "put",
    objectPath,
    "--file",
    file,
    "--remote",
    "--force",
    "--content-type",
    "image/png",
  ]);
}

function deleteObject() {
  wrangler(["r2", "object", "delete", objectPath, "--remote", "--force"], true);
}

async function listPage(limit) {
  const url = new URL("/api/gallery", baseUrl);
  url.searchParams.set("prefix", "pics/pic/__w6_preview__/");
  url.searchParams.set("limit", String(limit));
  const response = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  assert.equal(response.status, 200, `list status ${response.status}`);
  return response.json();
}

function versionUrl(etag, fileHash) {
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const sig = sign(`${key}.${etag}.${exp}`);
  return {
    url: `${baseUrl}/api/image/${encodeURIComponent(key)}?v=${encodeURIComponent(etag)}&exp=${exp}&sig=${sig}`,
    fileHash,
  };
}

let summary;
try {
  putObject(firstFile);
  const firstList = await listPage(2);
  const first = firstList.items.find((item) => item.key === key);
  assert(first, "first version was not listed");
  const firstUrl = versionUrl(first.etag, hashCode(firstBytes));

  putObject(secondFile);
  const secondList = await listPage(3);
  const second = secondList.items.find((item) => item.key === key);
  assert(second, "second version was not listed");
  assert.notEqual(second.etag, first.etag, "overwrite did not change the ETag");
  const secondUrl = versionUrl(second.etag, hashCode(secondBytes));

  const staleResponse = await fetch(firstUrl.url);
  assert.equal(staleResponse.status, 410, `old version status ${staleResponse.status}`);

  const currentResponse = await fetch(secondUrl.url);
  assert.equal(currentResponse.status, 200, `new version status ${currentResponse.status}`);
  const currentBytes = new Uint8Array(await currentResponse.arrayBuffer());
  assert.equal(hashCode(currentBytes), secondUrl.fileHash, "new version body mismatch");

  summary = {
    key,
    firstEtag: first.etag,
    secondEtag: second.etag,
    staleVersionStatus: staleResponse.status,
    currentVersionStatus: currentResponse.status,
    etagChanged: first.etag !== second.etag,
    bodyHashMatched: true,
  };
} finally {
  deleteObject();
}

const finalList = await listPage(4);
assert.equal(finalList.items.some((item) => item.key === key), false, "temporary key was not removed");
summary.temporaryObjectRemoved = true;
console.log(JSON.stringify(summary, null, 2));
