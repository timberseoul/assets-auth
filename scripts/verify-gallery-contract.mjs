import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const localContractDir = join(projectRoot, "contract", "gallery");
const peerContractDir = process.argv[2]
  ? resolve(process.argv[2])
  : resolve(projectRoot, "..", "df_blog", "opt", "gallery-contract");

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

const contract = readJson(join(localContractDir, "contract.json"));
const vectors = readJson(join(localContractDir, "signing-vectors.json"));
const fixtures = readJson(join(localContractDir, "response-fixtures.json"));

assert.equal(contract.contractVersion, 1, "unexpected contract version");
assert.equal(contract.status, "frozen", "contract must be frozen");
assert.equal(contract.listRequest.defaultLimit, 40, "default page size must be 40");
assert.equal(contract.listRequest.maxLimit, 50, "maximum page size must be 50");
assert.equal(contract.signature.signedUrlTtlSeconds, 31536000, "signed URL TTL must be one year");
assert.equal(contract.cache.manifestTtlSeconds, 300, "manifest TTL must be five minutes");
assert.equal(contract.cache.dimensionNegativeTtlSeconds, 300, "negative dimension TTL must be five minutes");

const requiredStatuses = [400, 401, 403, 404, 410, 416, 429, 503, 504];
const documentedStatuses = new Set(contract.errors.map((item) => item.status));
for (const status of requiredStatuses) {
  assert(documentedStatuses.has(status), `missing status mapping: ${status}`);
}

assert.equal(vectors.secretIsTestOnly, true, "signing vectors must use a test-only secret");
assert(vectors.vectors.length >= 3, "at least three signing vectors are required");

for (const vector of vectors.vectors) {
  const message = [vector.key, vector.etag, vector.exp].join(".");
  assert.equal(message, vector.message, `message mismatch for ${vector.key}`);
  const signature = createHmac("sha256", vectors.secret).update(message, "utf8").digest("hex");
  assert.equal(signature, vector.signature, `signature mismatch for ${vector.key}`);
}

assert(fixtures.cases.length >= 6, "response fixture coverage is incomplete");
const fixtureNames = new Set(fixtures.cases.map((item) => item.name));
for (const name of [
  "list-page",
  "list-final-page",
  "invalid-cursor",
  "image-not-modified",
  "image-range",
  "image-range-not-satisfiable",
  "image-version-gone",
]) {
  assert(fixtureNames.has(name), `missing response fixture: ${name}`);
}

for (const fixture of fixtures.cases) {
  assert(Number.isInteger(fixture.status), `invalid fixture status: ${fixture.name}`);
  assert(fixture.headers?.["Cache-Control"], `missing cache header: ${fixture.name}`);
}

if (existsSync(peerContractDir)) {
  for (const filename of ["contract.json", "signing-vectors.json", "response-fixtures.json", "README.md"]) {
    const localFile = join(localContractDir, filename);
    const peerFile = join(peerContractDir, filename);
    assert(existsSync(peerFile), `peer contract file missing: ${peerFile}`);
    assert.equal(sha256(peerFile), sha256(localFile), `peer contract drift: ${filename}`);
  }
} else {
  console.warn(`peer contract directory not found, skipped cross-repository comparison: ${peerContractDir}`);
}

console.log(`gallery contract verified: ${vectors.vectors.length} signing vectors, ${fixtures.cases.length} response fixtures`);
