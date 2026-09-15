import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

const baseUrl = String(process.env.PREVIEW_BASE_URL || "").replace(/\/$/, "");
const token = process.env.GALLERY_API_TOKEN || "";
const secret = process.env.SIGNING_SECRET || "";

assert(baseUrl, "PREVIEW_BASE_URL is required");
assert(token, "GALLERY_API_TOKEN is required");
assert(secret, "SIGNING_SECRET is required");

const sign = (message) => createHmac("sha256", secret).update(message, "utf8").digest("hex");

async function request(path, init = {}) {
  const response = await fetch(`${baseUrl}${path}`, init);
  return response;
}

const summary = {
  baseUrl,
  list: {},
  image: {},
  checks: {},
};

const listResponse = await request("/api/gallery?limit=40", {
  headers: { Authorization: `Bearer ${token}` },
});
assert.equal(listResponse.status, 200, `list status ${listResponse.status}`);
assert.equal(listResponse.headers.get("Cache-Control"), "private, no-store");
assert(listResponse.headers.get("Server-Timing"));

const list = await listResponse.json();
assert.equal(list.count, list.items.length);
assert(list.items.length > 0, "preview list is empty");
assert(list.count <= 40);
assert.equal(typeof list.truncated, "boolean");
assert(list.truncated ? typeof list.cursor === "string" && list.cursor.length > 0 : list.cursor === null);
assert(Number.isSafeInteger(list.generatedAt));
assert(Number.isSafeInteger(list.expiresAt));

const first = list.items[0];
assert(first.key.startsWith("pics/pic/"));
assert(first.etag);
assert(Number.isSafeInteger(first.size));
assert(first.uploaded === null || typeof first.uploaded === "string");

const signedUrl = new URL(first.url);
assert.equal(signedUrl.searchParams.get("v"), first.etag);
assert(Number(signedUrl.searchParams.get("exp")) > Math.floor(Date.now() / 1000));
const expectedSignature = sign(`${first.key}.${first.etag}.${signedUrl.searchParams.get("exp")}`);
assert.equal(signedUrl.searchParams.get("sig"), expectedSignature);

summary.list = {
  count: list.count,
  truncated: list.truncated,
  cursorPresent: Boolean(list.cursor),
  firstKey: first.key,
  etag: first.etag,
  generatedAt: list.generatedAt,
  expiresAt: list.expiresAt,
};

const imageResponse = await request(`${signedUrl.pathname}${signedUrl.search}`);
assert.equal(imageResponse.status, 200, `image status ${imageResponse.status}`);
assert.equal(imageResponse.headers.get("Access-Control-Allow-Origin"), "*");
assert.equal(imageResponse.headers.get("Cross-Origin-Resource-Policy"), "cross-origin");
assert.equal(imageResponse.headers.get("Cache-Control"), "public, max-age=31536000, immutable");
const imageBytes = new Uint8Array(await imageResponse.arrayBuffer());
assert(imageBytes.byteLength > 0, "image body is empty");

await new Promise((resolve) => setTimeout(resolve, 100));
const cachedImage = await request(`${signedUrl.pathname}${signedUrl.search}`);
assert.equal(cachedImage.status, 200);
assert.equal(cachedImage.headers.get("X-Worker-Cache"), "HIT");

const headResponse = await request(`${signedUrl.pathname}${signedUrl.search}`, { method: "HEAD" });
assert.equal(headResponse.status, 200);
assert.equal(headResponse.headers.get("X-Worker-Cache"), "BYPASS-HEAD");
assert.equal(headResponse.headers.get("Content-Length"), String(first.size));

const rangeResponse = await request(`${signedUrl.pathname}${signedUrl.search}`, {
  headers: { Range: "bytes=0-15" },
});
assert.equal(rangeResponse.status, 206);
assert.equal(rangeResponse.headers.get("X-Worker-Cache"), "BYPASS-RANGE");
assert.match(rangeResponse.headers.get("Content-Range") || "", /^bytes 0-15\//);
assert.equal((await rangeResponse.arrayBuffer()).byteLength, 16);

const conditionalResponse = await request(`${signedUrl.pathname}${signedUrl.search}`, {
  headers: { "If-None-Match": imageResponse.headers.get("ETag") || "" },
});
assert.equal(conditionalResponse.status, 304);

const legacyExp = Math.floor(Date.now() / 1000) + 3600;
const legacySignature = sign(`${first.key}.${legacyExp}`);
const legacyResponse = await request(
  `/api/image/${encodeURIComponent(first.key)}?exp=${legacyExp}&sig=${legacySignature}`
);
assert.equal(legacyResponse.status, 200, `legacy image status ${legacyResponse.status}`);

const invalidSignature = await request(`${signedUrl.pathname}${signedUrl.search.replace(/sig=[a-f0-9]+/, `sig=${"0".repeat(64)}`)}`);
assert.equal(invalidSignature.status, 403);

const invalidRange = await request(`${signedUrl.pathname}${signedUrl.search}`, {
  headers: { Range: "bytes=999999999-" },
});
assert.equal(invalidRange.status, 416);

summary.image = {
  status: imageResponse.status,
  cacheStatus: cachedImage.headers.get("X-Worker-Cache"),
  etag: imageResponse.headers.get("ETag"),
  rangeStatus: rangeResponse.status,
  conditionalStatus: conditionalResponse.status,
  legacyStatus: legacyResponse.status,
};
summary.checks = {
  versionedSignature: true,
  legacySignature: true,
  fullGetCache: true,
  headBypass: true,
  rangeBypass: true,
  notModified: true,
  invalidSignatureRejected: true,
  invalidRangeRejected: true,
};

console.log(JSON.stringify(summary, null, 2));
