import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index.js";
import { createExecutionContext } from "./helpers/execution-context.js";
import { imageFixtures } from "./helpers/image-fixtures.js";
import { installMockCaches, MockCache } from "./helpers/mock-cache.js";
import { MockR2Bucket } from "./helpers/mock-r2.js";

function signature(key, etag, exp, secret) {
  return createHmac("sha256", secret).update([key, etag, exp].join("."), "utf8").digest("hex");
}

describe("versioned image HTTP behavior", () => {
  const secret = "test-signing-secret";
  const key = "pics/pic/image.png";
  let bucket;
  let cache;
  let restoreCaches;

  beforeEach(() => {
    bucket = new MockR2Bucket([
      {
        key,
        bytes: imageFixtures.png,
        etag: "etag-v1",
        httpMetadata: {
          contentType: "image/png",
          cacheControl: "public, max-age=1",
          contentDisposition: 'inline; filename="image.png"',
        },
      },
    ]);
    cache = new MockCache();
    restoreCaches = installMockCaches(cache);
  });

  afterEach(() => {
    restoreCaches();
  });

  function signedPath(etag = "etag-v1", exp = Math.floor(Date.now() / 1000) + 3600) {
    const sig = signature(key, etag, exp, secret);
    return `/api/image/${encodeURIComponent(key)}?v=${encodeURIComponent(etag)}&exp=${exp}&sig=${sig}`;
  }

  async function request(path, init = {}) {
    const execution = createExecutionContext();
    const response = await worker.fetch(
      new Request(`https://assets.example${path}`, init),
      { pictures_lib: bucket, SIGNING_SECRET: secret },
      execution.ctx
    );
    await execution.flush();
    return response;
  }

  it("serves full GET responses with fixed public headers and MISS to HIT caching", async () => {
    const first = await request(signedPath());
    expect(first.status).toBe(200);
    expect(first.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
    expect(first.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(first.headers.get("Cross-Origin-Resource-Policy")).toBe("cross-origin");
    expect(first.headers.get("Accept-Ranges")).toBe("bytes");
    expect(first.headers.get("ETag")).toBe('"etag-v1"');
    expect(first.headers.get("Content-Disposition")).toBe('inline; filename="image.png"');
    expect(first.headers.get("Content-Length")).toBe(String(imageFixtures.png.byteLength));
    expect(first.headers.get("X-Worker-Cache")).toBe("MISS");
    expect(new Uint8Array(await first.arrayBuffer())).toEqual(imageFixtures.png);

    const second = await request(signedPath());
    expect(second.status).toBe(200);
    expect(second.headers.get("X-Worker-Cache")).toBe("HIT");
  });

  it("returns 304 for strong and weak If-None-Match values", async () => {
    const strong = await request(signedPath(), { headers: { "If-None-Match": '"etag-v1"' } });
    const weak = await request(signedPath(), { headers: { "If-None-Match": 'W/"etag-v1"' } });

    expect(strong.status).toBe(304);
    expect(weak.status).toBe(304);
    expect(strong.headers.get("ETag")).toBe('"etag-v1"');
    expect(await strong.text()).toBe("");
  });

  it("handles HEAD from R2 head without filling the full image cache", async () => {
    const response = await request(signedPath(), { method: "HEAD" });

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Length")).toBe(String(imageFixtures.png.byteLength));
    expect(response.headers.get("X-Worker-Cache")).toBe("BYPASS-HEAD");
    expect(bucket.headCalls).toHaveLength(1);
    expect(bucket.getCalls).toHaveLength(0);
    expect([...cache.responses.keys()].some((cacheKey) => cacheKey.includes("/__cache/image/"))).toBe(false);
  });

  it("serves bytes ranges with 206 and does not pollute the full image cache", async () => {
    const response = await request(signedPath(), { headers: { Range: "bytes=0-15" } });
    const body = new Uint8Array(await response.arrayBuffer());

    expect(response.status).toBe(206);
    expect(response.headers.get("Content-Range")).toBe(`bytes 0-15/${imageFixtures.png.byteLength}`);
    expect(response.headers.get("Content-Length")).toBe("16");
    expect(response.headers.get("X-Worker-Cache")).toBe("BYPASS-RANGE");
    expect(body).toEqual(imageFixtures.png.slice(0, 16));
    expect([...cache.responses.keys()].some((cacheKey) => cacheKey.includes("/__cache/image/"))).toBe(false);

    const full = await request(signedPath());
    expect(full.status).toBe(200);
    expect(full.headers.get("X-Worker-Cache")).toBe("MISS");
  });

  it("supports suffix and open-ended ranges", async () => {
    const suffix = await request(signedPath(), { headers: { Range: "bytes=-8" } });
    const open = await request(signedPath(), { headers: { Range: "bytes=8-" } });

    expect(suffix.status).toBe(206);
    expect(suffix.headers.get("Content-Range")).toBe(`bytes ${imageFixtures.png.byteLength - 8}-${imageFixtures.png.byteLength - 1}/${imageFixtures.png.byteLength}`);
    expect(open.status).toBe(206);
    expect(open.headers.get("Content-Length")).toBe(String(imageFixtures.png.byteLength - 8));
  });

  it("returns 416 with an unsatisfied Content-Range for malformed or multiple ranges", async () => {
    for (const range of ["bytes=999999-", "bytes=20-10", "bytes=0-1,4-5", "items=0-1"]) {
      const response = await request(signedPath(), { headers: { Range: range } });
      expect(response.status).toBe(416);
      expect(response.headers.get("Content-Range")).toBe(`bytes */${imageFixtures.png.byteLength}`);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
    }
  });

  it("returns 410 when the requested version no longer matches R2", async () => {
    const path = signedPath("etag-v1");
    bucket.setObject(key, {
      bytes: imageFixtures.png,
      etag: "etag-v2",
      httpMetadata: { contentType: "image/png" },
    });

    const response = await request(path);
    expect(response.status).toBe(410);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("keeps malformed keys and internal errors out of image caches", async () => {
    const malformed = await request("/api/image/%E0%A4%A?exp=1&sig=0".padEnd(100, "0"));
    const outOfScope = await request(`/api/image/${encodeURIComponent("pics/other/image.png")}?exp=1&sig=0`);
    const post = await request(signedPath(), { method: "POST" });

    expect(malformed.status).toBe(400);
    expect(outOfScope.status).toBe(403);
    expect(post.status).toBe(405);
    for (const response of [malformed, outOfScope, post]) {
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
      expect(await response.text()).not.toMatch(/SIGNING_SECRET|test-signing-secret|detail/i);
    }
  });

  it("handles image OPTIONS with wildcard CORS", async () => {
    const response = await request(signedPath(), { method: "OPTIONS" });

    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(response.headers.get("Access-Control-Allow-Methods")).toContain("HEAD");
  });

  it("returns 404 for missing objects and 503 without leaking storage errors", async () => {
    const missingPath = signedPath();
    bucket.deleteObject(key);
    const missing = await request(missingPath);

    expect(missing.status).toBe(404);
    expect(missing.headers.get("Cache-Control")).toBe("no-store");

    bucket.get = async () => { throw new Error("private storage detail"); };
    const unavailable = await request(signedPath());
    expect(unavailable.status).toBe(503);
    expect(await unavailable.text()).not.toContain("private storage detail");
  });

  it("honors If-None-Match for HEAD without a response body", async () => {
    const response = await request(signedPath(), {
      method: "HEAD",
      headers: { "If-None-Match": '"etag-v1"' },
    });

    expect(response.status).toBe(304);
    expect(await response.text()).toBe("");
    expect(response.headers.get("X-Worker-Cache")).toBeNull();
  });
});
