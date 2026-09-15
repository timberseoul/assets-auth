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

describe("ETag-versioned image identity", () => {
  const secret = "test-signing-secret";
  const token = "test-gallery-token";
  const key = "pics/pic/versioned.png";
  let bucket;
  let cache;
  let restoreCaches;

  beforeEach(() => {
    bucket = new MockR2Bucket([
      {
        key,
        bytes: imageFixtures.png,
        etag: "etag-v1",
        httpMetadata: { contentType: "image/png" },
      },
    ]);
    cache = new MockCache();
    restoreCaches = installMockCaches(cache);
  });

  afterEach(() => {
    restoreCaches();
  });

  async function request(path, init = {}) {
    const execution = createExecutionContext();
    const response = await worker.fetch(
      new Request(`https://assets.example${path}`, init),
      {
        pictures_lib: bucket,
        GALLERY_API_TOKEN: token,
        SIGNING_SECRET: secret,
        SIGNED_URL_TTL: "31536000",
        ALLOWED_ORIGINS: "https://example.com",
      },
      execution.ctx
    );
    await execution.flush();
    return response;
  }

  function imagePath(etag, exp) {
    return `/api/image/${encodeURIComponent(key)}?v=${encodeURIComponent(etag)}&exp=${exp}&sig=${signature(key, etag, exp, secret)}`;
  }

  it("emits v, etag, exp and sig in list items", async () => {
    const response = await request("/api/gallery?limit=40", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await response.json();
    const url = new URL(body.items[0].url);

    expect(body.items[0].etag).toBe("etag-v1");
    expect(url.searchParams.get("v")).toBe("etag-v1");
    expect(url.searchParams.get("sig")).toBe(signature(key, "etag-v1", Number(url.searchParams.get("exp")), secret));
    expect(Number(url.searchParams.get("exp")) - Math.floor(Date.now() / 1000)).toBeGreaterThan(31535000);
  });

  it("uses key plus etag in the image cache and avoids R2 on a version cache hit", async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const path = imagePath("etag-v1", exp);

    expect((await request(path)).status).toBe(200);
    const callsAfterMiss = bucket.getCalls.length;
    const second = await request(path);

    expect(second.status).toBe(200);
    expect(second.headers.get("X-Worker-Cache")).toBe("HIT");
    expect(bucket.getCalls.length).toBe(callsAfterMiss);
    expect([...cache.responses.keys()].some((cacheKey) => cacheKey.includes("?v=etag-v1"))).toBe(true);
  });

  it("does not serve new object content through an old version URL", async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const oldPath = imagePath("etag-v1", exp);

    bucket.setObject(key, {
      bytes: imageFixtures.png,
      etag: "etag-v2",
      httpMetadata: { contentType: "image/png" },
    });

    const response = await request(oldPath);
    expect(response.status).toBe(410);
  });

  it("rejects malformed and empty v values", async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const sig = signature(key, "", exp, secret);
    const empty = await request(`/api/image/${encodeURIComponent(key)}?v=&exp=${exp}&sig=${sig}`);
    const control = await request(`/api/image/${encodeURIComponent(key)}?v=bad%00value&exp=${exp}&sig=${sig}`);

    expect(empty.status).toBe(400);
    expect(control.status).toBe(400);
  });
});
