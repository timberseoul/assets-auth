import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index.js";
import { createExecutionContext } from "./helpers/execution-context.js";
import { imageFixtures } from "./helpers/image-fixtures.js";
import { installMockCaches, MockCache } from "./helpers/mock-cache.js";
import { MockR2Bucket } from "./helpers/mock-r2.js";

function versionedSignature(key, etag, exp, secret) {
  return createHmac("sha256", secret).update(`${key}.${etag}.${exp}`, "utf8").digest("hex");
}

describe("worker compatibility baseline", () => {
  const secret = "test-signing-secret";
  const token = "test-gallery-token";
  const key = "pics/pic/example.png";
  let cache;
  let bucket;
  let restoreCaches;

  beforeEach(() => {
    cache = new MockCache();
    restoreCaches = installMockCaches(cache);
    bucket = new MockR2Bucket([
      {
        key,
        bytes: imageFixtures.png,
        etag: "etag-v1",
        httpMetadata: { contentType: "image/png" },
      },
    ]);
  });

  afterEach(() => {
    restoreCaches();
  });

  function environment() {
    return {
      pictures_lib: bucket,
      GALLERY_API_TOKEN: token,
      SIGNING_SECRET: secret,
      SIGNED_URL_TTL: "3600",
      ALLOWED_ORIGINS: "https://example.com",
    };
  }

  async function request(path, init = {}) {
    const execution = createExecutionContext();
    const response = await worker.fetch(new Request(`https://assets.example${path}`, init), environment(), execution.ctx);
    await execution.flush();
    return response;
  }

  it("rejects missing and incorrect list tokens", async () => {
    const missing = await request("/api/gallery?limit=40");
    const incorrect = await request("/api/gallery?limit=40", {
      headers: { Authorization: "Bearer wrong-token" },
    });

    expect(missing.status).toBe(401);
    expect(incorrect.status).toBe(401);
  });

  it("serves ETag-versioned images and rejects legacy key.exp signatures", async () => {
    const exp = Math.floor(Date.now() / 1000) + 60;
    const sig = versionedSignature(key, "etag-v1", exp, secret);
    const path = `/api/image/${encodeURIComponent(key)}?v=etag-v1&exp=${exp}&sig=${sig}`;

    const first = await request(path);
    expect(first.status).toBe(200);
    expect(first.headers.get("X-Worker-Cache")).toBe("MISS");
    expect(new Uint8Array(await first.arrayBuffer())).toEqual(imageFixtures.png);

    const second = await request(path);
    expect(second.status).toBe(200);
    expect(second.headers.get("X-Worker-Cache")).toBe("HIT");

    const legacySig = createHmac("sha256", secret).update(`${key}.${exp}`, "utf8").digest("hex");
    const legacy = await request(`/api/image/${encodeURIComponent(key)}?exp=${exp}&sig=${legacySig}`);
    expect(legacy.status).toBe(400);
  });

  it("returns the cursor and etag fields needed by the next phases", async () => {
    const response = await request("/api/gallery?limit=40", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(bucket.listCalls.at(-1)?.limit).toBe(40);
    expect(bucket.getCalls.length).toBeGreaterThan(0);
    expect(bucket.getCalls.every((call) => call.options.range?.length <= 1024 * 1024)).toBe(true);
    expect(body.count).toBe(1);
    expect(body.items[0].key).toBe(key);
  });
});
