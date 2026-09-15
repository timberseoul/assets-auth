import { afterEach, beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index.js";
import { createExecutionContext } from "./helpers/execution-context.js";
import {
  createAvif,
  createGif,
  createJpeg,
  createPng,
  createSvg,
  createWebp,
} from "./helpers/image-fixtures.js";
import { installMockCaches, MockCache } from "./helpers/mock-cache.js";
import { MockR2Bucket } from "./helpers/mock-r2.js";

function mixedRecords() {
  return Array.from({ length: 40 }, (_, index) => {
    const group = index % 6;
    let extension = "png";
    let bytes = createPng({ width: 1600, height: 900 });
    if (group === 1) {
      extension = "gif";
      bytes = createGif({ width: 800, height: 600 });
    } else if (group === 2) {
      extension = "jpg";
      bytes = createJpeg({ width: 2400, height: 1600, padding: index < 8 ? 80 * 1024 : 0 });
    } else if (group === 3) {
      extension = "webp";
      bytes = createWebp({ width: 1600, height: 1000 });
    } else if (group === 4) {
      extension = "svg";
      bytes = createSvg({ width: 1200, height: 800, prefix: index < 8 ? " ".repeat(80 * 1024) : "" });
    } else {
      extension = "avif";
      bytes = createAvif({ width: 2560, height: 1440, padding: index < 8 ? 160 * 1024 : 0 });
    }
    return {
      key: `pics/pic/perf-${String(index).padStart(2, "0")}.${extension}`,
      bytes,
      etag: `perf-etag-${index}`,
      uploaded: new Date("2026-09-11T00:00:00.000Z"),
      httpMetadata: { contentType: "application/octet-stream" },
    };
  });
}

describe("cold 40-image page budget", () => {
  let bucket;
  let cache;
  let restoreCaches;

  beforeEach(() => {
    bucket = new MockR2Bucket(mixedRecords());
    cache = new MockCache();
    restoreCaches = installMockCaches(cache);
  });

  afterEach(() => {
    restoreCaches();
  });

  async function request(query = "limit=40") {
    const execution = createExecutionContext();
    const response = await worker.fetch(
      new Request(`https://assets.example/api/gallery?${query}`, {
        headers: { Authorization: "Bearer test-gallery-token" },
      }),
      {
        pictures_lib: bucket,
        GALLERY_API_TOKEN: "test-gallery-token",
        SIGNING_SECRET: "test-signing-secret",
        SIGNED_URL_TTL: "31536000",
        ALLOWED_ORIGINS: "https://example.com",
      },
      execution.ctx
    );
    await execution.flush();
    return response;
  }

  it("keeps reads bounded and well below the 38.84 MiB legacy baseline", async () => {
    const response = await request();
    const body = await response.json();
    const requestedBytes = bucket.getCalls.reduce((sum, call) => sum + (call.options.range?.length || 0), 0);

    expect(response.status).toBe(200);
    expect(body.items).toHaveLength(40);
    expect(bucket.getCalls.every((call) => call.options.range?.length <= 1024 * 1024)).toBe(true);
    expect(requestedBytes).toBeLessThan(10 * 1024 * 1024);
    expect(requestedBytes).toBeLessThan(38.84 * 1024 * 1024);
  });

  it("uses the manifest cache for the hot page without reading R2 again", async () => {
    await request();
    const listCalls = bucket.listCalls.length;
    const getCalls = bucket.getCalls.length;

    const hot = await request();
    expect(hot.status).toBe(200);
    expect(bucket.listCalls.length).toBe(listCalls);
    expect(bucket.getCalls.length).toBe(getCalls);
  });
});
