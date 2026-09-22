import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  DIMENSION_ABSOLUTE_MAX_BYTES,
  DIMENSION_LIMITS,
  IMAGE_METADATA_CACHE_VERSION,
} from "../src/constants.js";
import { getImageDimensions, parseImageDimensions, scanImageDimensions } from "../src/dimensions.js";
import { createExecutionContext } from "./helpers/execution-context.js";
import {
  corruptImage,
  createAvif,
  createGif,
  createJpeg,
  createPng,
  createSvg,
  createWebp,
  crossSegmentFixtures,
  imageFixtures,
  largeWebpFixtures,
  scanLimitFixtures,
} from "./helpers/image-fixtures.js";
import { installMockCaches, MockCache } from "./helpers/mock-cache.js";
import { MockR2Bucket } from "./helpers/mock-r2.js";

describe("image dimension parsers", () => {
  it.each([
    ["png", imageFixtures.png, 1200, 800],
    ["gif", imageFixtures.gif, 640, 480],
    ["jpeg", imageFixtures.jpeg, 1600, 900],
    ["webp", imageFixtures.webp, 1024, 768],
    ["svg", imageFixtures.svg, 320, 180],
    ["avif", imageFixtures.avif, 1920, 1080],
  ])("parses %s dimensions", (_name, bytes, width, height) => {
    expect(parseImageDimensions(bytes, `pics/pic/file.${_name}`)).toEqual({
      width,
      height,
      aspectRatio: Number((width / height).toFixed(6)),
    });
  });

  it("does not invent dimensions for corrupt or unsupported content", () => {
    const badPng = Uint8Array.from(createPng());
    badPng.set(new TextEncoder().encode("BAD!"), 12);

    expect(parseImageDimensions(badPng, "pics/pic/bad.png")).toBeNull();
    expect(parseImageDimensions(new TextEncoder().encode("not an image"), "pics/pic/file.bin")).toBeNull();
  });
});

describe("limited dimension scanning", () => {
  let cache;
  let restoreCaches;
  let execution;

  beforeEach(() => {
    cache = new MockCache();
    restoreCaches = installMockCaches(cache);
    execution = createExecutionContext();
  });

  afterEach(() => {
    restoreCaches();
  });

  async function scan(key, bytes, etag = "etag-v1") {
    const bucket = new MockR2Bucket([
      { key, bytes, etag, httpMetadata: { contentType: "application/octet-stream" } },
    ]);
    const metrics = {};
    const result = await getImageDimensions(
      { key, etag, size: bytes.byteLength, uploaded: new Date("2026-09-11T00:00:00.000Z") },
      { pictures_lib: bucket },
      "https://assets.example",
      execution.ctx,
      metrics
    );
    await execution.flush();
    return { bucket, metrics, result };
  }

  it("continues JPEG, SVG and AVIF scans across range boundaries", async () => {
    const cases = [
      ["pics/pic/cross.jpg", crossSegmentFixtures.jpeg, 2048, 1152],
      ["pics/pic/cross.svg", crossSegmentFixtures.svg, 800, 600],
      ["pics/pic/cross.avif", crossSegmentFixtures.avif, 2560, 1440],
    ];

    for (const [key, bytes, width, height] of cases) {
      const { bucket, result } = await scan(key, bytes);
      expect(result).toMatchObject({ width, height, status: "ok" });
      expect(bucket.getCalls.length).toBeGreaterThan(1);
      expect(bucket.getCalls.every((call) => call.options.range.length <= DIMENSION_ABSOLUTE_MAX_BYTES)).toBe(true);
    }
  });

  it("parses large VP8 and VP8L chunks from their headers before the WebP scan limit", async () => {
    const cases = [
      ["pics/pic/large-vp8.webp", largeWebpFixtures.vp8, 2048, 1152],
      ["pics/pic/large-vp8l.webp", largeWebpFixtures.vp8l, 2560, 1440],
    ];

    for (const [key, bytes, width, height] of cases) {
      const { bucket, result } = await scan(key, bytes);

      expect(bytes.byteLength).toBeGreaterThan(DIMENSION_LIMITS.webp.max);
      expect(result).toMatchObject({ width, height, status: "ok" });
      expect(result.status).not.toBe("scan-limit");
      expect(bucket.getCalls).toHaveLength(1);
      expect(bucket.getCalls[0].options.range.length).toBe(DIMENSION_LIMITS.webp.initial);
    }
  });

  it("stops at each format scan limit without reading the full object", async () => {
    const cases = [
      ["pics/pic/large.jpg", scanLimitFixtures.jpeg, 512 * 1024],
      ["pics/pic/large.svg", scanLimitFixtures.svg, 256 * 1024],
      ["pics/pic/large.avif", scanLimitFixtures.avif, 1024 * 1024],
    ];

    for (const [key, bytes, max] of cases) {
      const { bucket, result } = await scan(key, bytes);
      const bytesRead = bucket.getCalls.reduce((sum, call) => sum + call.options.range.length, 0);
      expect(result).toMatchObject({ width: null, height: null, status: "scan-limit" });
      expect(bytesRead).toBeLessThanOrEqual(max);
      expect(bytesRead).toBeLessThan(bytes.byteLength);
    }
  });

  it("returns unsupported-format after the fixed 64 KiB unknown-format budget", async () => {
    const bytes = new Uint8Array(256 * 1024).fill(7);
    const { bucket, result } = await scan("pics/pic/unknown.bin", bytes);

    expect(result).toMatchObject({ width: null, height: null, status: "unsupported-format" });
    expect(bucket.getCalls).toHaveLength(1);
    expect(bucket.getCalls[0].options.range.length).toBe(64 * 1024);
  });

  it("caches successful metadata for one year and failures for five minutes", async () => {
    await scan("pics/pic/cached.png", createPng(), "etag-positive");
    await scan("pics/pic/unknown.bin", new Uint8Array(128 * 1024), "etag-negative");

    const controls = [...cache.responses.values()].map((response) => response.headers.get("Cache-Control"));
    expect(controls).toContain("public, max-age=31536000");
    expect(controls).toContain("public, max-age=300");
    expect(
      [...cache.responses.keys()].some((key) =>
        key.includes("/__cache/image-metadata/" + IMAGE_METADATA_CACHE_VERSION + "/")
      )
    ).toBe(true);
  });

  it("bypasses a legacy negative metadata cache after the cache version changes", async () => {
    const key = "pics/pic/legacy.webp";
    const legacyCacheKey =
      "https://assets.example/__cache/image-metadata/v1/" +
      encodeURIComponent(key) +
      "?v=etag-v1";
    cache.responses.set(
      legacyCacheKey,
      new Response(
        JSON.stringify({
          width: null,
          height: null,
          aspectRatio: null,
          status: "scan-limit",
        }),
        { headers: { "Content-Type": "application/json" } }
      )
    );

    const { bucket, result } = await scan(key, largeWebpFixtures.vp8);

    expect(result).toMatchObject({ width: 2048, height: 1152, status: "ok" });
    expect(bucket.getCalls).toHaveLength(1);
  });

  it("does not share metadata across ETag versions of the same key", async () => {
    const key = "pics/pic/versioned.png";
    const first = await scan(key, createPng({ width: 100, height: 100 }), "etag-v1");
    const second = await scan(key, createPng({ width: 200, height: 100 }), "etag-v2");

    expect(first.result.width).toBe(100);
    expect(second.result.width).toBe(200);
    expect(cache.responses.size).toBe(2);
  });

  it("keeps R2 storage errors as short negative results", async () => {
    const metrics = {};
    const result = await scanImageDimensions(
      { key: "pics/pic/failure.png", etag: "etag-v1", size: 100 },
      { get: async () => { throw new Error("temporary R2 outage"); } },
      metrics
    );

    expect(result).toMatchObject({ width: null, height: null, status: "storage-error" });
  });
});
