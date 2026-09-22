import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index.js";
import { createExecutionContext } from "./helpers/execution-context.js";
import { createPng } from "./helpers/image-fixtures.js";
import { installMockCaches, MockCache } from "./helpers/mock-cache.js";
import { MockR2Bucket } from "./helpers/mock-r2.js";

describe("cursor gallery manifest", () => {
  const secret = "test-signing-secret";
  const token = "test-gallery-token";
  let bucket;
  let cache;
  let restoreCaches;

  beforeEach(() => {
    const records = Array.from({ length: 100 }, (_, index) => {
      const suffix = String(index).padStart(3, "0");
      return {
        key: `pics/pic/${suffix}.png`,
        bytes: createPng({ width: 100 + index, height: 100 }),
        etag: `etag-${index}`,
        uploaded: new Date(`2026-09-${String((index % 10) + 1).padStart(2, "0")}T00:00:00.000Z`),
        httpMetadata: { contentType: "image/png" },
      };
    });
    bucket = new MockR2Bucket(records);
    cache = new MockCache();
    restoreCaches = installMockCaches(cache);
  });

  afterEach(() => {
    vi.useRealTimers();
    restoreCaches();
  });

  async function request(path, headers = { Authorization: `Bearer ${token}` }, init = {}) {
    const execution = createExecutionContext();
    const response = await worker.fetch(
      new Request(`https://assets.example${path}`, { ...init, headers }),
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

  it("defaults to 40, caps at 50 and rejects invalid bounds", async () => {
    const first = await request("/api/gallery");
    const body = await first.json();

    expect(first.status).toBe(200);
    expect(body.count).toBe(40);
    expect(body.truncated).toBe(true);
    expect(body.cursor).toBeTruthy();
    expect(bucket.listCalls.at(-1)?.limit).toBe(40);

    const max = await request("/api/gallery?limit=50");
    expect(max.status).toBe(200);
    expect((await max.json()).count).toBe(50);

    for (const query of ["limit=0", "limit=51", "limit=abc", "limit=1.5"]) {
      const invalid = await request(`/api/gallery?${query}`);
      expect(invalid.status).toBe(400);
    }
  });

  it("rejects disallowed prefixes, oversized cursors and control characters", async () => {
    const cases = [
      "prefix=pics%2Fother%2F",
      "prefix=pics%2Fpic%2F..%2Fsecret%2F",
      `cursor=${"x".repeat(513)}`,
      "cursor=bad%00cursor",
    ];

    for (const query of cases) {
      const response = await request(`/api/gallery?${query}`);
      expect(response.status).toBe(400);
    }
  });

  it("returns one R2 page and a cursor without overlapping keys", async () => {
    const first = await request("/api/gallery?limit=40");
    const firstBody = await first.json();
    const second = await request(`/api/gallery?limit=40&cursor=${encodeURIComponent(firstBody.cursor)}`);
    const secondBody = await second.json();
    const firstKeys = new Set(firstBody.items.map((item) => item.key));

    expect(firstBody.items).toHaveLength(40);
    expect(secondBody.items).toHaveLength(40);
    expect(secondBody.items.every((item) => !firstKeys.has(item.key))).toBe(true);
    expect(bucket.listCalls.map((call) => call.limit)).toEqual([40, 40]);
  });

  it("refreshes signatures from a manifest cache without signed URL leakage", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-11T00:00:00.000Z"));

    const first = await request("/api/gallery?limit=40");
    const firstBody = await first.json();
    const listCalls = bucket.listCalls.length;

    vi.setSystemTime(new Date("2026-09-11T00:00:10.000Z"));
    const second = await request("/api/gallery?limit=40");
    const secondBody = await second.json();

    expect(bucket.listCalls.length).toBe(listCalls);
    expect(secondBody.generatedAt).toBe(firstBody.generatedAt);
    expect(secondBody.expiresAt).toBe(firstBody.expiresAt + 10);
    expect(secondBody.items[0].url).not.toBe(firstBody.items[0].url);

    const manifestEntry = [...cache.responses.entries()].find(([key]) => key.includes("/__cache/gallery-manifest"));
    expect(manifestEntry).toBeTruthy();
    expect(manifestEntry[0]).toContain("/__cache/gallery-manifest/v2");
    const manifest = await manifestEntry[1].clone().json();
    expect(JSON.stringify(manifest)).not.toMatch(/"(?:url|sig|exp|expiresAt)"\s*:/);
    expect(manifest.items[0]).toMatchObject({ width: 100, height: 100, aspectRatio: 1 });
  });

  it("rebuilds a legacy manifest cache that has no dimension fields", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-11T00:00:00.000Z"));

    const cacheKey = new URL("https://assets.example/__cache/gallery-manifest/v2");
    cacheKey.searchParams.set("prefix", "pics/pic/");
    cacheKey.searchParams.set("limit", "1");
    cache.responses.set(
      cacheKey.toString(),
      new Response(
        JSON.stringify({
          items: [
            {
              key: "pics/pic/000.png",
              etag: "etag-0",
              name: "000.png",
              size: 100,
              uploaded: "2026-09-11T00:00:00.000Z",
            },
          ],
          truncated: false,
          cursor: null,
          generatedAt: Math.floor(Date.now() / 1000),
        }),
        { headers: { "Content-Type": "application/json" } }
      )
    );

    const response = await request("/api/gallery?limit=1");
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.items[0]).toMatchObject({ width: 100, height: 100, aspectRatio: 1 });
    expect(bucket.listCalls).toHaveLength(1);
  });

  it("sets private no-store and emits Server-Timing", async () => {
    const response = await request("/api/gallery?limit=40");

    expect(response.headers.get("Cache-Control")).toBe("private, no-store");
    expect(response.headers.get("Server-Timing")).toMatch(/r2-list;dur=/);
    expect(response.headers.get("Server-Timing")).toMatch(/manifest-cache;dur=/);
    expect(response.headers.get("Server-Timing")).toMatch(/dimension-/);
  });

  it("limits list CORS to configured origins while allowing server requests", async () => {
    const allowed = await request("/api/gallery?limit=40", {
      Authorization: `Bearer ${token}`,
      Origin: "https://example.com",
    });
    const rejected = await request("/api/gallery?limit=40", {
      Authorization: `Bearer ${token}`,
      Origin: "https://attacker.example",
    });
    const server = await request("/api/gallery?limit=40", { Authorization: `Bearer ${token}` });
    const preflight = await request("/api/gallery", { Origin: "https://example.com" }, { method: "OPTIONS" });
    const blockedPreflight = await request("/api/gallery", { Origin: "https://attacker.example" }, { method: "OPTIONS" });

    expect(allowed.status).toBe(200);
    expect(allowed.headers.get("Access-Control-Allow-Origin")).toBe("https://example.com");
    expect(rejected.status).toBe(403);
    expect(rejected.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(server.status).toBe(200);
    expect(preflight.status).toBe(204);
    expect(blockedPreflight.status).toBe(403);
  });

  it("treats a truncated page without cursor as storage failure", async () => {
    bucket.list = async () => ({ objects: [], truncated: true, cursor: undefined, delimitedPrefixes: [] });
    const response = await request("/api/gallery?limit=40");

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "Storage Unavailable" });
  });

  it("reuses one dimension promise for duplicate key and ETag entries", async () => {
    const bytes = createPng({ width: 321, height: 123 });
    const record = {
      key: "pics/pic/duplicate.png",
      bytes,
      etag: "etag-duplicate",
      uploaded: new Date("2026-09-11T00:00:00.000Z"),
      httpMetadata: { contentType: "image/png" },
    };
    bucket = new MockR2Bucket([record]);
    const metadata = {
      key: record.key,
      etag: record.etag,
      size: bytes.byteLength,
      uploaded: record.uploaded,
    };
    bucket.list = async () => ({ objects: [metadata, metadata], truncated: false, cursor: undefined, delimitedPrefixes: [] });

    const response = await request("/api/gallery?limit=40");
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.items).toHaveLength(2);
    expect(body.items[0].width).toBe(321);
    expect(bucket.getCalls).toHaveLength(1);
  });
});
