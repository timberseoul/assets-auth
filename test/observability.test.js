import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index.js";
import { createExecutionContext } from "./helpers/execution-context.js";
import { createPng } from "./helpers/image-fixtures.js";
import { installMockCaches, MockCache } from "./helpers/mock-cache.js";
import { MockR2Bucket } from "./helpers/mock-r2.js";

describe("safe request observability", () => {
  let restoreCaches;

  beforeEach(() => {
    restoreCaches = installMockCaches(new MockCache());
  });

  afterEach(() => {
    restoreCaches();
    vi.restoreAllMocks();
  });

  async function request(path, bucket, init = {}) {
    const execution = createExecutionContext();
    const response = await worker.fetch(
      new Request(`https://assets.example${path}`, init),
      {
        pictures_lib: bucket,
        GALLERY_API_TOKEN: "top-secret-token",
        SIGNING_SECRET: "top-secret-signing-key",
        SIGNED_URL_TTL: "31536000",
        ALLOWED_ORIGINS: "https://example.com",
      },
      execution.ctx
    );
    await execution.flush();
    return response;
  }

  it("logs cache state and metrics without Authorization, secret or full signed URL", async () => {
    const logs = [];
    vi.spyOn(console, "log").mockImplementation((value) => logs.push(String(value)));
    const key = "pics/pic/observable.png";
    const bucket = new MockR2Bucket([
      {
        key,
        bytes: createPng(),
        etag: "etag-v1",
        httpMetadata: { contentType: "image/png" },
      },
    ]);

    const gallery = await request("/api/gallery?limit=40", bucket, {
      headers: { Authorization: "Bearer top-secret-token" },
    });
    const galleryBody = await gallery.json();
    await request(new URL(galleryBody.items[0].url).pathname + new URL(galleryBody.items[0].url).search, bucket);

    const output = logs.join("\n");
    expect(output).toContain("gallery_metrics");
    expect(output).toContain("gallery_request");
    expect(output).toContain('"cache":"MISS"');
    expect(output).not.toContain("top-secret-token");
    expect(output).not.toContain("top-secret-signing-key");
    expect(output).not.toContain("Authorization");
    expect(output).not.toContain("sig=");
    expect(output).not.toContain("https://assets.example/api/image/");
  });
});
