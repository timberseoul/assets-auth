import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createHmacSigner,
  normalizeEtag,
  signVersionedKey,
  timingSafeEqualHex,
  versionedSignatureMessage,
} from "../src/signing.js";

describe("versioned HMAC signing", () => {
  const contract = JSON.parse(readFileSync(resolve(process.cwd(), "contract", "gallery", "signing-vectors.json"), "utf8"));

  it("matches the frozen cross-repository vectors", async () => {
    for (const vector of contract.vectors) {
      expect(versionedSignatureMessage(vector.key, vector.etag, vector.exp)).toBe(vector.message);
      await expect(signVersionedKey(vector.key, vector.etag, vector.exp, contract.secret)).resolves.toBe(vector.signature);
    }
  });

  it("normalizes quoted ETags without changing their identity", () => {
    expect(normalizeEtag('"etag-v1"')).toBe("etag-v1");
    expect(normalizeEtag('W/"etag-v2"')).toBe("etag-v2");
    expect(normalizeEtag("etag-v3")).toBe("etag-v3");
  });

  it("uses the ETag-versioned signature message", async () => {
    const exp = 1800000000;
    const versioned = await signVersionedKey("pics/pic/a.png", "etag-v1", exp, "test-secret");
    expect(versioned).toMatch(/^[a-f0-9]{64}$/);
    expect(timingSafeEqualHex(versioned, versioned)).toBe(true);
    expect(timingSafeEqualHex(versioned, "0".repeat(64))).toBe(false);
  });

  it("reuses one signer for repeated messages", async () => {
    const signer = createHmacSigner("test-secret");
    const first = await signer.sign("first");
    const second = await signer.sign("second");

    expect(first).toMatch(/^[a-f0-9]{64}$/);
    expect(second).toMatch(/^[a-f0-9]{64}$/);
    expect(first).not.toBe(second);
  });
});
