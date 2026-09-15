import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const contractDir = resolve(process.cwd(), "contract", "gallery");
const readJson = (name) => JSON.parse(readFileSync(resolve(contractDir, name), "utf8"));

describe("gallery contract", () => {
  it("matches every frozen signing vector", () => {
    const vectors = readJson("signing-vectors.json");

    for (const vector of vectors.vectors) {
      const message = [vector.key, vector.etag, vector.exp].join(".");
      const signature = createHmac("sha256", vectors.secret).update(message, "utf8").digest("hex");

      expect(message).toBe(vector.message);
      expect(signature).toBe(vector.signature);
    }
  });

  it("keeps pagination and cache fixtures aligned with the frozen contract", () => {
    const contract = readJson("contract.json");
    const fixtures = readJson("response-fixtures.json");
    const listPage = fixtures.cases.find((entry) => entry.name === "list-page");
    const range = fixtures.cases.find((entry) => entry.name === "image-range");

    expect(contract.contractVersion).toBe(1);
    expect(contract.status).toBe("frozen");
    expect(contract.listRequest.defaultLimit).toBe(40);
    expect(contract.listRequest.maxLimit).toBe(50);
    expect(listPage?.body.cursor).toBe("next-page");
    expect(listPage?.body.items[0].etag).toBe("etag-v1");
    expect(listPage?.headers["Cache-Control"]).toBe("private, no-store");
    expect(range?.status).toBe(206);
    expect(range?.headers["Content-Range"]).toBe("bytes 0-15/123456");
  });
});
