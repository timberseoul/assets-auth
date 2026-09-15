function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return new TextEncoder().encode(String(value));
}

function quoteEtag(etag) {
  return `"${etag}"`;
}

function rangeSlice(bytes, range) {
  if (!range) return bytes;
  if ("suffix" in range) {
    const length = Math.min(bytes.byteLength, Math.max(0, range.suffix));
    return bytes.slice(bytes.byteLength - length);
  }

  const offset = Math.min(bytes.byteLength, Math.max(0, range.offset ?? 0));
  const length = Math.max(0, range.length ?? bytes.byteLength - offset);
  return bytes.slice(offset, Math.min(bytes.byteLength, offset + length));
}

export class MockR2Object {
  constructor(record, bytes = record.bytes, range = null) {
    this.key = record.key;
    this.version = record.version ?? "1";
    this.size = bytes.byteLength;
    this.etag = record.etag;
    this.httpEtag = quoteEtag(record.etag);
    this.uploaded = new Date(record.uploaded);
    this.httpMetadata = { ...(record.httpMetadata ?? {}) };
    this.customMetadata = { ...(record.customMetadata ?? {}) };
    this.range = range;
    this.bytes = bytes;
  }

  writeHttpMetadata(headers) {
    const metadata = this.httpMetadata;
    if (metadata.contentType) headers.set("Content-Type", metadata.contentType);
    if (metadata.contentLanguage) headers.set("Content-Language", metadata.contentLanguage);
    if (metadata.contentDisposition) headers.set("Content-Disposition", metadata.contentDisposition);
    if (metadata.contentEncoding) headers.set("Content-Encoding", metadata.contentEncoding);
    if (metadata.cacheControl) headers.set("Cache-Control", metadata.cacheControl);
    if (metadata.cacheExpiry) headers.set("Expires", metadata.cacheExpiry.toUTCString());
  }

  async arrayBuffer() {
    return this.bytes.slice().buffer;
  }

  async text() {
    return new TextDecoder().decode(this.bytes);
  }

  get body() {
    return new Response(this.bytes).body;
  }
}

export class MockR2Bucket {
  constructor(records = []) {
    this.objects = new Map();
    this.listCalls = [];
    this.getCalls = [];
    this.headCalls = [];
    for (const record of records) this.setObject(record.key, record);
  }

  setObject(key, record) {
    this.objects.set(key, {
      key,
      bytes: toBytes(record.bytes ?? ""),
      etag: record.etag ?? `etag-${this.objects.size + 1}`,
      uploaded: record.uploaded ?? new Date("2026-09-11T00:00:00.000Z"),
      version: record.version,
      httpMetadata: record.httpMetadata,
      customMetadata: record.customMetadata,
    });
  }

  deleteObject(key) {
    this.objects.delete(key);
  }

  async list({ prefix = "", cursor, limit = 1000 } = {}) {
    this.listCalls.push({ prefix, cursor, limit });
    const all = [...this.objects.values()]
      .filter((record) => record.key.startsWith(prefix))
      .sort((a, b) => a.key.localeCompare(b.key));
    const offset = cursor ? Number.parseInt(cursor.replace("cursor-", ""), 10) : 0;
    const start = Number.isFinite(offset) ? offset : 0;
    const page = all.slice(start, start + limit);
    const next = start + page.length;
    const truncated = next < all.length;

    return {
      objects: page.map((record) => new MockR2Object(record, record.bytes, null)),
      truncated,
      cursor: truncated ? `cursor-${next}` : undefined,
      delimitedPrefixes: [],
    };
  }

  async head(key, options = {}) {
    this.headCalls.push({ key, options });
    const record = this.objects.get(key);
    if (!record) return null;

    const object = new MockR2Object(record, record.bytes, null);
    object.bytes = undefined;
    return object;
  }

  async get(key, options = {}) {
    this.getCalls.push({ key, options });
    const record = this.objects.get(key);
    if (!record) return null;

    const bytes = rangeSlice(record.bytes, options.range);
    const range = options.range
      ? { offset: options.range.offset ?? 0, length: bytes.byteLength }
      : null;
    return new MockR2Object(record, bytes, range);
  }
}
