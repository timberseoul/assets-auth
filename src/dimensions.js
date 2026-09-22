import {
  DIMENSION_ABSOLUTE_MAX_BYTES,
  DIMENSION_LIMITS,
  IMAGE_METADATA_CACHE_VERSION,
  IMAGE_METADATA_NEGATIVE_TTL,
  IMAGE_METADATA_POSITIVE_TTL,
} from "./constants.js";

const JPEG_START_OF_FRAME = new Set([
  0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf,
]);

function ascii(bytes, offset, length) {
  let value = "";
  for (let index = offset; index < offset + length && index < bytes.length; index += 1) {
    value += String.fromCharCode(bytes[index]);
  }
  return value;
}

function readUint16BE(bytes, offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function readUint16LE(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readUint24LE(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16);
}

function readUint32BE(bytes, offset) {
  return bytes[offset] * 0x1000000 + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
}

function readUint32LE(bytes, offset) {
  return bytes[offset] + (bytes[offset + 1] << 8) + (bytes[offset + 2] << 16) + bytes[offset + 3] * 0x1000000;
}

function concatBytes(left, right) {
  if (left.byteLength === 0) return right;
  const combined = new Uint8Array(left.byteLength + right.byteLength);
  combined.set(left, 0);
  combined.set(right, left.byteLength);
  return combined;
}

function normalizeDimensions(width, height) {
  if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) return null;
  return {
    width: Math.round(width),
    height: Math.round(height),
    aspectRatio: Number((width / height).toFixed(6)),
  };
}

function parserResult(dimensions = null, reason = "invalid") {
  return { dimensions, reason };
}

export function detectImageFormat(bytes, key = "") {
  if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  ) {
    return "png";
  }
  if (bytes.length >= 6 && ascii(bytes, 0, 3) === "GIF" && ["87a", "89a"].includes(ascii(bytes, 3, 3))) {
    return "gif";
  }
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xd8) return "jpeg";
  if (bytes.length >= 12 && ascii(bytes, 0, 4) === "RIFF" && ascii(bytes, 8, 4) === "WEBP") return "webp";
  if (
    bytes.length >= 12 &&
    ascii(bytes, 4, 4) === "ftyp" &&
    `${ascii(bytes, 8, 4)}${ascii(bytes, 16, 4)}`.includes("avif")
  ) {
    return "avif";
  }

  const prefix = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 4096)));
  if (/<svg(?:\s|>)/i.test(prefix)) return "svg";

  const lowerKey = key.toLowerCase();
  if (lowerKey.endsWith(".png")) return "png";
  if (lowerKey.endsWith(".gif")) return "gif";
  if (lowerKey.endsWith(".jpg") || lowerKey.endsWith(".jpeg")) return "jpeg";
  if (lowerKey.endsWith(".webp")) return "webp";
  if (lowerKey.endsWith(".avif")) return "avif";
  if (lowerKey.endsWith(".svg")) return "svg";
  return "unknown";
}

function parsePng(bytes) {
  if (bytes.length < 24) return parserResult(null, "need-more");
  if (ascii(bytes, 12, 4) !== "IHDR") return parserResult();
  return parserResult(normalizeDimensions(readUint32BE(bytes, 16), readUint32BE(bytes, 20)));
}

function parseGif(bytes) {
  if (bytes.length < 10) return parserResult(null, "need-more");
  return parserResult(normalizeDimensions(readUint16LE(bytes, 6), readUint16LE(bytes, 8)));
}

function parseJpeg(bytes) {
  if (bytes.length < 2) return parserResult(null, "need-more");
  let offset = 2;

  while (offset < bytes.length) {
    if (bytes[offset] !== 0xff) {
      offset += 1;
      continue;
    }
    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
    if (offset >= bytes.length) return parserResult(null, "need-more");

    const marker = bytes[offset];
    offset += 1;
    if (marker === 0xd9 || marker === 0xda) return parserResult();
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > bytes.length) return parserResult(null, "need-more");

    const segmentLength = readUint16BE(bytes, offset);
    if (segmentLength < 2) return parserResult();
    if (offset + segmentLength > bytes.length) return parserResult(null, "need-more");
    if (JPEG_START_OF_FRAME.has(marker)) {
      if (segmentLength < 7 || offset + 7 > bytes.length) return parserResult(null, "need-more");
      return parserResult(normalizeDimensions(readUint16BE(bytes, offset + 5), readUint16BE(bytes, offset + 3)));
    }
    offset += segmentLength;
  }

  return parserResult(null, "need-more");
}

function parseWebp(bytes) {
  if (bytes.length < 16) return parserResult(null, "need-more");
  let offset = 12;

  while (offset + 8 <= bytes.length) {
    const chunkType = ascii(bytes, offset, 4);
    const chunkSize = readUint32LE(bytes, offset + 4);
    const dataOffset = offset + 8;
    const chunkEnd = dataOffset + chunkSize;

    if (chunkType === "VP8X") {
      if (chunkSize < 10 || dataOffset + 10 > bytes.length) {
        return parserResult(null, "need-more");
      }
      return parserResult(normalizeDimensions(1 + readUint24LE(bytes, dataOffset + 4), 1 + readUint24LE(bytes, dataOffset + 7)));
    }
    if (chunkType === "VP8 ") {
      if (chunkSize < 10 || dataOffset + 10 > bytes.length) {
        return parserResult(null, "need-more");
      }
      if (bytes[dataOffset + 3] !== 0x9d || bytes[dataOffset + 4] !== 0x01 || bytes[dataOffset + 5] !== 0x2a) return parserResult();
      return parserResult(normalizeDimensions(readUint16LE(bytes, dataOffset + 6) & 0x3fff, readUint16LE(bytes, dataOffset + 8) & 0x3fff));
    }
    if (chunkType === "VP8L") {
      if (chunkSize < 5 || dataOffset + 5 > bytes.length) {
        return parserResult(null, "need-more");
      }
      if (bytes[dataOffset] !== 0x2f) return parserResult();
      const width = 1 + (bytes[dataOffset + 1] | ((bytes[dataOffset + 2] & 0x3f) << 8));
      const height = 1 + ((bytes[dataOffset + 2] >> 6) | (bytes[dataOffset + 3] << 2) | ((bytes[dataOffset + 4] & 0x0f) << 10));
      return parserResult(normalizeDimensions(width, height));
    }
    if (chunkEnd > bytes.length) return parserResult(null, "need-more");
    offset = chunkEnd + (chunkSize % 2);
  }

  return parserResult(null, "need-more");
}

function parseSvgLength(value) {
  if (!value) return null;
  const match = value.trim().match(/^([+-]?(?:\d+\.?\d*|\.\d+))(?:px|pt|pc|mm|cm|in|%)?$/i);
  if (!match) return null;
  const number = Number.parseFloat(match[1]);
  return Number.isFinite(number) && number > 0 ? number : null;
}

function parseSvg(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const match = /<svg\b[^>]*>/i.exec(text);
  if (!match) return parserResult(null, "need-more");

  const tag = match[0];
  const width = parseSvgLength(tag.match(/\bwidth\s*=\s*["']([^"']+)["']/i)?.[1]);
  const height = parseSvgLength(tag.match(/\bheight\s*=\s*["']([^"']+)["']/i)?.[1]);
  if (width && height) return parserResult(normalizeDimensions(width, height));

  const viewBox = tag.match(/\bviewBox\s*=\s*["']\s*([\d.eE+-]+)[\s,]+([\d.eE+-]+)[\s,]+([\d.eE+-]+)[\s,]+([\d.eE+-]+)\s*["']/i);
  if (!viewBox) return parserResult();
  return parserResult(normalizeDimensions(Number(viewBox[3]), Number(viewBox[4])));
}

function readBoxSize(bytes, offset) {
  if (offset + 8 > bytes.length) return null;
  const size = readUint32BE(bytes, offset);
  if (size === 1) {
    if (offset + 16 > bytes.length) return null;
    const high = readUint32BE(bytes, offset + 8);
    const low = readUint32BE(bytes, offset + 12);
    return high * 0x100000000 + low;
  }
  return size;
}

function findIspe(bytes, start, end) {
  let offset = start;
  while (offset + 8 <= end) {
    const size = readBoxSize(bytes, offset);
    if (!size) return parserResult(null, "need-more");
    const type = ascii(bytes, offset + 4, 4);
    const headerSize = size === 1 ? 16 : 8;
    const boxEnd = offset + size;
    if (boxEnd > bytes.length || boxEnd > end) return parserResult(null, "need-more");
    if (boxEnd < offset + headerSize) return parserResult();

    if (type === "ispe") {
      if (size < 20) return parserResult();
      return parserResult(normalizeDimensions(readUint32BE(bytes, offset + 12), readUint32BE(bytes, offset + 16)));
    }
    if (type === "meta") {
      if (size < 12) return parserResult();
      const nested = findIspe(bytes, offset + 12, boxEnd);
      if (nested.dimensions || nested.reason !== "invalid") return nested;
    }
    if (type === "iprp" || type === "ipco") {
      const nested = findIspe(bytes, offset + headerSize, boxEnd);
      if (nested.dimensions || nested.reason !== "invalid") return nested;
    }
    offset = boxEnd;
  }
  return parserResult(null, "need-more");
}

function parseAvif(bytes) {
  if (bytes.length < 16) return parserResult(null, "need-more");
  return findIspe(bytes, 0, bytes.length);
}

export function parseImageDimensions(bytes, key = "") {
  const format = detectImageFormat(bytes, key);
  let parsed;
  if (format === "png") parsed = parsePng(bytes);
  else if (format === "gif") parsed = parseGif(bytes);
  else if (format === "jpeg") parsed = parseJpeg(bytes);
  else if (format === "webp") parsed = parseWebp(bytes);
  else if (format === "svg") parsed = parseSvg(bytes);
  else if (format === "avif") parsed = parseAvif(bytes);
  else parsed = parserResult();
  return parsed.dimensions;
}

function formatHint(key) {
  const lower = key.toLowerCase();
  if (lower.endsWith(".png")) return "png";
  if (lower.endsWith(".gif")) return "gif";
  if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "jpeg";
  if (lower.endsWith(".webp")) return "webp";
  if (lower.endsWith(".avif")) return "avif";
  if (lower.endsWith(".svg")) return "svg";
  return "unknown";
}

function emptyDimensions(status = "unsupported-format") {
  return { width: null, height: null, aspectRatio: null, status, bytesRead: 0 };
}

function dimensionsFromResult(result, bytesRead) {
  if (!result.dimensions) {
    const status = result.reason === "need-more" ? "scan-limit" : "unsupported-format";
    return { ...emptyDimensions(status), bytesRead };
  }
  return { ...result.dimensions, status: "ok", bytesRead };
}

function metadataCacheUrl(origin, key, etag) {
  const url = new URL(origin);
  url.pathname =
    "/__cache/image-metadata/" + IMAGE_METADATA_CACHE_VERSION + "/" + encodeURIComponent(key);
  url.search = "";
  url.searchParams.set("v", encodeURIComponent(etag));
  return url.toString();
}

function normalizeEtag(etag) {
  return String(etag || "").replace(/^W\//, "").replace(/^"|"$/g, "");
}

async function readCachedMetadata(cacheKey, metrics) {
  try {
    const cached = await caches.default.match(cacheKey);
    if (!cached) {
      metrics.dimensionCacheMisses += 1;
      return null;
    }
    const metadata = await cached.json();
    if (!metadata || typeof metadata !== "object") return null;
    metrics.dimensionCacheHits += 1;
    return metadata;
  } catch {
    metrics.dimensionCacheMisses += 1;
    return null;
  }
}

function writeCachedMetadata(cacheKey, metadata, ttl, ctx) {
  const response = new Response(JSON.stringify(metadata), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": `public, max-age=${ttl}`,
    },
  });
  const write = caches.default.put(cacheKey, response).catch(() => {});
  if (ctx?.waitUntil) {
    ctx.waitUntil(write);
  } else {
    void write;
  }
}

export async function scanImageDimensions(entry, bucket, metrics, options = {}) {
  const key = entry.key;
  const hint = formatHint(key);
  const limits = options.limits || DIMENSION_LIMITS;
  let format = hint;
  let plan = limits[format] || limits.unknown;
  let bytes = new Uint8Array();
  let bytesRead = 0;
  let detected = false;

  while (bytesRead < Math.min(plan.max, DIMENSION_ABSOLUTE_MAX_BYTES)) {
    const remaining = Math.min(plan.max, DIMENSION_ABSOLUTE_MAX_BYTES) - bytesRead;
    const requested = Math.min(bytesRead === 0 ? plan.initial : plan.chunk, remaining);
    if (requested <= 0) break;

    let object;
    try {
      object = await bucket.get(key, { range: { offset: bytesRead, length: requested } });
    } catch {
      return { ...emptyDimensions("storage-error"), bytesRead };
    }
    if (!object) return { ...emptyDimensions("not-found"), bytesRead };
    if (entry.etag && normalizeEtag(object.etag) !== normalizeEtag(entry.etag)) {
      return { ...emptyDimensions("stale-version"), bytesRead };
    }

    let chunk;
    try {
      chunk = new Uint8Array(await object.arrayBuffer());
    } catch {
      return { ...emptyDimensions("storage-error"), bytesRead };
    }
    if (chunk.byteLength === 0) break;
    bytes = concatBytes(bytes, chunk);
    bytesRead += chunk.byteLength;

    if (!detected) {
      format = detectImageFormat(bytes, key);
      detected = true;
      plan = limits[format] || limits.unknown;
      if (format === "unknown" && bytesRead >= plan.max) return { ...emptyDimensions("unsupported-format"), bytesRead };
    }

    let parsed;
    if (format === "png") parsed = parsePng(bytes);
    else if (format === "gif") parsed = parseGif(bytes);
    else if (format === "jpeg") parsed = parseJpeg(bytes);
    else if (format === "webp") parsed = parseWebp(bytes);
    else if (format === "svg") parsed = parseSvg(bytes);
    else if (format === "avif") parsed = parseAvif(bytes);
    else return { ...emptyDimensions("unsupported-format"), bytesRead };

    if (parsed.dimensions) return dimensionsFromResult(parsed, bytesRead);
    if (parsed.reason !== "need-more") return { ...emptyDimensions("unsupported-format"), bytesRead };
    if (chunk.byteLength < requested || bytesRead >= Math.min(plan.max, DIMENSION_ABSOLUTE_MAX_BYTES)) {
      return { ...emptyDimensions("scan-limit"), bytesRead };
    }
  }

  return { ...emptyDimensions("scan-limit"), bytesRead };
}

export async function getImageDimensions(entry, env, origin, ctx, metrics = {}) {
  metrics.dimensionCacheHits ??= 0;
  metrics.dimensionCacheMisses ??= 0;
  metrics.dimensionPositiveCacheHits ??= 0;
  metrics.dimensionNegativeCacheHits ??= 0;
  metrics.dimensionScanBytes ??= 0;
  metrics.dimensionScans ??= 0;
  metrics.dimensionFormatCounts ??= {};

  const etag = normalizeEtag(entry.etag);
  if (!etag) {
    const scanned = await scanImageDimensions(entry, env.pictures_lib, metrics);
    metrics.dimensionScans += 1;
    metrics.dimensionScanBytes += scanned.bytesRead;
    return scanned;
  }

  const cacheKey = new Request(metadataCacheUrl(origin, entry.key, etag), { method: "GET" });
  const cached = await readCachedMetadata(cacheKey, metrics);
  if (cached) {
    if (cached.status && cached.status !== "ok") metrics.dimensionNegativeCacheHits += 1;
    else metrics.dimensionPositiveCacheHits += 1;
    return {
      width: cached.width ?? null,
      height: cached.height ?? null,
      aspectRatio: cached.aspectRatio ?? null,
      status: cached.status ?? "ok",
      bytesRead: 0,
    };
  }

  const scanned = await scanImageDimensions(entry, env.pictures_lib, metrics);
  metrics.dimensionScans += 1;
  metrics.dimensionScanBytes += scanned.bytesRead;
  const format = formatHint(entry.key);
  metrics.dimensionFormatCounts[format] = (metrics.dimensionFormatCounts[format] || 0) + 1;

  const metadata = {
    width: scanned.width,
    height: scanned.height,
    aspectRatio: scanned.aspectRatio,
    status: scanned.status,
  };
  const ttl = scanned.status === "ok" ? IMAGE_METADATA_POSITIVE_TTL : IMAGE_METADATA_NEGATIVE_TTL;
  writeCachedMetadata(cacheKey, metadata, ttl, ctx);
  return scanned;
}
