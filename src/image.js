import { IMAGE_CACHE_TTL, IMAGE_MAX_VERSION_LENGTH } from "./constants.js";
import {
  createHmacSigner,
  normalizeEtag,
  timingSafeEqualHex,
  versionedSignatureMessage,
} from "./signing.js";
import {
  decodeImageKey,
  HttpError,
  parseByteRange,
  validateImageVersion,
} from "./validation.js";

function imageHeaders(extra = {}) {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Range, If-None-Match, Content-Type",
    "Cross-Origin-Resource-Policy": "cross-origin",
    "Cache-Control": "no-store",
    ...extra,
  };
}

function json(data, status, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...imageHeaders(extra),
    },
  });
}

function guessContentTypeFromKey(key) {
  const lower = key.toLowerCase();
  if (lower.endsWith(".avif")) return "image/avif";
  if (lower.endsWith(".webp")) return "image/webp";
  if (lower.endsWith(".png")) return "image/png";
  if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
  if (lower.endsWith(".gif")) return "image/gif";
  if (lower.endsWith(".svg")) return "image/svg+xml";
  return "application/octet-stream";
}

function objectHeaders(object, key) {
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("Cache-Control", `public, max-age=${IMAGE_CACHE_TTL}, immutable`);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
  headers.set("Cross-Origin-Resource-Policy", "cross-origin");
  headers.set("Accept-Ranges", "bytes");
  headers.set("Content-Type", object.httpMetadata?.contentType || guessContentTypeFromKey(key));
  headers.set("Content-Length", String(object.size));
  const etag = object.httpEtag || `"${normalizeEtag(object.etag)}"`;
  headers.set("ETag", etag);
  return headers;
}

function notModifiedHeaders(headers) {
  return {
    "Cache-Control": headers.get("Cache-Control") || `public, max-age=${IMAGE_CACHE_TTL}, immutable`,
    ETag: headers.get("ETag") || "",
    "Access-Control-Allow-Origin": "*",
    "Cross-Origin-Resource-Policy": "cross-origin",
  };
}

function matchesIfNoneMatch(header, etag) {
  if (!header) return false;
  const normalizedTarget = normalizeEtag(etag);
  return header.split(",").some((value) => {
    const candidate = value.trim();
    return candidate === "*" || normalizeEtag(candidate) === normalizedTarget;
  });
}

function imageCacheUrl(origin, key, version) {
  const url = new URL(origin);
  url.pathname = `/__cache/image/${encodeURIComponent(key)}`;
  url.search = "";
  if (version) url.searchParams.set("v", version);
  return url.toString();
}

async function readImageCache(cacheKey) {
  try {
    return await caches.default.match(cacheKey);
  } catch {
    return null;
  }
}

async function headObject(key, bucket) {
  try {
    return await bucket.head(key);
  } catch {
    throw new HttpError(503, "Storage Unavailable");
  }
}

async function getObject(key, bucket, range) {
  try {
    return await bucket.get(key, range ? { range } : undefined);
  } catch {
    throw new HttpError(503, "Storage Unavailable");
  }
}

export async function handleImage(request, url, env, ctx) {
  try {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return json({ error: "Method Not Allowed" }, 405, { Allow: "GET, HEAD, OPTIONS" });
    }
    if (!env.pictures_lib) return json({ error: "Service Unavailable" }, 503);

    const encodedKey = url.pathname.slice("/api/image/".length);
    const key = decodeImageKey(encodedKey);
    const versionParam = url.searchParams.get("v");
    if (versionParam !== null && versionParam.length > IMAGE_MAX_VERSION_LENGTH) {
      throw new HttpError(400, "Bad Request: invalid v");
    }
    const version = validateImageVersion(versionParam, true);
    const expValue = url.searchParams.get("exp") || "";
    const signature = (url.searchParams.get("sig") || "").toLowerCase();

    if (!/^\d{1,12}$/.test(expValue)) throw new HttpError(400, "Bad Request: invalid exp");
    if (!/^[a-f0-9]{64}$/.test(signature)) throw new HttpError(400, "Bad Request: invalid sig");
    const exp = Number(expValue);
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(exp) || exp < now) throw new HttpError(403, "URL expired");

    const signer = createHmacSigner(env.SIGNING_SECRET);
    if (!signer) throw new HttpError(503, "Service Unavailable");
    const message = versionedSignatureMessage(key, version, exp);
    const expectedSignature = await signer.sign(message);
    if (!timingSafeEqualHex(signature, expectedSignature)) throw new HttpError(403, "Invalid signature");

    if (request.method === "HEAD") {
      const object = await headObject(key, env.pictures_lib);
      if (!object) return json({ error: "Not Found" }, 404);
      if (normalizeEtag(object.etag) !== version) {
        return json({ error: "Image version no longer available" }, 410);
      }
      const headers = objectHeaders(object, key);
      if (matchesIfNoneMatch(request.headers.get("If-None-Match"), headers.get("ETag"))) {
        return new Response(null, { status: 304, headers: notModifiedHeaders(headers) });
      }
      headers.set("X-Worker-Cache", "BYPASS-HEAD");
      return new Response(null, { status: 200, headers });
    }

    const rangeHeader = request.headers.get("Range");
    if (rangeHeader) {
      const object = await headObject(key, env.pictures_lib);
      if (!object) return json({ error: "Not Found" }, 404);
      if (normalizeEtag(object.etag) !== version) {
        return json({ error: "Image version no longer available" }, 410);
      }
      const baseHeaders = objectHeaders(object, key);
      if (matchesIfNoneMatch(request.headers.get("If-None-Match"), baseHeaders.get("ETag"))) {
        return new Response(null, { status: 304, headers: notModifiedHeaders(baseHeaders) });
      }

      let range;
      try {
        range = parseByteRange(rangeHeader, object.size);
      } catch {
        return json({ error: "Range Not Satisfiable" }, 416, { "Content-Range": `bytes */${object.size}` });
      }
      const rangedObject = await getObject(key, env.pictures_lib, { offset: range.offset, length: range.length });
      if (!rangedObject) return json({ error: "Not Found" }, 404);
      if (normalizeEtag(rangedObject.etag) !== version) {
        return json({ error: "Image version no longer available" }, 410);
      }
      const end = range.offset + range.length - 1;
      const headers = objectHeaders(rangedObject, key);
      headers.set("Content-Length", String(range.length));
      headers.set("Content-Range", `bytes ${range.offset}-${end}/${object.size}`);
      headers.set("X-Worker-Cache", "BYPASS-RANGE");
      return new Response(rangedObject.body, { status: 206, headers });
    }

    const cacheKey = new Request(imageCacheUrl(url.origin, key, version), { method: "GET" });
    const cached = await readImageCache(cacheKey);
    if (cached) {
      if (matchesIfNoneMatch(request.headers.get("If-None-Match"), cached.headers.get("ETag"))) {
        return new Response(null, { status: 304, headers: notModifiedHeaders(cached.headers) });
      }
      const response = new Response(cached.body, cached);
      response.headers.set("X-Worker-Cache", "HIT");
      return response;
    }

    const object = await getObject(key, env.pictures_lib);
    if (!object) return json({ error: "Not Found" }, 404);
    if (normalizeEtag(object.etag) !== version) {
      return json({ error: "Image version no longer available" }, 410);
    }

    const headers = objectHeaders(object, key);
    if (matchesIfNoneMatch(request.headers.get("If-None-Match"), headers.get("ETag"))) {
      return new Response(null, { status: 304, headers: notModifiedHeaders(headers) });
    }
    const response = new Response(object.body, { status: 200, headers });
    response.headers.set("X-Worker-Cache", "MISS");
    const cacheWrite = caches.default.put(cacheKey, response.clone()).catch(() => {});
    if (ctx?.waitUntil) ctx.waitUntil(cacheWrite);
    else void cacheWrite;
    return response;
  } catch (error) {
    if (error instanceof HttpError) return json({ error: error.message }, error.status);
    return json({ error: "Internal Error" }, 500);
  }
}
