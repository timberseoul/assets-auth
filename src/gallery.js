import {
  DIMENSION_CONCURRENCY_DEFAULT,
  DIMENSION_PAGE_BUDGET_MS,
  GALLERY_MANIFEST_TTL,
  SIGNED_URL_TTL,
} from "./constants.js";
import { getImageDimensions } from "./dimensions.js";
import { createHmacSigner, versionedSignatureMessage } from "./signing.js";
import { HttpError, validateGalleryQuery } from "./validation.js";

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

function corsHeaders(origin) {
  if (!origin) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    Vary: "Origin",
  };
}

function timingSafeTextEqual(left, right) {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const length = Math.max(leftBytes.length, rightBytes.length);
  let difference = leftBytes.length ^ rightBytes.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return difference === 0;
}

function emptyDimensions() {
  return { width: null, height: null, aspectRatio: null };
}

async function mapWithConcurrency(items, concurrency, worker) {
  const results = new Array(items.length);
  let nextIndex = 0;
  const workerCount = Math.min(Math.max(1, concurrency), Math.max(1, items.length));

  async function run() {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      try {
        results[index] = await worker(items[index]);
      } catch {
        results[index] = emptyDimensions();
      }
    }
  }

  await Promise.all(Array.from({ length: workerCount }, () => run()));
  return results;
}

function normalizeManifest(value) {
  if (!value || !Array.isArray(value.items) || typeof value.generatedAt !== "number") return null;
  return value;
}

function manifestCacheUrl(origin, query) {
  const url = new URL(origin);
  url.pathname = "/__cache/gallery-manifest";
  url.search = "";
  url.searchParams.set("prefix", query.prefix);
  if (query.cursor) url.searchParams.set("cursor", query.cursor);
  url.searchParams.set("limit", String(query.limit));
  return url.toString();
}

async function readManifest(cacheKey, metrics) {
  const started = performance.now();
  try {
    const response = await caches.default.match(cacheKey);
    metrics.manifestCacheMs = performance.now() - started;
    if (!response) return null;
    const manifest = normalizeManifest(await response.json());
    if (!manifest) return null;
    if (Math.floor(Date.now() / 1000) - manifest.generatedAt > GALLERY_MANIFEST_TTL) return null;
    return manifest;
  } catch {
    metrics.manifestCacheMs = performance.now() - started;
    return null;
  }
}

function writeManifest(cacheKey, manifest, ctx) {
  const response = new Response(JSON.stringify(manifest), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": `public, max-age=${GALLERY_MANIFEST_TTL}`,
    },
  });
  const write = caches.default.put(cacheKey, response).catch(() => {});
  if (ctx?.waitUntil) ctx.waitUntil(write);
  else void write;
}

async function buildManifest(query, env, baseOrigin, ctx, metrics) {
  const listStarted = performance.now();
  const listed = await env.pictures_lib.list({
    prefix: query.prefix,
    cursor: query.cursor || undefined,
    limit: query.limit,
  });
  metrics.r2ListMs = performance.now() - listStarted;

  if (listed.truncated && !listed.cursor) {
    throw new HttpError(503, "Storage Unavailable");
  }

  const deadline = performance.now() + DIMENSION_PAGE_BUDGET_MS;
  const dimensionStarted = performance.now();
  const dimensionPromises = new Map();
  const dimensions = await mapWithConcurrency(listed.objects, DIMENSION_CONCURRENCY_DEFAULT, async (object) => {
    if (performance.now() >= deadline) return emptyDimensions();
    const identity = `${object.key}\u0000${object.etag}`;
    if (!dimensionPromises.has(identity)) {
      dimensionPromises.set(
        identity,
        getImageDimensions(
          {
            key: object.key,
            etag: object.etag,
            size: object.size,
            uploaded: object.uploaded,
          },
          env,
          baseOrigin,
          ctx,
          metrics
        )
      );
    }
    return dimensionPromises.get(identity);
  });
  metrics.dimensionMs = performance.now() - dimensionStarted;

  return {
    items: listed.objects.map((object, index) => ({
      key: object.key,
      etag: object.etag,
      name: object.key.slice(object.key.lastIndexOf("/") + 1),
      size: object.size ?? null,
      uploaded: object.uploaded ? object.uploaded.toISOString() : null,
      width: dimensions[index].width,
      height: dimensions[index].height,
      aspectRatio: dimensions[index].aspectRatio,
    })),
    truncated: Boolean(listed.truncated),
    cursor: listed.truncated ? listed.cursor : null,
    generatedAt: Math.floor(Date.now() / 1000),
  };
}

async function getManifest(query, env, baseOrigin, ctx, metrics) {
  const cacheKey = new Request(manifestCacheUrl(baseOrigin, query), { method: "GET" });
  const cached = await readManifest(cacheKey, metrics);
  if (cached) {
    metrics.manifestCacheHits += 1;
    return cached;
  }

  metrics.manifestCacheMisses += 1;
  const manifest = await buildManifest(query, env, baseOrigin, ctx, metrics);
  writeManifest(cacheKey, manifest, ctx);
  return manifest;
}

function serverTiming(metrics) {
  return [
    `r2-list;dur=${(metrics.r2ListMs || 0).toFixed(1)}`,
    `manifest-cache;dur=${(metrics.manifestCacheMs || 0).toFixed(1)}`,
    `dimension-cache;dur=${(metrics.dimensionMs || 0).toFixed(1)}`,
    `dimension-scan;dur=${(metrics.dimensionMs || 0).toFixed(1)}`,
    `signing;dur=${(metrics.signingMs || 0).toFixed(1)}`,
  ].join(", ");
}

function logGalleryMetrics(query, metrics, manifest, items) {
  console.log(
    JSON.stringify({
      event: "gallery_metrics",
      prefix: query.prefix,
      limit: query.limit,
      hasCursor: Boolean(query.cursor),
      r2ListMs: Number((metrics.r2ListMs || 0).toFixed(2)),
      manifestCacheHits: metrics.manifestCacheHits,
      manifestCacheMisses: metrics.manifestCacheMisses,
      dimensionCacheHits: metrics.dimensionCacheHits,
      dimensionCacheMisses: metrics.dimensionCacheMisses,
      dimensionPositiveCacheHits: metrics.dimensionPositiveCacheHits || 0,
      dimensionNegativeCacheHits: metrics.dimensionNegativeCacheHits || 0,
      dimensionScans: metrics.dimensionScans || 0,
      dimensionScanBytes: metrics.dimensionScanBytes || 0,
      dimensionFormatCounts: metrics.dimensionFormatCounts || {},
      signingMs: Number((metrics.signingMs || 0).toFixed(2)),
      count: items.length,
      truncated: manifest.truncated,
      generatedAt: manifest.generatedAt,
    })
  );
}

export async function handleGallery(request, url, env, ctx, corsOrigin) {
  const browserOrigin = request.headers.get("Origin");
  if (browserOrigin && !corsOrigin) {
    return json({ error: "Forbidden" }, 403, corsHeaders(corsOrigin));
  }
  if (request.method !== "GET") {
    return json({ error: "Method Not Allowed" }, 405, { ...corsHeaders(corsOrigin), Allow: "GET, OPTIONS" });
  }

  try {
    const expectedToken = String(env.GALLERY_API_TOKEN || "").trim();
    if (!expectedToken) return json({ error: "Service Unavailable" }, 503, corsHeaders(corsOrigin));
    const authorization = request.headers.get("Authorization") || "";
    const providedToken = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
    if (!providedToken || !timingSafeTextEqual(providedToken, expectedToken)) {
      return json({ error: "Unauthorized" }, 401, corsHeaders(corsOrigin));
    }
    if (!env.pictures_lib) return json({ error: "Service Unavailable" }, 503, corsHeaders(corsOrigin));

    const query = validateGalleryQuery(url);
    const metrics = {
      manifestCacheHits: 0,
      manifestCacheMisses: 0,
      dimensionCacheHits: 0,
      dimensionCacheMisses: 0,
    };
    const manifest = await getManifest(query, env, url.origin, ctx, metrics);
    const ttl = Number(env.SIGNED_URL_TTL) > 0 ? Math.floor(Number(env.SIGNED_URL_TTL)) : SIGNED_URL_TTL;
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + ttl;
    const signer = createHmacSigner(env.SIGNING_SECRET);
    if (!signer) return json({ error: "Service Unavailable" }, 503, corsHeaders(corsOrigin));

    const signingStarted = performance.now();
    const items = await Promise.all(
      manifest.items.map(async (item) => {
        const etag = item.etag;
        const signature = await signer.sign(versionedSignatureMessage(item.key, etag, expiresAt));
        return {
          ...item,
          aspectRatio: item.width && item.height ? Number((item.width / item.height).toFixed(6)) : null,
          url: `${url.origin}/api/image/${encodeURIComponent(item.key)}?v=${encodeURIComponent(etag)}&exp=${expiresAt}&sig=${signature}`,
        };
      })
    );
    metrics.signingMs = performance.now() - signingStarted;
    logGalleryMetrics(query, metrics, manifest, items);

    return json(
      {
        items,
        count: items.length,
        truncated: manifest.truncated,
        cursor: manifest.cursor,
        generatedAt: manifest.generatedAt,
        expiresAt,
      },
      200,
      {
        ...corsHeaders(corsOrigin),
        "Cache-Control": "private, no-store",
        "Server-Timing": serverTiming(metrics),
      }
    );
  } catch (error) {
    if (error instanceof HttpError) {
      console.error(JSON.stringify({ event: "gallery_error", status: error.status, error: error.name }));
      return json({ error: error.message }, error.status, corsHeaders(corsOrigin));
    }
    console.error(JSON.stringify({ event: "gallery_error", status: 500, error: error instanceof Error ? error.name : "UnknownError" }));
    return json({ error: "Internal Error" }, 500, corsHeaders(corsOrigin));
  }
}
