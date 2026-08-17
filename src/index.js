const IMAGE_CACHE_TTL = 31536000;
const IMAGE_METADATA_CACHE_TTL = 31536000;

export default {
    async fetch(request, env, ctx) {
      try {
        const url = new URL(request.url);
        const origin = request.headers.get("Origin") || "";
        const corsOrigin = resolveCorsOrigin(origin, env.ALLOWED_ORIGINS || "");

        if (request.method === "OPTIONS") {
          return handleOptions(url.pathname, corsOrigin);
        }

        if (url.pathname === "/api/gallery") {
          return handleGallery(request, url, env, corsOrigin);
        }

        if (url.pathname.startsWith("/api/image/")) {
          return handleImage(request, url, env, ctx, corsOrigin);
        }

        return json({ error: "Not Found" }, 404);
      } catch (err) {
        return json(
          { error: "Internal Error", detail: err instanceof Error ? err.message : String(err) },
          500
        );
      }
    },
  };

  /**
   * 必要环境变量
   * - pictures_lib: R2 bucket binding（你当前是这个名字）
   * - GALLERY_API_TOKEN: /api/gallery Bearer token
   * - SIGNING_SECRET: 图片签名密钥
   *
   * 可选环境变量
   * - SIGNED_URL_TTL: 签名有效期秒数，默认 900
   * - ALLOWED_ORIGINS: 允许跨域来源，逗号分隔
   */

  async function handleGallery(request, url, env, corsOrigin) {
    if (request.method !== "GET") {
      return json({ error: "Method Not Allowed" }, 405, corsHeaders(corsOrigin));
    }

    // 1) 严格 token 鉴权
    const requiredToken = (env.GALLERY_API_TOKEN || "").trim();
    if (!requiredToken) {
      return json({ error: "Server token not configured: GALLERY_API_TOKEN" }, 500, corsHeaders(corsOrigin));
    }

    const auth = request.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (!token || token !== requiredToken) {
      return json({ error: "Unauthorized" }, 401, corsHeaders(corsOrigin));
    }

    // 2) 防呆：R2 binding
    if (!env.pictures_lib) {
      return json({ error: "R2 binding missing: pictures_lib" }, 500, corsHeaders(corsOrigin));
    }

    // 3) 参数
    const prefix = url.searchParams.get("prefix") || "pics/pic/";
    const cursor = url.searchParams.get("cursor") || undefined;
    const limitRaw = Number(url.searchParams.get("limit") || 200);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(limitRaw, 500)) : 200;

    // 4) list
    const listed = await env.pictures_lib.list({ prefix, cursor, limit });

    const ttl = parsePositiveInt(env.SIGNED_URL_TTL, 900);
    const exp = Math.floor(Date.now() / 1000) + ttl;
    const base = new URL(request.url);

    // Limit concurrent R2 reads while calculating dimensions for the listed images.
    const items = await mapWithConcurrency(listed.objects, 5, async (obj) => {
      const key = obj.key;
      const encodedKey = encodeURIComponent(key);
      const [sig, dimensions] = await Promise.all([
        signKeyExp(key, exp, env.SIGNING_SECRET),
        getCachedImageDimensions(key, env, base.origin, ctx),
      ]);
      const imageUrl = `${base.origin}/api/image/${encodedKey}?exp=${exp}&sig=${sig}`;

      return {
        key,
        name: key.split("/").pop() || key,
        size: obj.size ?? null,
        uploaded: obj.uploaded ? obj.uploaded.toISOString() : null,
        width: dimensions.width,
        height: dimensions.height,
        aspectRatio: dimensions.aspectRatio,
        url: imageUrl,
      };
    });

    return json(
      {
        items,
        count: items.length,
        truncated: Boolean(listed.truncated),
        cursor: listed.cursor || null,
      },
      200,
      corsHeaders(corsOrigin)
    );
  }

  async function getCachedImageDimensions(key, env, origin, ctx) {
    const cacheUrl = new URL(origin);
    cacheUrl.pathname = `/__cache/image-metadata/${encodeURIComponent(key)}`;
    cacheUrl.search = "";
    const cacheKey = new Request(cacheUrl.toString(), { method: "GET" });

    const cached = await caches.default.match(cacheKey);
    if (cached) {
      try {
        return await cached.json();
      } catch {
        // Ignore malformed legacy cache entries and recalculate them.
      }
    }

    const object = await env.pictures_lib.get(key);
    if (!object) return emptyImageDimensions();

    let dimensions;
    try {
      dimensions = parseImageDimensions(await object.arrayBuffer(), key);
    } catch {
      dimensions = null;
    }

    const metadata = dimensions
      ? {
          width: dimensions.width,
          height: dimensions.height,
          aspectRatio: Number((dimensions.width / dimensions.height).toFixed(6)),
        }
      : emptyImageDimensions();

    ctx.waitUntil(
      caches.default.put(
        cacheKey,
        new Response(JSON.stringify(metadata), {
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": `public, max-age=${IMAGE_METADATA_CACHE_TTL}`,
          },
        })
      )
    );

    return metadata;
  }

  function emptyImageDimensions() {
    return { width: null, height: null, aspectRatio: null };
  }

  async function mapWithConcurrency(items, concurrency, worker) {
    const results = new Array(items.length);
    let nextIndex = 0;
    const workerCount = Math.min(Math.max(1, concurrency), items.length);

    async function run() {
      while (nextIndex < items.length) {
        const index = nextIndex++;
        results[index] = await worker(items[index], index);
      }
    }

    await Promise.all(Array.from({ length: workerCount }, () => run()));
    return results;
  }

  function parseImageDimensions(buffer, key) {
    const bytes = new Uint8Array(buffer);
    const lower = key.toLowerCase();

    if (isPng(bytes)) return { width: readUint32BE(bytes, 16), height: readUint32BE(bytes, 20) };
    if (isGif(bytes)) return { width: readUint16LE(bytes, 6), height: readUint16LE(bytes, 8) };
    if (isJpeg(bytes)) return parseJpegDimensions(bytes);
    if (isWebp(bytes)) return parseWebpDimensions(bytes);
    if (lower.endsWith(".svg") || looksLikeSvg(bytes)) return parseSvgDimensions(bytes);
    if (lower.endsWith(".avif") || looksLikeAvif(bytes)) return parseAvifDimensions(bytes);
    return null;
  }

  function isPng(bytes) {
    return bytes.length >= 24 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 && bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a;
  }

  function isGif(bytes) {
    return bytes.length >= 10 && ascii(bytes, 0, 3) === "GIF" && (ascii(bytes, 3, 3) === "89a" || ascii(bytes, 3, 3) === "87a");
  }

  function isJpeg(bytes) {
    return bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xd8;
  }

  function parseJpegDimensions(bytes) {
    let offset = 2;
    while (offset + 3 < bytes.length) {
      if (bytes[offset] !== 0xff) {
        offset++;
        continue;
      }
      while (bytes[offset] === 0xff) offset++;
      const marker = bytes[offset++];
      if (marker === 0xd9 || marker === 0xda) break;
      if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
      if (offset + 2 > bytes.length) break;
      const segmentLength = readUint16BE(bytes, offset);
      if (segmentLength < 2 || offset + segmentLength > bytes.length) break;
      if (isJpegStartOfFrame(marker) && offset + 7 < bytes.length) {
        return { height: readUint16BE(bytes, offset + 3), width: readUint16BE(bytes, offset + 5) };
      }
      offset += segmentLength;
    }
    return null;
  }

  function isJpegStartOfFrame(marker) {
    return [0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker);
  }

  function isWebp(bytes) {
    return bytes.length >= 16 && ascii(bytes, 0, 4) === "RIFF" && ascii(bytes, 8, 4) === "WEBP";
  }

  function parseWebpDimensions(bytes) {
    let offset = 12;
    while (offset + 8 <= bytes.length) {
      const chunkType = ascii(bytes, offset, 4);
      const chunkSize = readUint32LE(bytes, offset + 4);
      const data = offset + 8;

      if (chunkType === "VP8X" && data + 10 <= bytes.length) {
        return { width: 1 + readUint24LE(bytes, data + 4), height: 1 + readUint24LE(bytes, data + 7) };
      }
      if (chunkType === "VP8 " && data + 10 <= bytes.length && bytes[data + 3] === 0x9d && bytes[data + 4] === 0x01 && bytes[data + 5] === 0x2a) {
        return { width: readUint16LE(bytes, data + 6) & 0x3fff, height: readUint16LE(bytes, data + 8) & 0x3fff };
      }
      if (chunkType === "VP8L" && data + 5 <= bytes.length && bytes[data] === 0x2f) {
        return {
          width: 1 + (bytes[data + 1] | ((bytes[data + 2] & 0x3f) << 8)),
          height: 1 + ((bytes[data + 2] >> 6) | (bytes[data + 3] << 2) | ((bytes[data + 4] & 0x0f) << 10)),
        };
      }
      offset = data + chunkSize + (chunkSize % 2);
    }
    return null;
  }

  function looksLikeSvg(bytes) {
    return /<svg(?:\s|>)/i.test(new TextDecoder().decode(bytes.slice(0, 1024)));
  }

  function parseSvgDimensions(bytes) {
    const text = new TextDecoder().decode(bytes.slice(0, 1024 * 1024));
    const tag = text.match(/<svg\b[^>]*>/i)?.[0] || "";
    const width = parseSvgLength(tag.match(/\bwidth\s*=\s*["']([^"']+)["']/i)?.[1]);
    const height = parseSvgLength(tag.match(/\bheight\s*=\s*["']([^"']+)["']/i)?.[1]);
    if (width && height) return { width, height };
    const viewBox = tag.match(/\bviewBox\s*=\s*["']\s*([\d.e+-]+)[\s,]+([\d.e+-]+)[\s,]+([\d.e+-]+)[\s,]+([\d.e+-]+)\s*["']/i);
    if (!viewBox) return null;
    const viewBoxWidth = Number(viewBox[3]);
    const viewBoxHeight = Number(viewBox[4]);
    return viewBoxWidth > 0 && viewBoxHeight > 0 ? { width: viewBoxWidth, height: viewBoxHeight } : null;
  }

  function parseSvgLength(value) {
    const number = Number.parseFloat(value || "");
    return Number.isFinite(number) && number > 0 ? number : null;
  }

  function looksLikeAvif(bytes) {
    return ascii(bytes, 4, 4) === "ftyp" && ascii(bytes, 8, 4).includes("avif");
  }

  function parseAvifDimensions(bytes) {
    for (let i = 0; i + 16 <= bytes.length; i++) {
      if (ascii(bytes, i, 4) !== "ispe") continue;
      const width = readUint32BE(bytes, i + 8);
      const height = readUint32BE(bytes, i + 12);
      if (width > 0 && height > 0) return { width, height };
    }
    return null;
  }

  function ascii(bytes, offset, length) {
    let value = "";
    for (let i = offset; i < offset + length && i < bytes.length; i++) value += String.fromCharCode(bytes[i]);
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

  async function handleImage(request, url, env, ctx, corsOrigin) {
    const imageHeaders = imageCorsHeaders(corsOrigin);

    if (request.method !== "GET" && request.method !== "HEAD") {
      return json({ error: "Method Not Allowed" }, 405, imageHeaders);
    }

    if (!env.pictures_lib) {
      return json({ error: "R2 binding missing: pictures_lib" }, 500, imageHeaders);
    }

    const encodedKey = url.pathname.slice("/api/image/".length);
    if (!encodedKey) return json({ error: "Bad Request: missing key" }, 400, imageHeaders);

    let key;
    try {
      key = decodeURIComponent(encodedKey);
    } catch {
      return json({ error: "Bad Request: invalid key encoding" }, 400, imageHeaders);
    }

    const expStr = url.searchParams.get("exp") || "";
    const sig = (url.searchParams.get("sig") || "").toLowerCase();

    if (!/^\d+$/.test(expStr)) return json({ error: "Bad Request: invalid exp" }, 400, imageHeaders);
    if (!/^[a-f0-9]{64}$/.test(sig)) return json({ error: "Bad Request: invalid sig" }, 400, imageHeaders);

    const exp = Number(expStr);
    const now = Math.floor(Date.now() / 1000);
    if (exp < now) return json({ error: "URL expired" }, 403, imageHeaders);

    const expectedSig = await signKeyExp(key, exp, env.SIGNING_SECRET);
    if (!timingSafeEqual(sig, expectedSig)) return json({ error: "Invalid signature" }, 403, imageHeaders);

    let cacheKey = null;
    if (request.method === "GET") {
      const cacheUrl = new URL(request.url);
      cacheUrl.pathname = `/__cache/image/${encodeURIComponent(key)}`;
      cacheUrl.search = "";
      cacheKey = new Request(cacheUrl.toString(), { method: "GET" });
      const cached = await caches.default.match(cacheKey);
      if (cached) {
        const hit = new Response(cached.body, cached);
        hit.headers.set("X-Worker-Cache", "HIT");
        return hit;
      }
    }

    const object = await env.pictures_lib.get(key);
    if (!object) return json({ error: "Not Found" }, 404, imageHeaders);

    const headers = new Headers(imageHeaders);
    headers.set("Cache-Control", `public, max-age=${IMAGE_CACHE_TTL}, immutable`);
    headers.set("Accept-Ranges", "bytes");
    if (object.httpEtag || object.etag) headers.set("ETag", object.httpEtag || object.etag);

    const contentType =
      object.httpMetadata?.contentType ||
      guessContentTypeFromKey(key) ||
      "application/octet-stream";
    headers.set("Content-Type", contentType);

    object.writeHttpMetadata(headers);

    if (request.method === "HEAD") {
      return new Response(null, { status: 200, headers });
    }

    const response = new Response(object.body, { status: 200, headers });
    response.headers.set("X-Worker-Cache", "MISS");
    if (cacheKey) {
      ctx.waitUntil(caches.default.put(cacheKey, response.clone()));
    }
    return response;
  }

  async function signKeyExp(key, exp, secret) {
    const sec = (secret || "").trim();
    if (!sec) throw new Error("SIGNING_SECRET is missing");

    const payload = `${key}.${exp}`;
    const enc = new TextEncoder();

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(sec),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const sigBuf = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(payload));
    return toHex(sigBuf);
  }

  function toHex(buf) {
    const bytes = new Uint8Array(buf);
    let out = "";
    for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
    return out;
  }

  function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  function guessContentTypeFromKey(key) {
    const lower = key.toLowerCase();
    if (lower.endsWith(".avif")) return "image/avif";
    if (lower.endsWith(".webp")) return "image/webp";
    if (lower.endsWith(".png")) return "image/png";
    if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
    if (lower.endsWith(".gif")) return "image/gif";
    if (lower.endsWith(".svg")) return "image/svg+xml";
    return null;
  }

  function parsePositiveInt(v, fallback) {
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
  }

  function resolveCorsOrigin(origin, allowedOriginsCsv) {
    if (!origin) return "";
    const list = allowedOriginsCsv
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    return list.includes(origin) ? origin : "";
  }

  function corsHeaders(corsOrigin) {
    if (!corsOrigin) return {};
    return {
      "Access-Control-Allow-Origin": corsOrigin,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      Vary: "Origin",
    };
  }

  function imageCorsHeaders(corsOrigin) {
    return {
      ...corsHeaders(corsOrigin),
      "Cross-Origin-Resource-Policy": "cross-origin",
    };
  }

  function handleOptions(pathname, corsOrigin) {
    if (pathname !== "/api/gallery") {
      return new Response(null, { status: 204 });
    }
    if (!corsOrigin) {
      return new Response(null, { status: 403 });
    }
    return new Response(null, {
      status: 204,
      headers: corsHeaders(corsOrigin),
    });
  }

  function json(data, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(data), {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        ...extraHeaders,
      },
    });
  }

