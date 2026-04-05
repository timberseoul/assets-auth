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
          return handleImage(request, url, env);
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

    const items = [];
    for (const obj of listed.objects) {
      const key = obj.key;
      const sig = await signKeyExp(key, exp, env.SIGNING_SECRET);
      const encodedKey = encodeURIComponent(key);
      const imageUrl = `${base.origin}/api/image/${encodedKey}?exp=${exp}&sig=${sig}`;

      items.push({
        key,
        name: key.split("/").pop() || key,
        size: obj.size ?? null,
        uploaded: obj.uploaded ? obj.uploaded.toISOString() : null,
        url: imageUrl,
      });
    }

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

  async function handleImage(request, url, env) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return json({ error: "Method Not Allowed" }, 405);
    }

    if (!env.pictures_lib) {
      return json({ error: "R2 binding missing: pictures_lib" }, 500);
    }

    const encodedKey = url.pathname.slice("/api/image/".length);
    if (!encodedKey) return json({ error: "Bad Request: missing key" }, 400);

    let key;
    try {
      key = decodeURIComponent(encodedKey);
    } catch {
      return json({ error: "Bad Request: invalid key encoding" }, 400);
    }

    const expStr = url.searchParams.get("exp") || "";
    const sig = (url.searchParams.get("sig") || "").toLowerCase();

    if (!/^\d+$/.test(expStr)) return json({ error: "Bad Request: invalid exp" }, 400);
    if (!/^[a-f0-9]{64}$/.test(sig)) return json({ error: "Bad Request: invalid sig" }, 400);

    const exp = Number(expStr);
    const now = Math.floor(Date.now() / 1000);
    if (exp < now) return json({ error: "URL expired" }, 403);

    const expectedSig = await signKeyExp(key, exp, env.SIGNING_SECRET);
    if (!timingSafeEqual(sig, expectedSig)) return json({ error: "Invalid signature" }, 403);

    const object = await env.pictures_lib.get(key);
    if (!object) return json({ error: "Not Found" }, 404);

    const headers = new Headers();
    headers.set("Cache-Control", "public, max-age=31536000, immutable");
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

    return new Response(object.body, { status: 200, headers });
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