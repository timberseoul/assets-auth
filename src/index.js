 export default {
    async fetch(request, env) {
      try {
        const url = new URL(request.url);

        if (url.pathname === "/api/gallery") return handleGallery(request, env);
        if (url.pathname.startsWith("/api/image/")) return handleImage(request, env);

        return json({ error: "Not Found" }, 404);
      } catch (err) {
        return json({ error: err?.message || String(err) }, 500);
      }
    },
  };

  async function handleGallery(request, env) {
    if (request.method !== "GET") return json({ error: "Method Not Allowed" }, 405);
    assertEnv(env);

    const url = new URL(request.url);
    const prefix = (url.searchParams.get("prefix") || "pics/pic/").trim();
    const limit = clampInt(url.searchParams.get("limit"), 1, 1000, 200);
    const ttl = clampInt(url.searchParams.get("ttl"), 60, 86400 * 365, Number(env.SIGN_TTL_SECONDS || 3600));

    const listed = await env.ASSETS_BUCKET.list({ prefix, limit });
    const exts = /\.(avif|webp|png|jpe?g|gif)$/i;
    const origin = `${url.protocol}//${url.host}`;

    const items = [];
    for (const obj of listed.objects) {
      if (!exts.test(obj.key)) continue;
      const path = `/api/image/${encodeURIComponent(obj.key)}`;
      const { exp, sig } = await signPath(path, ttl, env.SIGNING_SECRET);
      items.push({
        key: obj.key,
        name: obj.key.split("/").pop() || obj.key,
        url: `${origin}${path}?exp=${exp}&sig=${sig}`,
        size: obj.size,
        uploaded: obj.uploaded?.toISOString?.() || null,
      });
    }

    return json({ items, count: items.length, truncated: listed.truncated, cursor: listed.cursor || null }, 200, {
      "Cache-Control": "public, max-age=30, s-maxage=30",
    });
  }

  async function handleImage(request, env) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return json({ error: "Method Not Allowed" }, 405);
    }
    assertEnv(env);

    const url = new URL(request.url);
    const exp = url.searchParams.get("exp");
    const sig = url.searchParams.get("sig");
    if (!exp || !sig) return json({ error: "Missing exp/sig" }, 403);

    const now = Math.floor(Date.now() / 1000);
    const expNum = Number(exp);
    if (!Number.isFinite(expNum) || expNum < now) return json({ error: "Signature expired" }, 403);

    const ok = await verifySignature(url.pathname, exp, sig, env.SIGNING_SECRET);
    if (!ok) return json({ error: "Bad signature" }, 403);

    const encodedKey = url.pathname.replace(/^\/api\/image\//, "");
    const key = decodeURIComponent(encodedKey);
    const object = await env.ASSETS_BUCKET.get(key);
    if (!object) return json({ error: "Not Found" }, 404);

    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("ETag", object.httpEtag);
    headers.set("Cache-Control", "public, max-age=31536000, immutable");
    headers.set("X-Content-Type-Options", "nosniff");
    if (!headers.get("Content-Type")) headers.set("Content-Type", guessType(key));

    if (request.method === "HEAD") return new Response(null, { status: 200, headers });
    return new Response(object.body, { status: 200, headers });
  }

  function assertEnv(env) {
    if (!env.ASSETS_BUCKET) throw new Error("Missing R2 binding ASSETS_BUCKET");
    if (typeof env.SIGNING_SECRET !== "string" || !env.SIGNING_SECRET.length) {
      throw new Error("Missing SIGNING_SECRET");
    }
  }

  async function signPath(pathname, ttlSec, secret) {
    const exp = String(Math.floor(Date.now() / 1000) + ttlSec);
    const payload = `${pathname}\n${exp}`;
    const sig = await hmacHex(payload, secret);
    return { exp, sig };
  }

  async function verifySignature(pathname, exp, sig, secret) {
    const payload = `${pathname}\n${exp}`;
    const expected = await hmacHex(payload, secret);
    return timingSafeEqual(expected, sig.toLowerCase());
  }

  async function hmacHex(message, secret) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const mac = await crypto.subtle.sign("HMAC", key, enc.encode(message));
    return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let out = 0;
    for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return out === 0;
  }

  function clampInt(raw, min, max, fallback) {
    const n = Number(raw ?? fallback);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, Math.floor(n)));
  }

  function json(data, status = 200, extra = {}) {
    return new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8", ...extra },
    });
  }

  function guessType(key) {
    if (/\.avif$/i.test(key)) return "image/avif";
    if (/\.webp$/i.test(key)) return "image/webp";
    if (/\.png$/i.test(key)) return "image/png";
    if (/\.jpe?g$/i.test(key)) return "image/jpeg";
    if (/\.gif$/i.test(key)) return "image/gif";
    return "application/octet-stream";
  }