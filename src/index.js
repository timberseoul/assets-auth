import { handleGallery } from "./gallery.js";
import { handleImage } from "./image.js";

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

function resolveCorsOrigin(origin, allowedOriginsCsv) {
  if (!origin) return "";
  const allowedOrigins = String(allowedOriginsCsv || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  return allowedOrigins.includes(origin) ? origin : "";
}

function listCorsHeaders(origin) {
  if (!origin) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    Vary: "Origin",
  };
}

function imageCorsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Range, If-None-Match, Content-Type",
    "Cross-Origin-Resource-Policy": "cross-origin",
  };
}

function logRequest(route, request, response, startedAt, details = {}) {
  const entry = {
    event: "gallery_request",
    route,
    method: request.method,
    status: response.status,
    colo: request.cf?.colo || null,
    durationMs: Number((performance.now() - startedAt).toFixed(2)),
    cache: response.headers.get("X-Worker-Cache") || null,
    responseBytes: Number(response.headers.get("Content-Length")) || null,
    ...details,
  };
  console.log(JSON.stringify(entry));
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const corsOrigin = resolveCorsOrigin(origin, env.ALLOWED_ORIGINS || "");
    const startedAt = performance.now();

    try {
      if (request.method === "OPTIONS") {
        if (url.pathname === "/api/gallery") {
          if (origin && !corsOrigin) return json({ error: "Forbidden" }, 403);
          return new Response(null, { status: 204, headers: listCorsHeaders(corsOrigin) });
        }
        if (url.pathname.startsWith("/api/image/")) {
          return new Response(null, { status: 204, headers: imageCorsHeaders() });
        }
        return json({ error: "Not Found" }, 404);
      }

      if (url.pathname === "/api/gallery") {
        const response = await handleGallery(request, url, env, ctx, corsOrigin);
        logRequest("gallery", request, response, startedAt, {
          limit: url.searchParams.get("limit") || 40,
          hasCursor: url.searchParams.has("cursor"),
        });
        return response;
      }

      if (url.pathname.startsWith("/api/image/")) {
        const response = await handleImage(request, url, env, ctx);
        logRequest("image", request, response, startedAt, {
          keyPrefix: url.pathname.slice("/api/image/".length, "/api/image/".length + 40),
        });
        return response;
      }

      return json({ error: "Not Found" }, 404);
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "gallery_unhandled_error",
          method: request.method,
          path: url.pathname,
          error: error instanceof Error ? error.name : "UnknownError",
        })
      );
      return json({ error: "Internal Error" }, 500, imageCorsHeaders());
    }
  },
};
