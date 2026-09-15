import {
  GALLERY_DEFAULT_LIMIT,
  GALLERY_MAX_CURSOR_LENGTH,
  GALLERY_MAX_LIMIT,
  GALLERY_MAX_PREFIX_LENGTH,
  GALLERY_PREFIX,
  IMAGE_MAX_KEY_LENGTH,
} from "./constants.js";

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

export function badRequest(message) {
  return new HttpError(400, message);
}

function hasControlCharacters(value) {
  return /[\x00-\x1f\x7f]/.test(value);
}

function hasUnsafeSegments(value) {
  return value.split("/").some((segment) => segment === "." || segment === "..");
}

export function validatePrefix(value) {
  const prefix = value === null ? GALLERY_PREFIX : value;
  if (!prefix || prefix.length > GALLERY_MAX_PREFIX_LENGTH) throw badRequest("invalid prefix");
  if (!prefix.startsWith(GALLERY_PREFIX) || prefix.includes("\\") || hasControlCharacters(prefix) || hasUnsafeSegments(prefix)) {
    throw badRequest("invalid prefix");
  }
  return prefix;
}

export function validateCursor(value) {
  if (value === null || value === "") return null;
  if (value.length > GALLERY_MAX_CURSOR_LENGTH || hasControlCharacters(value)) throw badRequest("invalid cursor");
  return value;
}

export function validateLimit(value) {
  if (value === null) return GALLERY_DEFAULT_LIMIT;
  if (!/^\d+$/.test(value)) throw badRequest("invalid limit");
  const limit = Number(value);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > GALLERY_MAX_LIMIT) throw badRequest("invalid limit");
  return limit;
}

export function validateGalleryQuery(url) {
  return {
    prefix: validatePrefix(url.searchParams.get("prefix")),
    cursor: validateCursor(url.searchParams.get("cursor")),
    limit: validateLimit(url.searchParams.get("limit")),
  };
}

export function decodeImageKey(encodedKey) {
  if (!encodedKey || encodedKey.length > IMAGE_MAX_KEY_LENGTH * 3) throw badRequest("invalid key encoding");
  let key;
  try {
    key = decodeURIComponent(encodedKey);
  } catch {
    throw badRequest("invalid key encoding");
  }
  if (!key || key.length > IMAGE_MAX_KEY_LENGTH || key.includes("\\") || hasControlCharacters(key)) {
    throw badRequest("invalid key");
  }
  if (!key.startsWith(GALLERY_PREFIX) || hasUnsafeSegments(key)) throw new HttpError(403, "invalid key scope");
  return key;
}

export function validateImageVersion(value, required) {
  if (value === null) {
    if (required) throw badRequest("invalid v");
    return null;
  }
  if (!value || value.length > 256 || !/^[A-Za-z0-9._~-]+$/.test(value)) throw badRequest("invalid v");
  return value;
}

export function parseByteRange(header, size) {
  if (!header) return null;
  if (!Number.isSafeInteger(size) || size < 1 || !header.startsWith("bytes=") || header.includes(",")) {
    throw new HttpError(416, "Range Not Satisfiable");
  }

  const match = /^bytes=(\d*)-(\d*)$/.exec(header);
  if (!match || (!match[1] && !match[2])) throw new HttpError(416, "Range Not Satisfiable");

  if (!match[1]) {
    const suffixLength = Number(match[2]);
    if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) throw new HttpError(416, "Range Not Satisfiable");
    const length = Math.min(suffixLength, size);
    return { offset: size - length, length };
  }

  const start = Number(match[1]);
  if (!Number.isSafeInteger(start) || start >= size) throw new HttpError(416, "Range Not Satisfiable");
  const requestedEnd = match[2] ? Number(match[2]) : size - 1;
  if (!Number.isSafeInteger(requestedEnd) || requestedEnd < start) throw new HttpError(416, "Range Not Satisfiable");
  const end = Math.min(requestedEnd, size - 1);
  return { offset: start, length: end - start + 1, end };
}
