export const GALLERY_PREFIX = "pics/pic/";
export const GALLERY_DEFAULT_LIMIT = 40;
export const GALLERY_MAX_LIMIT = 50;
export const GALLERY_MAX_CURSOR_LENGTH = 512;
export const GALLERY_MAX_PREFIX_LENGTH = 512;
export const IMAGE_MAX_KEY_LENGTH = 1024;
export const IMAGE_MAX_VERSION_LENGTH = 256;

export const SIGNED_URL_TTL = 31536000;
export const IMAGE_CACHE_TTL = 31536000;
export const IMAGE_METADATA_POSITIVE_TTL = 31536000;
export const IMAGE_METADATA_NEGATIVE_TTL = 300;
export const GALLERY_MANIFEST_TTL = 300;

export const DIMENSION_CONCURRENCY_DEFAULT = 5;
export const DIMENSION_ABSOLUTE_MAX_BYTES = 1024 * 1024;

export const DIMENSION_LIMITS = Object.freeze({
  png: { initial: 64 * 1024, chunk: 64 * 1024, max: 64 * 1024 },
  gif: { initial: 64 * 1024, chunk: 64 * 1024, max: 64 * 1024 },
  webp: { initial: 64 * 1024, chunk: 64 * 1024, max: 64 * 1024 },
  jpeg: { initial: 64 * 1024, chunk: 64 * 1024, max: 512 * 1024 },
  avif: { initial: 128 * 1024, chunk: 128 * 1024, max: 1024 * 1024 },
  svg: { initial: 64 * 1024, chunk: 64 * 1024, max: 256 * 1024 },
  unknown: { initial: 64 * 1024, chunk: 64 * 1024, max: 64 * 1024 },
});
