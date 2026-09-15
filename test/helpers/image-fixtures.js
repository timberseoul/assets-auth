function concatBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.byteLength;
  }
  return bytes;
}

function u16be(value) {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function u32be(value) {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function u16le(value) {
  return new Uint8Array([value & 0xff, (value >>> 8) & 0xff]);
}

function u32le(value) {
  return new Uint8Array([
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  ]);
}

function u24le(value) {
  return new Uint8Array([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff]);
}

function ascii(value) {
  return new TextEncoder().encode(value);
}

function box(type, payload) {
  return concatBytes(u32be(payload.byteLength + 8), ascii(type), payload);
}

export function createPng({ width = 1200, height = 800 } = {}) {
  return concatBytes(
    new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    u32be(13),
    ascii("IHDR"),
    u32be(width),
    u32be(height),
    new Uint8Array([8, 6, 0, 0, 0]),
    new Uint8Array(4),
  );
}

export function createGif({ width = 640, height = 480 } = {}) {
  return concatBytes(ascii("GIF89a"), u16le(width), u16le(height), new Uint8Array(4));
}

function jpegSegment(marker, payload) {
  return concatBytes(new Uint8Array([0xff, marker]), u16be(payload.byteLength + 2), payload);
}

export function createJpeg({ width = 1600, height = 900, padding = 0 } = {}) {
  const parts = [new Uint8Array([0xff, 0xd8])];
  let remaining = padding;
  while (remaining > 0) {
    const chunkSize = Math.min(remaining, 65533);
    parts.push(jpegSegment(0xe1, new Uint8Array(chunkSize)));
    remaining -= chunkSize;
  }
  parts.push(jpegSegment(0xc0, concatBytes(new Uint8Array([8]), u16be(height), u16be(width), new Uint8Array([3, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]))));
  parts.push(new Uint8Array([0xff, 0xd9]));
  return concatBytes(...parts);
}

export function createWebp({ width = 1024, height = 768 } = {}) {
  const vp8x = concatBytes(
    ascii("VP8X"),
    u32le(10),
    new Uint8Array([0, 0, 0, 0]),
    u24le(width - 1),
    u24le(height - 1),
  );
  return concatBytes(ascii("RIFF"), u32le(4 + vp8x.byteLength), ascii("WEBP"), vp8x);
}

export function createSvg({ width = 320, height = 180, prefix = "" } = {}) {
  return ascii(`${prefix}<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}"></svg>`);
}

export function createAvif({ width = 1920, height = 1080, padding = 0 } = {}) {
  const ftyp = box("ftyp", concatBytes(ascii("avif"), u32be(0), ascii("avif"), ascii("mif1")));
  const ispe = box("ispe", concatBytes(new Uint8Array(4), u32be(width), u32be(height)));
  const ipco = box("ipco", ispe);
  const iprp = box("iprp", ipco);
  const free = padding > 0 ? box("free", new Uint8Array(padding)) : new Uint8Array();
  const meta = box("meta", concatBytes(new Uint8Array(4), iprp));
  return concatBytes(ftyp, free, meta);
}

export function corruptImage(bytes) {
  const copy = Uint8Array.from(bytes);
  if (copy.byteLength > 0) copy[copy.byteLength - 1] ^= 0xff;
  return copy;
}

export const imageFixtures = {
  png: createPng(),
  gif: createGif(),
  jpeg: createJpeg(),
  webp: createWebp(),
  svg: createSvg(),
  avif: createAvif(),
};

export const crossSegmentFixtures = {
  jpeg: createJpeg({ width: 2048, height: 1152, padding: 80 * 1024 }),
  svg: createSvg({ width: 800, height: 600, prefix: " ".repeat(80 * 1024) }),
  avif: createAvif({ width: 2560, height: 1440, padding: 160 * 1024 }),
};

export const scanLimitFixtures = {
  jpeg: createJpeg({ width: 4096, height: 2160, padding: 520 * 1024 }),
  svg: createSvg({ width: 4096, height: 2160, prefix: " ".repeat(260 * 1024) }),
  avif: createAvif({ width: 4096, height: 2160, padding: 1024 * 1024 }),
};
