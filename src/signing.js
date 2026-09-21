export function normalizeEtag(etag) {
  return String(etag || "").replace(/^W\//, "").replace(/^"|"$/g, "");
}

export function timingSafeEqualHex(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  let output = "";
  for (const byte of bytes) output += byte.toString(16).padStart(2, "0");
  return output;
}

export function createHmacSigner(secret) {
  const normalizedSecret = String(secret || "").trim();
  if (!normalizedSecret) return null;
  const encoder = new TextEncoder();
  const keyPromise = crypto.subtle.importKey(
    "raw",
    encoder.encode(normalizedSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return {
    async sign(message) {
      const key = await keyPromise;
      const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
      return toHex(signature);
    },
  };
}

export async function signMessage(message, secret) {
  const signer = createHmacSigner(secret);
  if (!signer) throw new Error("SIGNING_SECRET is missing");
  return signer.sign(message);
}

export function versionedSignatureMessage(key, etag, exp) {
  return [key, normalizeEtag(etag), exp].join(".");
}

export async function signVersionedKey(key, etag, exp, secret) {
  return signMessage(versionedSignatureMessage(key, etag, exp), secret);
}
