const pemToDer = (pem: string): ArrayBuffer => {
  if (!pem || typeof pem !== "string") throw new Error("missing_private_key");
  // Nuclear strip: remove headers/footers and ANY non-base64 char
  const stripped = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/[^A-Za-z0-9+/=]/g, "");
  const bin = atob(stripped);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out.buffer;
};

const utf8 = (s: string) => new TextEncoder().encode(s);
const b64u = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const b64uStr = (s: string) =>
  btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

const base64urlDecodeToBytes = (value: string): Uint8Array => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const base64 = `${normalized}${padding}`;
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const base64urlDecodeToString = (value: string): string => {
  const bytes = base64urlDecodeToBytes(value);
  return new TextDecoder().decode(bytes);
};

export async function signIdentityToken(
  payload: { email: string },
  privateKeyPem: string
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const fullPayload = {
    v: 1,
    sub: payload.email.toLowerCase(),
    aud: "bus-auth",
    purpose: "identity",
    iat: now,
    exp: now + 7 * 24 * 60 * 60,
  };

  const header = { alg: "EdDSA", typ: "JWT" };
  const signingInput = `${b64uStr(JSON.stringify(header))}.${b64uStr(JSON.stringify(fullPayload))}`;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(privateKeyPem),
    { name: "Ed25519" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("Ed25519", key, utf8(signingInput));
  return `${signingInput}.${b64u(new Uint8Array(sig))}`;
}

export function generateNumericCode(length: number): string {
  let code = "";
  for (let i = 0; i < length; i += 1) code += Math.floor(Math.random() * 10).toString();
  return code;
}

export async function hashString(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

export const normalizeEmail = (e: string) => (e ?? "").trim().toLowerCase();

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function constantTimeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i += 1) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export async function hashMagicCode(code: string, normalizedEmail: string, pepper?: string) {
  return sha256Hex(`${code}:${normalizedEmail}:${pepper ?? ""}`);
}

export const short8 = (s: string) => (s ? s.slice(0, 8) : "");

export const verifyIdentityToken = async (
  token: string,
  publicKeyPem: string
): Promise<string | null> => {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }
  const [headerEncoded, bodyEncoded, signatureEncoded] = parts;
  let body: { sub?: string; aud?: string; purpose?: string; v?: number; exp?: number };
  try {
    body = JSON.parse(base64urlDecodeToString(bodyEncoded)) as {
      sub?: string;
      aud?: string;
      purpose?: string;
      v?: number;
      exp?: number;
    };
  } catch {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (!body.exp || now > body.exp) {
    return null;
  }
  if (body.aud !== "bus-auth" || body.purpose !== "identity" || body.v !== 1) {
    return null;
  }
  if (!body.sub) {
    return null;
  }

  const signingInput = `${headerEncoded}.${bodyEncoded}`;
  const signatureBytes = base64urlDecodeToBytes(signatureEncoded);
  const publicKey = await crypto.subtle.importKey(
    "spki",
    pemToDer(publicKeyPem),
    { name: "Ed25519" },
    true,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    "Ed25519",
    publicKey,
    signatureBytes,
    utf8(signingInput)
  );

  if (!valid) {
    return null;
  }
  return body.sub;
};
