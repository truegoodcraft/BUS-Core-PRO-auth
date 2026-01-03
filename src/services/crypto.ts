// Helper to safely decode PEM (handles whitespace/newlines correctly)
const pemToDer = (pem: string): ArrayBuffer => {
  // Remove PEM headers/footers and ALL whitespace (including \r\n)
  const stripped = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");

  const binary = atob(stripped);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

const utf8Encode = (value: string): Uint8Array => new TextEncoder().encode(value);

const base64urlEncode = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const base64urlEncodeString = (value: string): string =>
  base64urlEncode(utf8Encode(value));

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
  const headerEncoded = base64urlEncodeString(JSON.stringify(header));
  const payloadEncoded = base64urlEncodeString(JSON.stringify(fullPayload));
  const signingInput = `${headerEncoded}.${payloadEncoded}`;

  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(privateKeyPem),
    { name: "Ed25519" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("Ed25519", privateKey, utf8Encode(signingInput));
  const signatureEncoded = base64urlEncode(new Uint8Array(signature));
  return `${signingInput}.${signatureEncoded}`;
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
    utf8Encode(signingInput)
  );

  if (!valid) {
    return null;
  }
  return body.sub;
};
