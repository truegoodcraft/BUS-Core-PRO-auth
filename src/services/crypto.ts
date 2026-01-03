const utf8Encode = (value: string): Uint8Array => {
  return new TextEncoder().encode(value);
};

const base64urlEncode = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const base64urlEncodeString = (value: string): string => {
  return base64urlEncode(utf8Encode(value));
};

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

const pemToDer = (pem: string): ArrayBuffer => {
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

export const hashString = async (input: string): Promise<string> => {
  const hash = await crypto.subtle.digest("SHA-256", utf8Encode(input));
  const bytes = new Uint8Array(hash);
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
};

export const generateNumericCode = (length: number = 6): string => {
  if (length <= 0) {
    return "";
  }
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let code = "";
  for (const byte of bytes) {
    code += (byte % 10).toString();
  }
  return code;
};

export const signIdentityToken = async (
  payload: { email: string },
  privateKeyPem: string
): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: "EdDSA",
    typ: "JWT",
  };
  const body = {
    typ: "identity",
    sub: payload.email,
    iss: "auth.buscore.ca",
    iat: now,
    exp: now + 7 * 24 * 60 * 60,
  };

  const headerEncoded = base64urlEncodeString(JSON.stringify(header));
  const bodyEncoded = base64urlEncodeString(JSON.stringify(body));
  const signingInput = `${headerEncoded}.${bodyEncoded}`;

  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(privateKeyPem),
    { name: "Ed25519" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    utf8Encode(signingInput)
  );

  const signatureEncoded = base64urlEncode(new Uint8Array(signature));
  return `${signingInput}.${signatureEncoded}`;
};

export const verifyIdentityToken = async (
  token: string,
  publicKeyPem: string
): Promise<string | null> => {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }
  const [headerEncoded, bodyEncoded, signatureEncoded] = parts;
  let body: { sub?: string; iss?: string; exp?: number };
  try {
    body = JSON.parse(base64urlDecodeToString(bodyEncoded)) as {
      sub?: string;
      iss?: string;
      exp?: number;
    };
  } catch {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (!body.exp || now > body.exp) {
    return null;
  }
  if (body.iss !== "auth.buscore.ca") {
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

  if (!valid || !body.sub) {
    return null;
  }
  return body.sub;
};

export const getExpFromJwt = (token: string): number => {
  const [, payload] = token.split(".");
  if (!payload) {
    return 0;
  }
  try {
    const obj = JSON.parse(base64urlDecodeToString(payload)) as { exp?: number };
    return typeof obj.exp === "number" ? obj.exp : 0;
  } catch {
    return 0;
  }
};
