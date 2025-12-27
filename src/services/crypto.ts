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
