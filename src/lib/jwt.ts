function b64urlToB64(input: string): string {
  // JWT uses base64url; convert to standard base64 for atob
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  else if (pad !== 0) b64 += "===";
  return b64;
}

export function getExpFromJwt(jwt: string): number {
  try {
    const parts = jwt.split(".");
    if (parts.length < 2) return 0;
    const payloadB64 = b64urlToB64(parts[1]);
    const json = atob(payloadB64);
    const obj = JSON.parse(json);
    return typeof obj.exp === "number" ? obj.exp : 0;
  } catch {
    return 0;
  }
}
