function b64urlToB64(s: string): string {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  else if (pad !== 0) b64 += "===";
  return b64;
}

export function getExpFromJwt(jwt: string): number {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) return 0;
    const payloadJson = atob(b64urlToB64(parts[1]));
    const payload = JSON.parse(payloadJson);
    return typeof payload.exp === "number" ? payload.exp : 0;
  } catch {
    return 0;
  }
}
