function b64urlToB64(s: string): string {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  return b64;
}

export function getExpFromJwt(token: string): number {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return 0;
    const payload = atob(b64urlToB64(parts[1]));
    const obj = JSON.parse(payload);
    return typeof obj.exp === "number" ? obj.exp : 0;
  } catch {
    return 0;
  }
}
