function base64UrlToBase64(str: string): string {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4;
  if (pad === 2) base64 += "==";
  else if (pad === 3) base64 += "=";
  else if (pad !== 0) base64 += "===";
  return base64;
}

export function getExpFromJwt(token: string): number {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return 0;
    const payloadJson = atob(base64UrlToBase64(parts[1]));
    const claims = JSON.parse(payloadJson);
    return typeof claims.exp === "number" ? claims.exp : 0;
  } catch {
    return 0;
  }
}
