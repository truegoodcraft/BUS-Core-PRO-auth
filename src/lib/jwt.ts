function b64urlToB64(s: string): string {
  // URL-safe -> standard base64
  let b = s.replace(/-/g, "+").replace(/_/g, "/");
  // pad to length % 4 === 0
  const pad = b.length % 4;
  if (pad === 2) b += "==";
  else if (pad === 3) b += "=";
  else if (pad === 1) b += "==="; // defensive, should not happen
  return b;
}

export function getExpFromJwt(jwt: string): number {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) return 0;
    const payloadJson = atob(b64urlToB64(parts[1]));
    const claims = JSON.parse(payloadJson);
    return typeof claims.exp === "number" ? claims.exp : 0;
  } catch (err) {
    // Do NOT throw; verify must continue even if exp can’t be parsed
    console.log("[jwt] exp decode failed; proceeding with exp=0");
    return 0;
  }
}
