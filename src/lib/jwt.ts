export function getExpFromJwt(token: string): number {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return 0;

    let base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const pad = base64.length % 4;
    if (pad === 2) {
      base64 += "==";
    } else if (pad === 3) {
      base64 += "=";
    }

    const payload = JSON.parse(atob(base64));
    return typeof payload.exp === "number" ? payload.exp : 0;
  } catch (err) {
    console.error("[jwt] decode error:", err);
    return 0;
  }
}
