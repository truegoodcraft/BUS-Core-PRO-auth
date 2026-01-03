export function getExpFromJwt(token: string): number {
  try {
    const payloadB64 = token.split(".")[1];
    const base64 = payloadB64.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    return JSON.parse(jsonPayload).exp || 0;
  } catch {
    return 0;
  }
}
