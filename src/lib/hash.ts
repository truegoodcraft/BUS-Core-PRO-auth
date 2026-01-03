import { hashString } from "../services/crypto";

export async function hashMagicCode(code: string, email: string, _env: unknown): Promise<string> {
  const normalizedEmail = (email ?? "").trim().toLowerCase();
  return hashString(`${code}:${normalizedEmail}`);
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i += 1) {
    res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return res === 0;
}
