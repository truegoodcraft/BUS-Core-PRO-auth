import type { MiddlewareHandler } from "hono";
import { verifyIdentityToken } from "../services/crypto";
import type { Env } from "../index";

export const identityAuth: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  const authHeader = c.req.header("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return c.json({ ok: false, error: "missing_bearer" }, 401);
  }
  const token = authHeader.slice(7).trim();
  const subject = await verifyIdentityToken(token, c.env.IDENTITY_PUBLIC_KEY);
  if (!subject) {
    return c.json({ ok: false, error: "invalid_identity" }, 401);
  }
  c.set("tokenSubject", subject);
  await next();
};
