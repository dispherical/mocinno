import { getConnInfo } from "hono/bun";
import { ipRestriction } from "hono/ip-restriction";
import { createMiddleware } from "hono/factory";

export const localOnly = ipRestriction(
  getConnInfo,
  {
    denyList: [],
    allowList: [
      "127.0.0.1",
      "::1",
      "::ffff:127.0.0.1",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "fc00::/7",
      "fe80::/10",
    ],
  },
  async (remote, c) => {
    return c.json({ error: "Forbidden.", success: false }, 403);
  },
);

export const denyForward = createMiddleware(async (c, next) => {
  if (
    c.req.header("X-Forwarded-For") ||
    c.req.header("X-Forwarded-Proto") ||
    c.req.header("X-Forwarded-Host")
  )
    return c.json({ error: "Forbidden.", success: false }, 403);
  return next();
});
