import { getConnInfo } from "hono/bun";
import { ipRestriction } from "hono/ip-restriction";
import { createMiddleware, createFactory } from "hono/factory";
import type { Liquid } from "liquidjs";
import type { Session } from "hono-sessions";

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

export const route = createFactory<{
  Variables: {
    session: Session;
    session_key_rotation: boolean;
    engine: Liquid;
  };
}>();
