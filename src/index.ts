import { CookieStore, sessionMiddleware } from "hono-sessions";
import * as env from "./env";
import {
  getChallengeResponse,
  getOrIssueCertificate,
  isPublicDomain,
  renewExpiringCertificates,
} from "./cert";
import * as db from "./db";
import { serveStatic } from "hono/bun";
import { route } from "./middleware";
import { Liquid } from "liquidjs";
import { proxyRequest, reloadProxy } from "./utils";

import internalRoutes from "@/routes/internal";
import webRoutes from "@/routes/web";
import userRoutes from "@/routes/user";
import authRoutes from "@/routes/auth";
import applicationRoutes from "@/routes/application";
import adminRoutes from "@/routes/admin";

const app = route.createApp();

app.get("/privacy.pdf", serveStatic({ path: "./src/public/privacy.pdf" }));

const store = new CookieStore();

app.use(
  "*",
  sessionMiddleware({
    store,
    encryptionKey: env.ENCRYPTION_KEY,
    expireAfterSeconds: 900,
    autoExtendExpiration: true,
    cookieOptions: {
      sameSite: "Lax",
      path: "/",
      httpOnly: true,
    },
  }),
);

const engine = new Liquid({
  root: "./views",
  extname: ".liquid",
  outputEscape: "escape",
  cache: process.env.NODE_ENV == "production",
});

app.use("*", async (c, next) => {
  c.set("engine", engine);
  const session = c.get("session");

  // allowing sudo mode in development without 2fa
  if (process.env.NODE_ENV !== "production") session.flash("sudo", true);
  await next();
});

app.route("", internalRoutes);

app.route("", webRoutes);
app.route("", userRoutes);
app.route("", authRoutes);
app.route("", applicationRoutes);
app.route("", adminRoutes);

const serve = Bun.serve({
  fetch: app.fetch,
  port: env.MOCINNO_PORT,
  maxRequestBodySize: env.MOCINNO_MAX_BODY_REQUEST_SIZE,
  hostname: env.MOCINNO_HOSTNAME,
});

Bun.serve({
  port: process.env.PORT || 80,
  hostname: "0.0.0.0",
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname.startsWith("/.well-known/acme-challenge/")) {
      const token = url.pathname.split("/").pop();
      const keyAuth = getChallengeResponse(token);
      if (keyAuth)
        return new Response(keyAuth, {
          headers: { "Content-Type": "application/octet-stream" },
        });
      return new Response("Not found", { status: 404 });
    }
    const host = req.headers.get("host")?.split(":")[0] || "";
    if (env.DISABLE_SSL || !isPublicDomain(host)) {
      try {
        const appDomain = env.APP_DOMAIN;
        if (appDomain && host === appDomain) {
          const appPort = env.MOCINNO_PORT.toFixed(0);
          return proxyRequest(req, `127.0.0.1:${appPort}`);
        }
        const domainRow = await db.getDomainByName(host);
        if (!domainRow) return new Response("Not found", { status: 404 });
        return proxyRequest(req, domainRow.proxy);
      } catch (err) {
        if (err instanceof Error) {
          console.error("HTTP proxy error:", err.message);
        } else {
          console.error("HTTP proxy error:", err);
        }
        return new Response("Bad Gateway", { status: 502 });
      }
    }
    return Response.redirect(
      `https://${req.headers.get("host")}${url.pathname}${url.search}`,
      301,
    );
  },
});

console.log("Mocinno is running on port %s (%s)", serve.port, serve.hostname);

(async () => {
  if (!env.DISABLE_SSL) {
    if (env.APP_DOMAIN) {
      try {
        await getOrIssueCertificate(env.APP_DOMAIN);
        console.log(`Certificate ready for ${env.APP_DOMAIN}`);
      } catch (err) {
        if (err instanceof Error) {
          console.error(
            `Failed to issue certificate for ${env.APP_DOMAIN}:`,
            err.message,
          );
          return;
        }
        console.error(
          `Failed to issue certificate for ${env.APP_DOMAIN}, error unknown:`,
          err,
        );
      }
    }

    const domains = await db.getAllDomains();
    for (const d of domains) {
      try {
        await getOrIssueCertificate(d.domain);
      } catch (err) {
        if (err instanceof Error) {
          console.error(
            `Failed to issue certificate for ${d.domain}:`,
            err.message,
          );
          return;
        }
        console.error(
          `Failed to issue certificate for ${d.domain}, error unknown:`,
          err,
        );
      }
    }

    await reloadProxy();
    console.log("Proxy server running on port 443");

    setInterval(
      async () => {
        try {
          await renewExpiringCertificates();
          await reloadProxy();
        } catch (err) {
          if (err instanceof Error) {
            console.error("Certificate renewal error:", err.message);
          } else {
            console.error("Certificate renewal error:", err);
          }
        }
      },
      12 * 60 * 60 * 1000,
    );
  } else {
    console.log("[!] SSL is disabled. Please don't be stupid with this.");
  }
})();

process.on("uncaughtException", (error) => {
  console.error(error);
});

process.on("unhandledRejection", (error) => {
  console.error(error);
});
