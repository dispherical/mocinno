import { CookieStore, sessionMiddleware } from "hono-sessions";
import * as env from "./env";
import { Hono } from "hono";
import { getOrIssueCertificate, renewExpiringCertificates } from "./cert";
import * as db from "./db.js";

const app = new Hono();

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

const serve = Bun.serve({
  fetch: app.fetch,
  port: env.MOCINNO_PORT,
  maxRequestBodySize: env.MOCINNO_MAX_BODY_REQUEST_SIZE,
  hostname: env.MOCINNO_HOSTNAME,
});

console.log("Mocinno is running on port %s (%s)", serve.port, serve.hostname);

(async () => {
  if (!env.DISABLE_SSL) {
    const appDomain = process.env.APP_DOMAIN;
    if (appDomain) {
      try {
        await getOrIssueCertificate(appDomain);
        console.log(`Certificate ready for ${appDomain}`);
      } catch (err) {
        if (err instanceof Error) {
          console.error(
            `Failed to issue certificate for ${appDomain}:`,
            err.message,
          );
          return;
        }
        console.error(
          `Failed to issue certificate for ${appDomain}, error unknown:`,
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
