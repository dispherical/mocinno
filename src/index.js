import { Hono } from "hono";
import { getConnInfo } from "hono/bun";
import { ipRestriction } from "hono/ip-restriction";
import { sessionMiddleware, CookieStore } from "hono-sessions";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:dns/promises";
import * as db from "./db.js";
import { serveStatic } from "hono/bun";
import { utils } from "ssh2";
import {
  getChallengeResponse,
  issueCertificate,
  renewExpiringCertificates,
  getOrIssueCertificate,
  isPublicDomain,
} from "./cert.js";
import {
  pveFetch,
  setContainerDescription,
  isContainerSuspended,
  getContainerConfig,
} from "./pve-utils.js";

const app = new Hono();

const serve = Bun.serve({
  fetch: app.fetch,
  port: process.env.MOCINNO_PORT || 3000,
  maxRequestBodySize:
    process.env.MOCINNO_MAX_BODY_REQUEST_SIZE || 1024 * 1024 * 128,
  hostname: process.env.MOCINNO_HOSTNAME || "127.0.0.1",
});

console.log("Mocinno is running on port %s (%s)", serve.port, serve.hostname);

(async () => {
  if (process.env.DISABLE_SSL !== "true") {
    const appDomain = process.env.APP_DOMAIN;
    if (appDomain) {
      try {
        await getOrIssueCertificate(appDomain);
        console.log(`Certificate ready for ${appDomain}`);
      } catch (err) {
        console.error(
          `Failed to issue certificate for ${appDomain}:`,
          err.message,
        );
      }
    }

    const domains = await db.getAllDomains();
    for (const d of domains) {
      try {
        await getOrIssueCertificate(d.domain);
      } catch (err) {
        console.error(
          `Failed to issue certificate for ${d.domain}:`,
          err.message,
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
          console.error("Certificate renewal error:", err.message);
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
