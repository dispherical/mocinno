import { resolve } from "node:dns/promises";
import * as crypto from "node:crypto";
import * as db from "./db";

import * as env from "./env";

export async function checkDNSVerification(domain: string, username: string) {
  try {
    const records = await resolve(domain, "TXT");
    for (const record of records) {
      const txt = record.join("");
      if (txt === `domain-verification=${username}`) return true;
    }
  } catch {}

  try {
    const cnames = await resolve(domain, "CNAME");
    for (const cname of cnames) {
      if (
        cname === `${username}.hackclub.app` ||
        cname === `${username}.hackclub.app.`
      )
        return true;
    }
  } catch {}

  return false;
}

export function formatUptime(seconds: number) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);

  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);

  return parts.join(" ") || "0m";
}

export function isFQDN(domain: string) {
  return /^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/.test(domain);
}

export function isWhitelisted(domain: string, username: string) {
  return (
    domain === `${username}.hackclub.app` ||
    domain.endsWith(`.${username}.hackclub.app`) ||
    domain.endsWith(`.${username}.localhost`) ||
    domain.endsWith(`${username}.localhost`)
  );
}

export function generateState(length = 16) {
  return crypto
    .randomBytes(length)
    .toString("base64")
    .replace(/[^a-zA-Z0-9]/g, "")
    .slice(0, length);
}

export async function buildServerNames() {
  const certs = await db.getAllCertificates();
  const serverNames: { [key: string]: { cert: string; key: string } } = {};
  for (const cert of certs) {
    serverNames[cert.domain] = { cert: cert.cert, key: cert.key };
  }
  return serverNames;
}

export async function proxyRequest(req: Request, target: string) {
  const url = new URL(req.url);
  const targetUrl = new URL(req.url);

  targetUrl.protocol = "http:";
  targetUrl.host = target;

  const proxyReq = new Request(targetUrl.toString(), {
    method: req.method,
    headers: req.headers,
    body: req.method !== "GET" && req.method !== "HEAD" ? req.body : undefined,
    redirect: "manual",
  });

  proxyReq.headers.set(
    "X-Forwarded-For",
    req.headers.get("X-Forwarded-For") || "",
  );
  proxyReq.headers.set("X-Forwarded-Proto", "https");
  proxyReq.headers.set("X-Forwarded-Host", url.hostname);

  try {
    const proxyRes = await fetch(proxyReq);

    const res = new Response(proxyRes.body, proxyRes);

    ["connection", "transfer-encoding"].forEach((h) => res.headers.delete(h));

    return res;
  } catch (err) {
    console.error("Proxy error:", err);
    return new Response("Bad Gateway", { status: 502 });
  }
}

let proxyServer: Bun.Server<null> | null = null;

export async function reloadProxy() {
  const serverNames = await buildServerNames();
  if (Object.keys(serverNames).length === 0) return;

  const appPort = env.MOCINNO_PORT;
  const appDomain = env.APP_DOMAIN;

  const proxyFetch = async (req: Request) => {
    try {
      const host = new URL(req.url).hostname;

      if (appDomain && host === appDomain) {
        return proxyRequest(req, `127.0.0.1:${appPort}`);
      }

      const domainRow = await db.getDomainByName(host);
      if (!domainRow) return new Response("Not found", { status: 404 });

      return proxyRequest(req, domainRow.proxy);
    } catch (err) {
      if (err instanceof Error) {
        console.error("Proxy error:", err.message);
      } else {
        console.error("Proxy error:", err);
      }
      return new Response("Bad Gateway", { status: 502 });
    }
  };

  if (proxyServer) proxyServer.stop(true);

  if (!env.DISABLE_SSL) {
    proxyServer = Bun.serve({
      port: 443,
      hostname: "0.0.0.0",
      tls: [
        ...Object.entries(serverNames).map(([domain, { cert, key }]) => ({
          domain,
          cert,
          key,
        })),
      ],
      fetch: proxyFetch,
    });
  }
}
