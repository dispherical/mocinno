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

  const reqHeaders = new Headers(req.headers);

  reqHeaders.delete("accept-encoding");

  reqHeaders.delete("connection");
  reqHeaders.delete("keep-alive");
  reqHeaders.delete("transfer-encoding");
  reqHeaders.delete("upgrade");
  reqHeaders.delete("proxy-connection");
  reqHeaders.delete("te");
  reqHeaders.delete("trailer");

  const xff = req.headers.get("x-forwarded-for");
  reqHeaders.set("x-forwarded-for", xff || "");
  reqHeaders.set("x-forwarded-proto", url.protocol.replace(":", ""));
  reqHeaders.set("x-forwarded-host", url.hostname);

  try {
    const proxyRes = await fetch(targetUrl.toString(), {
      method: req.method,
      headers: reqHeaders,
      body: req.method !== "GET" && req.method !== "HEAD" ? req.body : undefined,
      redirect: "manual",
    });

    const resHeaders = new Headers(proxyRes.headers);
    resHeaders.delete("content-encoding");
    resHeaders.delete("content-length");
    resHeaders.delete("transfer-encoding");
    resHeaders.delete("connection");
    resHeaders.delete("keep-alive");

    return new Response(proxyRes.body, {
      status: proxyRes.status,
      statusText: proxyRes.statusText,
      headers: resHeaders,
    });
  } catch (err) {
    console.error("Proxy error:", err);
    return new Response("Bad Gateway", { status: 502 });
  }
}

export type WSData = {
  backendWs: WebSocket;
  queue: (string | Buffer)[] | null;
};

export const wsHandlers: Bun.WebSocketHandler<WSData> = {
  open(ws) {
    const { backendWs } = ws.data;

    backendWs.addEventListener("message", (e) => {
      if (ws.readyState === 1) ws.send(e.data as string | Buffer);
    });
    backendWs.addEventListener("close", (e) => {
      try {
        ws.close(e.code, e.reason);
      } catch {}
    });
    backendWs.addEventListener("error", () => {
      try {
        ws.close(1011, "Backend error");
      } catch {}
    });

    if (backendWs.readyState === 1 && ws.data.queue) {
      for (const m of ws.data.queue) backendWs.send(m);
      ws.data.queue = null;
    } else if (backendWs.readyState === 0 && ws.data.queue) {
      const q = ws.data.queue;
      ws.data.queue = null;
      backendWs.addEventListener(
        "open",
        () => {
          for (const m of q) backendWs.send(m);
        },
        { once: true },
      );
    }
  },

  message(ws, message) {
    const { backendWs } = ws.data;
    if (backendWs.readyState === 1) {
      backendWs.send(message);
    } else if (backendWs.readyState === 0) {
      (ws.data.queue ??= []).push(message);
    }
  },

  close(ws, code, reason) {
    try {
      ws.data.backendWs.close(code, reason);
    } catch {}
  },
};

export function isWebSocketUpgrade(req: Request) {
  return (
    req.headers.get("upgrade")?.toLowerCase() === "websocket" &&
    (req.headers.get("connection")?.toLowerCase().includes("upgrade") ?? false)
  );
}

export function proxyWebSocket(
  req: Request,
  target: string,
  server: Bun.Server<WSData>,
): Response | undefined {
  const url = new URL(req.url);
  const wsTargetUrl = `ws://${target}${url.pathname}${url.search}`;

  const skip = new Set([
    "connection",
    "upgrade",
    "host",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-extensions",
    "sec-websocket-accept",
    "content-length",
  ]);
  const headers: Record<string, string> = {};
  for (const [k, v] of req.headers) {
    if (!skip.has(k.toLowerCase())) headers[k] = v;
  }
  headers["x-forwarded-for"] = req.headers.get("x-forwarded-for") ?? "";
  headers["x-forwarded-proto"] = url.protocol.replace(":", "");
  headers["x-forwarded-host"] = url.hostname;

  const protoHeader = req.headers.get("sec-websocket-protocol");
  const protocols = protoHeader
    ? protoHeader.split(",").map((s) => s.trim()).filter(Boolean)
    : undefined;

  let backendWs: WebSocket;
  try {
    backendWs = new WebSocket(wsTargetUrl, { headers, protocols } as any);
  } catch (err) {
    console.error("WS proxy connect error:", err);
    return new Response("Bad Gateway", { status: 502 });
  }

  const ok = server.upgrade(req, {
    data: { backendWs, queue: null },
  });
  if (!ok) {
    backendWs.close();
    return new Response("WebSocket upgrade failed", { status: 500 });
  }
  return undefined;
}

let proxyServer: Bun.Server<WSData> | null = null;

export async function reloadProxy() {
  const serverNames = await buildServerNames();
  if (Object.keys(serverNames).length === 0) return;

  const appPort = env.MOCINNO_PORT;
  const appDomain = env.APP_DOMAIN;

  const proxyFetch = async (
    req: Request,
    server: Bun.Server<WSData>,
  ): Promise<Response | undefined> => {
    try {
      const host = new URL(req.url).hostname;

      let target: string;
      if (appDomain && host === appDomain) {
        target = `127.0.0.1:${appPort}`;
      } else {
        const domainRow = await db.getDomainByName(host);
        if (!domainRow) return new Response("Not found", { status: 404 });
        target = domainRow.proxy;
      }

      if (isWebSocketUpgrade(req)) {
        return proxyWebSocket(req, target, server);
      }
      return proxyRequest(req, target);
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
    proxyServer = Bun.serve<WSData, {}>({
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
      websocket: wsHandlers,
    });
  }
}
