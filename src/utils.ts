import { resolve } from "node:dns/promises";
import * as crypto from "node:crypto";

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
