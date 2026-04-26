import { resolve } from "dns/promises";

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
