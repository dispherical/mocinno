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

app.get("/api/tls-ask", async (c) => {
  const domain = c.req.query("domain");
  if (!domain) {
    c.status(400);
    return c.text("Missing domain");
  }

  if (domain == "dashboard.hackclub.app") return c.text("OK");

  if (domain.endsWith(".hackclub.app")) {
    const parts = domain.replace(".hackclub.app", "").split(".");
    const username = parts[parts.length - 1];

    const user = await db.findUserByUsername(username);

    if (!user) {
      c.status(404);
      return c.text("Not found");
    }

    const domainRow = await db.getDomainByName(domain);

    if (domainRow || domain === `${username}.hackclub.app`) {
      return c.text("OK");
    }

    c.status(404);
    return c.text("Not found");
  }

  const appDomain = process.env.APP_DOMAIN;
  if (appDomain && domain === appDomain) return c.text("OK");

  const domainRow = await db.getDomainByName(domain);
  if (domainRow) return c.text("OK");

  c.status(404);
  return c.text("Not found");
});

app.post("/api/proxy/reload", async (c) => {
  const profile = c.get("session").get("profile");
  if (!profile || !db.isAdmin(profile.email)) {
    c.status(403);
    return c.json({ error: "Forbidden" });
  }
  await reloadProxy();
  return c.json({ message: "Proxy reloaded" });
});

app.get("/admin", async (c) => {
  const session = c.get("session");
  const profile = session.get("profile");
  if (!profile) return c.redirect("/flow/authorization/login/start");
  if (!db.isAdmin(profile.email)) {
    c.status(403);
    return c.text("Forbidden");
  }

  const users = [];
  const applications = await db.getPendingApplications();
  const allApplications = await db.getAllApplications();
  const invites = await db.getAllInvites();

  const config = require("../config.js");
  const nodes = config.servers.map((s) => s.node);

  const stats = await Promise.all(
    nodes.map(async (node) => {
      const stats = await getNodeStats(node);
      return { name: node, stats };
    }),
  );

  const html = await engine.renderFile("admin", {
    profile,
    users,
    applications,
    allApplications,
    invites,
    stats,
    appDomain: process.env.APP_DOMAIN || c.req.header("host"),
  });

  return c.html(html);
});

app.post("/api/admin/invites/create", async (c) => {
  const profile = c.get("session").get("profile");
  if (!profile || !db.isAdmin(profile.email)) {
    c.status(403);
    return c.json({ error: "Forbidden" });
  }

  const body = await c.req.json();
  const code = crypto.randomBytes(8).toString("hex");
  const maxUses = parseInt(body.maxUses) || null;
  const expiresAt = body.expiresAt || null;

  const invite = await db.createInvite({
    code,
    adminEmail: profile.email,
    maxUses,
    expiresAt,
  });
  return c.json({ message: "Invite created", invite });
});

app.post("/api/admin/invites/delete", async (c) => {
  const profile = c.get("session").get("profile");
  if (!profile || !db.isAdmin(profile.email)) {
    c.status(403);
    return c.json({ error: "Forbidden" });
  }

  const { code } = await c.req.json();
  await db.deleteInvite(code);
  return c.json({ message: "Invite deleted" });
});

app.get("/api/admin/users", async (c) => {
  const profile = c.get("session").get("profile");
  if (!profile || !db.isAdmin(profile.email)) {
    c.status(403);
    return c.json({ error: "Forbidden" });
  }

  const query = c.req.query("q") || "";
  const page = Math.max(1, parseInt(c.req.query("page")) || 1);
  const limit = Math.min(
    100,
    Math.max(1, parseInt(c.req.query("limit")) || 50),
  );
  const offset = (page - 1) * limit;

  const { users, total } = await db.searchUsers({ query, limit, offset });

  const usersWithStatus = [];
  for (const user of users) {
    let container = null;
    let suspended = false;
    if (user.vmid) {
      container = await getContainerStatus(user);
      suspended = await isContainerSuspended(user);
    }
    usersWithStatus.push({ ...user, container, suspended });
  }

  return c.json({
    users: usersWithStatus,
    total,
    page,
    limit,
    pages: Math.ceil(total / limit),
  });
});

app.get("/api/admin/applications", async (c) => {
  const profile = c.get("session").get("profile");
  if (!profile || !db.isAdmin(profile.email)) {
    c.status(403);
    return c.json({ error: "Forbidden" });
  }

  const applications = await db.getPendingApplications();
  return c.json(applications);
});

app.post("/api/admin/applications/approve", async (c) => {
  const profile = c.get("session").get("profile");
  if (!profile || !db.isAdmin(profile.email)) {
    c.status(403);
    return c.json({ error: "Forbidden" });
  }

  const body = await c.req.json();
  const appId = body.id;
  if (!appId) {
    c.status(400);
    return c.json({ error: "Application ID required" });
  }

  const application = await db.getApplicationById(appId);

  if (!application) {
    c.status(404);
    return c.json({ error: "Application not found" });
  }

  if (application.status !== "pending") {
    c.status(400);
    return c.json({ error: "Application already processed" });
  }

  const config = require("../config.js");

  const vmid = await getNextVmid();
  const node = await getNextNode();

  const serverConfig = config.servers.find((s) => s.node === node);

  const templateConfig = Array.isArray(serverConfig.templates)
    ? serverConfig.templates.find((t) => t.name === application.template) ||
      serverConfig.templates[0]
    : serverConfig.templates;

  const password = crypto.randomBytes(12).toString("hex");
  const allocated = await db.allocateIP(
    serverConfig.ipv4.cidr,
    serverConfig.ipv4.gateway,
  );

  let net0 = `name=eth0,bridge=vmbr4030,firewall=1,ip=${allocated.ip}/${allocated.prefix},gw=${serverConfig.ipv4?.gateway || allocated.gateway}`;

  if (serverConfig.ipv6) {
    net0 += `,ip6=${serverConfig.ipv6.prefix}${vmid}/${serverConfig.ipv6.cidr},gw6=${serverConfig.ipv6.gateway}`;
  }

  console.log("net0: ", net0);
  console.log("ipv6 config: ", serverConfig.ipv6);

  const result = await pveFetch(`/nodes/${node}/lxc`, "POST", {
    vmid,
    ostemplate: templateConfig.template || process.env.OS_TEMPLATE,
    rootfs: serverConfig.rootfs || process.env.ROOTFS,
    unprivileged: 1,
    features: "nesting=1",
    cores: 2,
    memory: 2048,
    swap: 512,
    net0,
    hostname: application.username,
    "ssh-public-keys": `${bastionPubKey}\n${application.ssh_key}`,
    password,
    start: 1,
    onboot: 1,
  });

  await waitForTask(node, result.data);

  await fetch(`http://${serverConfig.hostIP}:9191/add/${vmid}`, {
    headers: { Authorization: `Bearer ${process.env.NDP_API_KEY}` },
  });

  await db.createUser({
    sub: application.sub,
    username: application.username,
    sshKeys: [application.ssh_key],
    vmid: parseInt(vmid),
    ip: allocated.ip,
    ipv6: serverConfig.ipv6 ? `${serverConfig.ipv6.prefix}${vmid}` : null,
    node,
  });

  await db.updateApplicationStatus(appId, "approved", profile.email);
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: application.email,
    subject: "Nest account approved!",
    text: `Your Nest account was approved. Congrats!

Internal IPv4: ${allocated.ip}
Public IPv6: ${serverConfig.ipv6 ? `${serverConfig.ipv6.prefix}${vmid}` : "N/A"}
Username: ${application.username}
Operating System: ${templateConfig.name || process.env.OS_TEMPLATE}

To login to Nest, you may use ssh ${application.username}@hackclub.app
By default, you have 2 GB of RAM, 2 CPU cores, and 8 GB of storage. To increase this limit, you may fill out this form: https://nest.fillout.com/resources

From the Dashboard (https://dashboard.hackclub.app/dashboard), you can manage custom domains, reboot your container, stop your container, or even delete your Nest account.
If you need help with your server you can contact the nest admin on the #nest-help channel on the Hack Club Slack!
`,
  });
  return c.json({ message: "Approved and container created", vmid, password });
});

app.post("/api/admin/applications/reject", async (c) => {
  const profile = c.get("session").get("profile");
  if (!profile || !db.isAdmin(profile.email)) {
    c.status(403);
    return c.json({ error: "Forbidden" });
  }

  const body = await c.req.json();
  const appId = body.id;
  if (!appId) {
    c.status(400);
    return c.json({ error: "Application ID required" });
  }

  const application = await db.getApplicationById(appId);
  if (!application) {
    c.status(404);
    return c.json({ error: "Application not found" });
  }
  if (application.status !== "pending") {
    c.status(400);
    return c.json({ error: "Application already processed" });
  }

  await db.updateApplicationStatus(appId, "rejected", profile.email);

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: application.email,
    subject: "Nest account rejected",
    text: `Your Nest account was rejected.

You may contact the Nest team via #nest-help to learn more.`,
  });
  return c.json({ message: "Application rejected" });
});

app.post("/api/admin/users/suspend", async (c) => {
  const profile = c.get("session").get("profile");
  if (!profile || !db.isAdmin(profile.email)) {
    c.status(403);
    return c.json({ error: "Forbidden" });
  }

  const body = await c.req.json();
  const vmid = body.vmid;
  const reason = body.reason || "Suspended by admin";
  if (!vmid) {
    c.status(400);
    return c.json({ error: "VMID required" });
  }

  const user = await db.findUserByVmid(vmid);

  if (!user) {
    c.status(404);
    return c.json({ error: "No account found" });
  }

  await setContainerDescription(user, `suspend: ${reason}`);

  try {
    const status = await getContainerStatus(user);
    if (status?.status === "running") {
      const stopResult = await pveFetch(
        `/nodes/${user.node}/lxc/${user.vmid}/status/stop`,
        "POST",
      );
      await waitForTask(user.node, stopResult.data);
    }
  } catch {}

  return c.json({ message: `Container ${vmid} suspended` });
});

app.post("/api/admin/users/unsuspend", async (c) => {
  const profile = c.get("session").get("profile");
  if (!profile || !db.isAdmin(profile.email)) {
    c.status(403);
    return c.json({ error: "Forbidden" });
  }

  const body = await c.req.json();
  const vmid = body.vmid;
  if (!vmid) {
    c.status(400);
    return c.json({ error: "VMID required" });
  }

  const user = await db.findUserByVmid(vmid);

  if (!user) {
    c.status(404);
    return c.json({ error: "No account found" });
  }

  await setContainerDescription(user, "");
  return c.json({ message: `Container ${vmid} unsuspended` });
});

app.post("/api/admin/users/update", async (c) => {
  const profile = c.get("session").get("profile");
  if (!profile || !db.isAdmin(profile.email)) {
    c.status(403);
    return c.json({ error: "Forbidden" });
  }

  const body = await c.req.json();
  const vmid = body.vmid;
  if (!vmid) {
    c.status(400);
    return c.json({ error: "VMID required" });
  }

  const user = await db.findUserByVmid(vmid);

  if (!user) {
    c.status(404);
    return c.json({ error: "No account found" });
  }

  const updates = {};

  if (body.cores !== undefined) {
    const cores = parseInt(body.cores);

    if (isNaN(cores) || cores < 1 || cores > 16) {
      c.status(400);
      return c.json({ error: "Cores must be 1-16" });
    }

    updates.cores = cores;
  }

  if (body.memory !== undefined) {
    const memory = parseInt(body.memory);

    if (isNaN(memory) || memory < 128 || memory > 32768) {
      c.status(400);
      return c.json({ error: "Memory must be 128-32768 MB" });
    }

    updates.memory = memory;
  }

  if (body.username !== undefined) {
    const username = body.username.toLowerCase();

    if (!/^[a-z][a-z0-9_-]{1,30}[a-z0-9]$/.test(username)) {
      c.status(400);
      return c.json({ error: "Invalid username" });
    }

    const taken = await db.isUsernameTaken(username);
    if (taken) {
      c.status(409);
      return c.json({ error: "Username already taken" });
    }

    await db.updateUsername(vmid, username);
    updates.hostname = username;
  }

  if (Object.keys(updates).length > 0) {
    await pveFetch(
      `/nodes/${user.node}/lxc/${user.vmid}/config`,
      "PUT",
      updates,
    );
  }

  return c.json({ message: "Updated" });
});

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
