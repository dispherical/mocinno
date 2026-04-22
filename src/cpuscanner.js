import * as db from "./db.js";

const config = require("../config.js");

const CPU_THRESHOLD = 0.9;
const CHECK_INTERVAL_MS = 60 * 60 * 1000;
const NOTIFY_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const MIN_DATA_POINTS = 40;
const lastNotified = new Map();

async function pveFetch(path, method = "GET", body = null) {
  const url = `${process.env.PVE_URL}${path}`;
  const options = {
    method,
    headers: {
      Authorization: `PVEAPIToken=${process.env.PVE_TOKEN}`,
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    tls: { rejectUnauthorized: false },
  };
  if (body) {
    const params = new URLSearchParams();
    Object.entries(body).forEach(([k, v]) => params.append(k, v));
    options.body = params;
  }
  const res = await fetch(url, options);
  if (!res.ok) {
    throw new Error(`PVE API Error: ${res.status} - ${await res.text()}`);
  }
  return res.json();
}

async function notifySlack(vmid, username, avgCpu, cores) {
  const url = process.env.SLACK_WEBHOOK_URL;
  if (!url) return;
  try {
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: `Container ${vmid} (${username}) averaging ${(avgCpu * 100).toFixed(1)}% CPU over 24h`,
        blocks: [
          {
            type: "section",
            text: { type: "mrkdwn", text: `:fire: *High sustained CPU usage*` },
          },
          {
            type: "section",
            fields: [
              { type: "mrkdwn", text: `*User*\n${username}` },
              { type: "mrkdwn", text: `*VMID*\n${vmid}` },
              {
                type: "mrkdwn",
                text: `*24h avg*\n${(avgCpu * 100).toFixed(1)}% of ${cores} core(s)`,
              },
            ],
          },
        ],
      }),
    });
  } catch (e) {
    console.error(`slack notification failed:`, e.message);
  }
}

async function checkNode(node, vmidToName, liveVmids) {
  let list;
  try {
    list = await pveFetch(`/nodes/${node}/lxc`);
  } catch (e) {
    console.error(`failed to list containers on ${node}:`, e.message);
    return;
  }

  for (const ct of list.data) {
    liveVmids.add(ct.vmid);
    if (ct.status !== "running") continue;

    try {
      const rrd = await pveFetch(
        `/nodes/${node}/lxc/${ct.vmid}/rrddata?timeframe=day&cf=AVERAGE`,
      );
      const points = rrd.data.filter((p) => typeof p.cpu === "number");
      if (points.length < MIN_DATA_POINTS) continue;

      const avg = points.reduce((s, p) => s + p.cpu, 0) / points.length;
      if (avg < CPU_THRESHOLD) continue;

      const now = Date.now();
      const last = lastNotified.get(ct.vmid);
      if (last && now - last < NOTIFY_COOLDOWN_MS) continue;
      lastNotified.set(ct.vmid, now);

      const username = vmidToName.get(ct.vmid) || ct.name || "unknown";
      const cores = ct.cpus || "?";
      console.log(
        `high cpu: vmid ${ct.vmid} (${username}) on ${node} avg ${(avg * 100).toFixed(1)}%`,
      );
      await notifySlack(ct.vmid, username, avg, cores);
    } catch (e) {
      console.error(`failed to check vmid ${ct.vmid} on ${node}:`, e.message);
    }
  }
}

async function checkAllContainers() {
  const vmidToName = new Map();
  try {
    const users = await db.getAllUsers();
    for (const u of users) {
      if (u.vmid) vmidToName.set(u.vmid, u.username);
    }
  } catch (e) {
    console.error("failed to load users:", e.message);
  }

  const nodes = Object.values(config.servers).map((s) => s.node);
  const liveVmids = new Set();

  await Promise.all(
    nodes.map((node) => checkNode(node, vmidToName, liveVmids)),
  );

  for (const vmid of lastNotified.keys()) {
    if (!liveVmids.has(vmid)) lastNotified.delete(vmid);
  }
}

console.log("cpu monitor starting");

(async function loop() {
  try {
    await checkAllContainers();
  } catch (e) {
    console.error("check run failed:", e.message);
  }
  setTimeout(loop, CHECK_INTERVAL_MS);
})();
