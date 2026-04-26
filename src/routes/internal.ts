import { denyForward, localOnly, route } from "@/middleware";
import {
  getContainerIP,
  getContainerStatus,
  isContainerSuspended,
  pveFetch,
  waitForTask,
} from "@/pve-utils";
import * as db from "@/db";
import * as env from "@/env";
import type { NodeLXCStatusStart } from "@/types/pve";

const app = route.createApp();

app.post("/pubkey", localOnly, denyForward, async (c) => {
  const body = await c.req.json();
  const username = body.username;
  const publicKey = body.publicKey;

  if (!username || !publicKey) return c.json({ success: false });

  const user = await db.findUserByUsername(username);
  if (!user || !user.ssh_keys || user.ssh_keys.length === 0) {
    return c.json({ success: false });
  }

  const clientKeyParts = publicKey.trim().split(" ");
  const clientKeyData =
    clientKeyParts.length >= 2 ? clientKeyParts[1] : publicKey;

  const matched = user.ssh_keys.some((k) => {
    const parts = k.trim().split(" ");
    const data = parts.length >= 2 ? parts[1] : k;
    return data === clientKeyData;
  });

  if (matched) {
    return c.json({ success: true });
  }

  return c.json({ success: false });
});

app.post("/config", localOnly, denyForward, async (c) => {
  const body = await c.req.json();
  const username = body.username;

  if (!username) return c.json({ config: {} });

  const user = await db.findUserByUsername(username);
  if (!user || !user.vmid) return c.json({ config: {} });

  const suspended = await isContainerSuspended(user);
  if (suspended) {
    return c.json({ config: {} });
  }

  let ip = await getContainerIP(user, user.ip);
  const statusRes = await getContainerStatus(user);
  const status = statusRes?.status;

  if (status !== "running") {
    try {
      const result = await pveFetch<{ data: NodeLXCStatusStart }>(
        `/nodes/${user.node}/lxc/${user.vmid}/status/start`,
        "POST",
      );

      await waitForTask(user.node, result.data);
      await new Promise((r) => setTimeout(r, 3000));

      ip = await getContainerIP(user, null);
    } catch {
      return c.json({ config: {} });
    }
  }

  if (!ip) return c.json({ config: {} });

  return c.json({
    config: {
      backend: "sshproxy",
      sshproxy: {
        server: ip,
        port: 22,
        usernamePassThrough: false,
        username: "root",
        privateKey: env.BASTION_PRIV_KEY,
      },
    },
  });
});

// wtf is this route used for
app.post("/password", localOnly, denyForward, async (c) => {
  return c.json({ success: false });
});

export default app;
