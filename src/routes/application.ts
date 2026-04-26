import { Hono } from "hono";
import { type Session } from "hono-sessions";
import * as db from "@/db";
import { utils } from "ssh2";

const app = new Hono<{
  Variables: {
    session: Session;
  };
}>();

app.get("/api/username/check", async (c) => {
  const username = c.req.query("username")?.toLowerCase();
  if (!username || !/^[a-z][a-z0-9_-]{1,30}[a-z0-9]$/.test(username)) {
    return c.json({
      available: false,
      error:
        "Invalid username. 3-32 chars, lowercase alphanumeric, hyphens, underscores. Must start with a letter and end with a letter or number.",
    });
  }
  if (require("../reservedUsernames.js").includes(username.toLowerCase())) {
    return c.json({ available: false, error: "This username is reserved." });
  }

  const taken = await db.isUsernameTaken(username);
  return c.json({ available: !taken });
});

app.post("/api/application/submit", async (c) => {
  const profile = c.get("session").get("profile");

  if (!profile) {
    c.status(401);
    return c.json({ error: "Unauthorized" });
  }

  const existing = await db.findUserBySub(profile.sub);
  if (existing) {
    c.status(400);
    return c.json({ error: "You already have an account" });
  }

  const pendingApp = await db.getApplicationBySub(profile.sub);
  if (pendingApp?.status === "pending") {
    c.status(400);
    return c.json({ error: "You already have a pending application" });
  }

  let eligible = profile.verification_status === "verified";
  const inviteCode = c.get("session").get("invite_code");
  if (inviteCode && !eligible) {
    const invite = await db.getInvite(inviteCode);
    if (
      invite &&
      (!invite.max_uses || invite.uses < invite.max_uses) &&
      (!invite.expires_at || new Date() <= new Date(invite.expires_at))
    ) {
      eligible = true;
    }
  }

  if (!eligible) {
    c.status(403);
    return c.json({
      error:
        "You are not eligible. You must be verified on auth.hackclub.com or have a valid invite code.",
    });
  }

  const body = await c.req.json();
  const username = body.username?.toLowerCase();
  const sshKey = body.sshKey?.trim();
  const reason = body.reason?.trim();
  const template = body.template;

  if (!username || !/^[a-z][a-z0-9_-]{1,30}[a-z0-9]$/.test(username)) {
    c.status(400);
    return c.json({
      error:
        "Invalid username. 3-32 chars, lowercase alphanumeric, hyphens, underscores. Must start with a letter and end with a letter or number.",
    });
  }
  if (require("../reservedUsernames.js").includes(username.toLowerCase())) {
    return c.json({ error: "This username is reserved." });
  }

  try {
    let parsed = utils.parseKey(sshKey);

    if (parsed instanceof Error) {
      c.status(400);
      return c.json({ error: "Invalid SSH public key format." });
    }
  } catch (e) {
    if (e instanceof Error) {
      console.error("SSH key parsing error:", e.message);
    } else {
      console.error("Unexpected error during SSH key parsing:", e);
    }
    c.status(400);
    return c.json({
      error: "Invalid SSH public key format.",
    });
  }

  if (!reason || reason.length < 10) {
    c.status(400);
    return c.json({
      error: "Please provide a reason (at least 10 characters).",
    });
  }

  const taken = await db.isUsernameTaken(username);
  if (taken) {
    c.status(409);
    return c.json({ error: "Username is already taken" });
  }

  const app = await db.createApplication({
    sub: profile.sub,
    email: profile.email,
    username,
    sshKey,
    reason,
    template,
  });

  if (inviteCode && profile.verification_status !== "verified") {
    await db.incrementInvite(inviteCode);
    c.get("session").set("invite_code", null);
  }

  return c.json({ message: "Application submitted", application: app });
});

export default app;
