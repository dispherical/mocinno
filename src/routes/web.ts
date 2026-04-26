import * as db from "../db";
import { getContainerStatus, isContainerSuspended } from "@/pve-utils";
import { route } from "@/middleware";

const app = route.createApp();

app.get("/", async (c) => {
  const html = await c.get("engine").renderFile("home");
  return c.html(html);
});

app.get("/dashboard", async (c) => {
  const session = c.get("session");
  const profile = session.get("profile");
  if (!profile) return c.redirect("/flow/authorization/login/start");

  const user = await db.findUserBySub(profile.sub);
  const admin = db.isAdmin(profile.email);
  let container = null;
  let domains: {
    id: number;
    user_id: number | null;
    domain: string;
    proxy: string;
    created_at: Date | null;
  }[] = [];
  let suspended = false;
  let application = null;
  let eligible = false;

  if (user?.vmid) {
    container = await getContainerStatus(user);
    domains = await db.getDomainsForUser(user.id);
    suspended = await isContainerSuspended(user);
  } else if (!user) {
    application = await db.getApplicationBySub(profile.sub);
    if (!application || application.status === "rejected") {
      eligible = profile.verification_status === "verified";
    }

    const inviteCode = session.get("invite_code");
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
  }

  const config = await import("config");
  const html = await c.get("engine").renderFile("dashboard", {
    profile,
    user,
    container,
    domains,
    admin,
    suspended,
    application,
    eligible,
    config: config.default,
  });

  return c.html(html);
});

export default app;
