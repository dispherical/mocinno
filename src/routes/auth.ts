import { exchangeCodeForProfile } from "@/hca";
import { generateState } from "@/utils";
import * as db from "@/db";
import * as env from "@/env";
import { route } from "@/middleware";

const app = route.createApp();

app.get("/flow/authorization/:mode/start", async (c) => {
  const mode = c.req.param("mode");
  const session = c.get("session");

  const state = generateState();
  session.set("oauth_state", { state, mode });

  const params = new URLSearchParams({
    client_id: env.OAUTH_CLIENT_ID,
    redirect_uri: env.OAUTH_CLIENT_REDIRECT_URI,
    response_type: "code",
    scope: "openid profile email verification_status slack_id",
    state: state,
  });

  if (mode === "sudo") params.append("prompt", "login");

  return c.redirect(
    `https://auth.hackclub.com/oauth/authorize?${params.toString()}`,
  );
});

app.get("/flow/authorization/goalpost", async (c) => {
  const session = c.get("session");
  const code = c.req.query("code");
  const state = c.req.query("state");
  const stored = session.get("oauth_state");

  if (!code || !stored || state !== stored.state)
    return c.redirect("/flow/authorization/login/start");

  const profile = await exchangeCodeForProfile(
    code,
    env.OAUTH_CLIENT_REDIRECT_URI,
  );

  if (!profile) return c.redirect("/flow/authorization/login/start");
  if (env.NODE_ENV != "production") profile.verification_status = "verified";
  session.set("profile", profile);

  // this allows one destructive action per 2fa login
  if (stored.mode === "sudo") session.flash("sudo", true);

  return c.redirect("/dashboard");
});

app.get("/invite/:code", async (c) => {
  const code = c.req.param("code");
  const invite = await db.getInvite(code);
  if (!invite) return c.text("Invalid invite code", 404);
  if (invite.max_uses && invite.uses >= invite.max_uses)
    return c.text("Invite code depleted", 403);
  if (invite.expires_at && new Date() > invite.expires_at)
    return c.text("Invite code expired", 403);

  c.get("session").set("invite_code", code);
  return c.redirect("/flow/authorization/login/start");
});

export default app;
