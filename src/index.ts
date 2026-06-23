import { CookieStore, sessionMiddleware } from "hono-sessions";
import * as env from "./env";
import { serveStatic } from "hono/bun";
import { route } from "./middleware";
import "@/proxy/index.ts";
import { Liquid } from "liquidjs";

import internalRoutes from "@/routes/internal";
import webRoutes from "@/routes/web";
import userRoutes from "@/routes/user";
import authRoutes from "@/routes/auth";
import applicationRoutes from "@/routes/application";
import adminRoutes from "@/routes/admin";
import publicRoutes from "@/routes/public";

const app = route.createApp();

app.get("/privacy.pdf", serveStatic({ path: "./src/public/privacy.pdf" }));

const store = new CookieStore();

app.use(
  "*",
  sessionMiddleware({
    store,
    encryptionKey: env.ENCRYPTION_KEY,
    expireAfterSeconds: 900,
    autoExtendExpiration: true,
    cookieOptions: {
      sameSite: "Lax",
      path: "/",
      httpOnly: true,
    },
  }),
);

const engine = new Liquid({
  root: "./views",
  extname: ".liquid",
  outputEscape: "escape",
  cache: process.env.NODE_ENV == "production",
});

app.use("*", async (c, next) => {
  c.set("engine", engine);
  const session = c.get("session");

  // allowing sudo mode in development without 2fa
  if (process.env.NODE_ENV !== "production") session.flash("sudo", true);
  await next();
});

app.route("", internalRoutes);

app.route("", webRoutes);
app.route("", userRoutes);
app.route("", authRoutes);
app.route("", applicationRoutes);
app.route("", adminRoutes);
app.route("", publicRoutes);

const serve = Bun.serve({
  fetch: app.fetch,
  port: env.MOCINNO_PORT,
  maxRequestBodySize: env.MOCINNO_MAX_BODY_REQUEST_SIZE,
  hostname: env.MOCINNO_HOSTNAME,
});

console.log("Mocinno is running on port %s (%s)", serve.port, serve.hostname);

process.on("uncaughtException", (error) => {
  console.error(error);
});

process.on("unhandledRejection", (error) => {
  console.error(error);
});
