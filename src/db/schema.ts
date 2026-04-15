import { integer, pgTable, text, serial, timestamp } from "drizzle-orm/pg-core";

export const usersTable = pgTable("users", {
  id: serial("id").primaryKey(),
  sub: text("sub").unique().notNull(),
  username: text("username").unique().notNull(),
  ssh_keys: text("ssh_keys").array().notNull(),
  vmid: integer("vmid"),
  ip: text("ip"),
  ipv6: text("ipv6"),
  created_at: timestamp("created_at").defaultNow(),
});

export const domainsTable = pgTable("domains", {
  id: serial("id").primaryKey(),
  user_id: integer("user_id").references(() => usersTable.id, {
    onDelete: "cascade",
  }),
  domain: text("domain").unique().notNull(),
  proxy: text("proxy").notNull(),
  created_at: timestamp("created_at").defaultNow(),
});

export const applicationsTable = pgTable("applications", {
  id: serial("id").primaryKey(),
  sub: text("sub").notNull(),
  email: text("email").notNull(),
  username: text("username").notNull(),
  ssh_key: text("ssh_key").notNull(),
  reason: text("reason").notNull(),
  server: text("server").notNull().default("nest-prov-1"),
  template: text("template").notNull().default("Debian 13"),

  status: text("status").notNull().default("pending"),
  reviewed_by: text("reviewed_by"),
  reviewed_at: timestamp("reviewed_at"),
  created_at: timestamp("created_at").defaultNow(),
});

export const certificatesTable = pgTable("certificates", {
  id: serial("id").primaryKey(),
  domain: text("domain").unique().notNull(),
  cert: text("cert").notNull(),
  key: text("key").notNull(),
  expires_at: timestamp("expires_at").notNull(),
  created_at: timestamp("created_at").defaultNow(),
});

export const invitesTable = pgTable("invites", {
  code: text("code").primaryKey(),
  admin_email: text("admin_email").notNull(),
  max_uses: integer("max_uses"),
  uses: integer("uses").notNull().default(0),
  expires_at: timestamp("expires_at"),
  created_at: timestamp("created_at").defaultNow(),
});

export const settingsTable = pgTable("settings", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
});
