import {
  eq,
  like,
  or,
  and,
  asc,
  desc,
  lte,
  count,
  isNotNull,
  sql,
} from "drizzle-orm";
import { db } from "./db/index.ts";
import {
  usersTable,
  domainsTable,
  applicationsTable,
  certificatesTable,
  settingsTable,
  invitesTable,
} from "./db/schema.ts";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((e) => e.trim().toLowerCase())
  .filter(Boolean);

const RESERVED_IPS = new Set(["10.60.0.1", "10.60.0.2", "10.60.0.3"]);

function parseCIDR(cidr) {
  const [base, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr, 10);
  const parts = base.split(".").map(Number);
  const baseInt =
    (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  const mask = ~((1 << (32 - prefix)) - 1) >>> 0;
  const network = (baseInt & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;
  return { network, broadcast, prefix };
}

function intToIP(n) {
  return [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ].join(".");
}

export async function allocateIP(cidr, gateway) {
  const { network, broadcast, prefix } = parseCIDR(cidr);
  const startHost = network + 2;
  const endHost = broadcast - 1;

  const usedRows = await db
    .select({ ip: usersTable.ip })
    .from(usersTable)
    .where(isNotNull(usersTable.ip));
  const usedIPs = new Set(usedRows.map((r) => r.ip));

  for (let i = startHost; i <= endHost; i++) {
    const candidate = intToIP(i >>> 0);
    if (RESERVED_IPS.has(candidate)) continue;

    if (!usedIPs.has(candidate)) {
      try {
        await execAsync(`ping -c 1 -W 1 ${candidate}`);
      } catch (error) {
        return {
          ip: candidate,
          prefix,
          gateway: gateway || intToIP(network + 1),
        };
      }
    }
  }
  throw new Error("No available IPs in CIDR range");
}

export function isAdmin(email) {
  return ADMIN_EMAILS.includes(email?.toLowerCase());
}

export async function findUserBySub(sub) {
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.sub, sub));
  return user ?? null;
}

export async function findUserByUsername(username) {
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.username, username));
  return user ?? null;
}

export async function isUsernameTaken(username) {
  const [user] = await db
    .select({ id: usersTable.id })
    .from(usersTable)
    .where(eq(usersTable.username, username));
  if (user) return true;
  const [app] = await db
    .select({ id: applicationsTable.id })
    .from(applicationsTable)
    .where(
      and(
        eq(applicationsTable.username, username),
        eq(applicationsTable.status, "pending"),
      ),
    );
  return !!app;
}

export async function createUser({ sub, username, sshKeys, vmid, ip, ipv6 }) {
  const [user] = await db
    .insert(usersTable)
    .values({
      sub,
      username,
      ssh_keys: sshKeys,
      vmid,
      ip: ip || null,
      ipv6: ipv6 || null,
    })
    .returning();
  return user;
}

export async function updateUserSSHKeys(sub, keys) {
  const [user] = await db
    .update(usersTable)
    .set({ ssh_keys: keys })
    .where(eq(usersTable.sub, sub))
    .returning();
  return user ?? null;
}

export async function deleteUser(sub) {
  await db.delete(applicationsTable).where(eq(applicationsTable.sub, sub));
  await db.delete(usersTable).where(eq(usersTable.sub, sub));
}

export async function getDomainsForUser(userId) {
  return db
    .select()
    .from(domainsTable)
    .where(eq(domainsTable.user_id, userId))
    .orderBy(asc(domainsTable.created_at));
}

export async function addDomain({ userId, domain, proxy }) {
  const [row] = await db
    .insert(domainsTable)
    .values({ user_id: userId, domain, proxy })
    .returning();
  return row;
}

export async function removeDomain(userId, domain) {
  const [row] = await db
    .delete(domainsTable)
    .where(
      and(eq(domainsTable.user_id, userId), eq(domainsTable.domain, domain)),
    )
    .returning();
  return row ?? null;
}

export async function domainExists(domain) {
  const [row] = await db
    .select({ id: domainsTable.id })
    .from(domainsTable)
    .where(eq(domainsTable.domain, domain));
  return !!row;
}

export async function domainOwnedBy(domain, userId) {
  const [row] = await db
    .select({ id: domainsTable.id })
    .from(domainsTable)
    .where(
      and(eq(domainsTable.domain, domain), eq(domainsTable.user_id, userId)),
    );
  return !!row;
}

export async function getAllDomains() {
  return db
    .select({
      domain: domainsTable.domain,
      proxy: domainsTable.proxy,
      username: usersTable.username,
    })
    .from(domainsTable)
    .innerJoin(usersTable, eq(domainsTable.user_id, usersTable.id))
    .orderBy(asc(domainsTable.domain));
}

export async function createApplication({
  sub,
  email,
  username,
  sshKey,
  reason,
  template,
}) {
  const [app] = await db
    .insert(applicationsTable)
    .values({ sub, email, username, ssh_key: sshKey, reason, template })
    .returning();
  return app;
}

export async function getPendingApplications() {
  return db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.status, "pending"))
    .orderBy(asc(applicationsTable.created_at));
}

export async function getAllApplications() {
  return db
    .select()
    .from(applicationsTable)
    .orderBy(desc(applicationsTable.created_at));
}

export async function getApplicationById(id) {
  const [app] = await db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.id, id));
  return app ?? null;
}

export async function getApplicationBySub(sub) {
  const [app] = await db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.sub, sub))
    .orderBy(desc(applicationsTable.created_at))
    .limit(1);
  return app ?? null;
}

export async function updateApplicationStatus(id, status, reviewedBy) {
  const [app] = await db
    .update(applicationsTable)
    .set({ status, reviewed_by: reviewedBy, reviewed_at: new Date() })
    .where(eq(applicationsTable.id, id))
    .returning();
  return app ?? null;
}

export async function getAllUsers() {
  return db.select().from(usersTable).orderBy(desc(usersTable.created_at));
}

export async function searchUsers({ query, limit = 50, offset = 0 }) {
  if (query) {
    const likePattern = `%${query}%`;
    const whereClause = or(
      like(usersTable.username, likePattern),
      like(usersTable.ip, likePattern),
      like(sql`CAST(${usersTable.vmid} AS TEXT)`, likePattern),
    );
    const rows = await db
      .select()
      .from(usersTable)
      .where(whereClause)
      .orderBy(desc(usersTable.created_at))
      .limit(limit)
      .offset(offset);
    const [{ total }] = await db
      .select({ total: count() })
      .from(usersTable)
      .where(whereClause);
    return { users: rows, total: Number(total) };
  }
  const rows = await db
    .select()
    .from(usersTable)
    .orderBy(desc(usersTable.created_at))
    .limit(limit)
    .offset(offset);
  const [{ total }] = await db.select({ total: count() }).from(usersTable);
  return { users: rows, total: Number(total) };
}

export async function updateUsername(vmid, newUsername) {
  const [user] = await db
    .update(usersTable)
    .set({ username: newUsername })
    .where(eq(usersTable.vmid, vmid))
    .returning();
  return user ?? null;
}

export async function getDomainByName(domain) {
  const [row] = await db
    .select()
    .from(domainsTable)
    .where(eq(domainsTable.domain, domain));
  return row ?? null;
}

export async function getSetting(key) {
  const [row] = await db
    .select({ value: settingsTable.value })
    .from(settingsTable)
    .where(eq(settingsTable.key, key));
  return row?.value ?? null;
}

export async function setSetting(key, value) {
  await db
    .insert(settingsTable)
    .values({ key, value })
    .onConflictDoUpdate({ target: settingsTable.key, set: { value } });
}

export async function saveCertificate({ domain, cert, key, expiresAt }) {
  const [row] = await db
    .insert(certificatesTable)
    .values({ domain, cert, key, expires_at: new Date(expiresAt) })
    .onConflictDoUpdate({
      target: certificatesTable.domain,
      set: {
        cert,
        key,
        expires_at: new Date(expiresAt),
        created_at: new Date(),
      },
    })
    .returning();
  return row;
}

export async function getCertificate(domain) {
  const [row] = await db
    .select()
    .from(certificatesTable)
    .where(eq(certificatesTable.domain, domain));
  return row ?? null;
}

export async function deleteCertificate(domain) {
  await db
    .delete(certificatesTable)
    .where(eq(certificatesTable.domain, domain));
}

export async function getAllCertificates() {
  return db
    .select()
    .from(certificatesTable)
    .orderBy(asc(certificatesTable.domain));
}

export async function getExpiringCertificates(withinDays = 30) {
  const cutoff = new Date(Date.now() + withinDays * 24 * 60 * 60 * 1000);
  return db
    .select()
    .from(certificatesTable)
    .where(lte(certificatesTable.expires_at, cutoff))
    .orderBy(asc(certificatesTable.expires_at));
}

export async function createInvite({ code, adminEmail, maxUses, expiresAt }) {
  const [invite] = await db
    .insert(invitesTable)
    .values({
      code,
      admin_email: adminEmail,
      max_uses: maxUses || null,
      expires_at: expiresAt ? new Date(expiresAt) : null,
    })
    .returning();
  return invite;
}

export async function getInvite(code) {
  const [invite] = await db
    .select()
    .from(invitesTable)
    .where(eq(invitesTable.code, code));
  return invite ?? null;
}

export async function incrementInvite(code) {
  await db
    .update(invitesTable)
    .set({ uses: sql`${invitesTable.uses} + 1` })
    .where(eq(invitesTable.code, code));
}

export async function getAllInvites() {
  return db.select().from(invitesTable).orderBy(desc(invitesTable.created_at));
}

export async function deleteInvite(code) {
  await db.delete(invitesTable).where(eq(invitesTable.code, code));
}

export { sql };
