import { sql } from "bun";

await sql`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sub TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    ssh_key TEXT NOT NULL,
    vmid INTEGER,
    ip TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )
`;

await sql`
  CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    domain TEXT UNIQUE NOT NULL,
    proxy TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )
`;

await sql`
  CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sub TEXT NOT NULL,
    email TEXT NOT NULL,
    username TEXT NOT NULL,
    ssh_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    reviewed_by TEXT,
    reviewed_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )
`;

try { await sql`ALTER TABLE users ADD COLUMN ip TEXT`; } catch {}

await sql`PRAGMA foreign_keys = ON`;

const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);

const CONTAINER_CIDR = process.env.CONTAINER_CIDR || '10.0.0.0/24';
const CONTAINER_GATEWAY = process.env.CONTAINER_GATEWAY || '';

function parseCIDR(cidr) {
  const [base, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  const parts = base.split('.').map(Number);
  const baseInt = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  const mask = ~((1 << (32 - prefix)) - 1) >>> 0;
  const network = (baseInt & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;
  return { network, broadcast, prefix };
}

function intToIP(n) {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
}

export async function allocateIP() {
  const { network, broadcast, prefix } = parseCIDR(CONTAINER_CIDR);
  const startHost = network + 2;
  const endHost = broadcast - 1;

  const usedRows = await sql`SELECT ip FROM users WHERE ip IS NOT NULL`;
  const usedIPs = new Set(usedRows.map(r => r.ip));

  for (let i = startHost; i <= endHost; i++) {
    const candidate = intToIP(i >>> 0);
    if (!usedIPs.has(candidate)) {
      return { ip: candidate, prefix, gateway: CONTAINER_GATEWAY || intToIP(network + 1) };
    }
  }
  throw new Error('No available IPs in CIDR range');
}

export function isAdmin(email) {
  return ADMIN_EMAILS.includes(email?.toLowerCase());
}

export async function findUserBySub(sub) {
  const [user] = await sql`SELECT * FROM users WHERE sub = ${sub}`;
  return user ?? null;
}

export async function findUserByUsername(username) {
  const [user] = await sql`SELECT * FROM users WHERE username = ${username}`;
  return user ?? null;
}

export async function isUsernameTaken(username) {
  const [row] = await sql`SELECT 1 FROM users WHERE username = ${username}`;
  if (row) return true;
  const [app] = await sql`SELECT 1 FROM applications WHERE username = ${username} AND status = 'pending'`;
  return !!app;
}

export async function createUser({ sub, username, sshKey, vmid, ip }) {
  const [user] = await sql`
    INSERT INTO users (sub, username, ssh_key, vmid, ip)
    VALUES (${sub}, ${username}, ${sshKey}, ${vmid}, ${ip || null})
    RETURNING *
  `;
  return user;
}

export async function deleteUser(sub) {
  await sql`DELETE FROM users WHERE sub = ${sub}`;
}

export async function getDomainsForUser(userId) {
  return await sql`SELECT * FROM domains WHERE user_id = ${userId} ORDER BY created_at`;
}

export async function addDomain({ userId, domain, proxy }) {
  const [row] = await sql`
    INSERT INTO domains (user_id, domain, proxy)
    VALUES (${userId}, ${domain}, ${proxy})
    RETURNING *
  `;
  return row;
}

export async function removeDomain(userId, domain) {
  const [row] = await sql`
    DELETE FROM domains WHERE user_id = ${userId} AND domain = ${domain}
    RETURNING *
  `;
  return row ?? null;
}

export async function domainExists(domain) {
  const [row] = await sql`SELECT 1 FROM domains WHERE domain = ${domain}`;
  return !!row;
}

export async function domainOwnedBy(domain, userId) {
  const [row] = await sql`SELECT 1 FROM domains WHERE domain = ${domain} AND user_id = ${userId}`;
  return !!row;
}

export async function getAllDomains() {
  return await sql`
    SELECT d.domain, d.proxy, u.username
    FROM domains d
    JOIN users u ON d.user_id = u.id
    ORDER BY d.domain
  `;
}

export async function createApplication({ sub, email, username, sshKey, reason }) {
  const [app] = await sql`
    INSERT INTO applications (sub, email, username, ssh_key, reason)
    VALUES (${sub}, ${email}, ${username}, ${sshKey}, ${reason})
    RETURNING *
  `;
  return app;
}

export async function getPendingApplications() {
  return await sql`SELECT * FROM applications WHERE status = 'pending' ORDER BY created_at`;
}

export async function getAllApplications() {
  return await sql`SELECT * FROM applications ORDER BY created_at DESC`;
}

export async function getApplicationById(id) {
  const [app] = await sql`SELECT * FROM applications WHERE id = ${id}`;
  return app ?? null;
}

export async function getApplicationBySub(sub) {
  const [app] = await sql`SELECT * FROM applications WHERE sub = ${sub} ORDER BY created_at DESC LIMIT 1`;
  return app ?? null;
}

export async function updateApplicationStatus(id, status, reviewedBy) {
  const [app] = await sql`
    UPDATE applications
    SET status = ${status}, reviewed_by = ${reviewedBy}, reviewed_at = datetime('now')
    WHERE id = ${id}
    RETURNING *
  `;
  return app ?? null;
}

export async function getAllUsers() {
  return await sql`SELECT * FROM users ORDER BY created_at DESC`;
}

export async function searchUsers({ query, limit = 50, offset = 0 }) {
  if (query) {
    const like = `%${query}%`;
    const rows = await sql`SELECT * FROM users WHERE username LIKE ${like} OR ip LIKE ${like} OR CAST(vmid AS TEXT) LIKE ${like} ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`;
    const [{ total }] = await sql`SELECT COUNT(*) as total FROM users WHERE username LIKE ${like} OR ip LIKE ${like} OR CAST(vmid AS TEXT) LIKE ${like}`;
    return { users: rows, total };
  }
  const rows = await sql`SELECT * FROM users ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`;
  const [{ total }] = await sql`SELECT COUNT(*) as total FROM users`;
  return { users: rows, total };
}

export async function updateUsername(vmid, newUsername) {
  const [user] = await sql`UPDATE users SET username = ${newUsername} WHERE vmid = ${vmid} RETURNING *`;
  return user ?? null;
}

export { sql };
