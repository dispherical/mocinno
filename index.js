import { Hono } from 'hono'
import { sessionMiddleware, CookieStore } from 'hono-sessions'
import { Liquid } from 'liquidjs'
import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:dns/promises'
import * as db from './db.js'
import { getChallengeResponse, issueCertificate, renewExpiringCertificates, getOrIssueCertificate, isPublicDomain } from './cert.js'
import nodemailer from 'nodemailer';

const bastionPubKey = readFileSync(process.env.BASTION_PROXY_KEY_PUB || './bastion_proxy_key.pub', 'utf-8').trim();

function generateState(length = 16) {
  return crypto.randomBytes(length)
    .toString('base64')
    .replace(/[^a-zA-Z0-9]/g, '')
    .slice(0, length);
}

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  }
});

async function getContainerConfig(vmid) {
  const node = process.env.PVE_NODE;
  try {
    const config = await pveFetch(`/nodes/${node}/lxc/${vmid}/config`);
    return config.data;
  } catch {
    return null;
  }
}

async function isContainerSuspended(vmid) {
  const config = await getContainerConfig(vmid);
  return config?.description?.toLowerCase().includes('suspend') ?? false;
}

async function setContainerDescription(vmid, description) {
  const node = process.env.PVE_NODE;
  await pveFetch(`/nodes/${node}/lxc/${vmid}/config`, 'PUT', { description });
}

const app = new Hono()

const store = new CookieStore()
app.use('*', sessionMiddleware({
  store,
  encryptionKey: process.env.ENCRYPTION_KEY,
  expireAfterSeconds: 900,
  autoExtendExpiration: true,
  cookieOptions: {
    sameSite: 'Lax',
    path: '/',
    httpOnly: true,
  },
}))

async function pveFetch(path, method = 'GET', body = null) {
  const url = `${process.env.PVE_URL}${path}`;
  const options = {
    method,
    headers: {
      'Authorization': `PVEAPIToken=${process.env.PVE_TOKEN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json'
    },
    tls: {
      rejectUnauthorized: false,
    },
  };

  if (body) {
    const params = new URLSearchParams();
    Object.entries(body).forEach(([k, v]) => params.append(k, v));
    options.body = params;
  }

  const res = await fetch(url, options);
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`PVE API Error: ${res.status} - ${err}`);
  }
  return res.json();
}

function isFQDN(domain) {
  return /^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/.test(domain);
}

function isWhitelisted(domain, username) {
  return domain === `${username}.hackclub.app` || domain.endsWith(`.${username}.hackclub.app`) || domain.endsWith(`.${username}.localhost`) || domain.endsWith(`${username}.localhost`);
}

async function checkDNSVerification(domain, username) {
  try {
    const records = await resolve(domain, 'TXT');
    for (const record of records) {
      const txt = record.join('');
      if (txt === `domain-verification=${username}`) return true;
    }
  } catch { }

  try {
    const cnames = await resolve(domain, 'CNAME');
    for (const cname of cnames) {
      if (cname === `${username}.hackclub.app` || cname === `${username}.hackclub.app.`) return true;
    }
  } catch { }

  return false;
}

async function getContainerIP(vmid, userIp) {
  if (userIp) return userIp;
  const node = process.env.PVE_NODE;
  try {
    const ifaces = await pveFetch(`/nodes/${node}/lxc/${vmid}/interfaces`);
    const eth0 = ifaces.data?.find(i => i.name === 'eth0');
    return eth0?.['inet']?.split('/')[0] ?? null;
  } catch {
    return null;
  }
}

async function getContainerStatus(vmid) {
  const node = process.env.PVE_NODE;
  try {
    const status = await pveFetch(`/nodes/${node}/lxc/${vmid}/status/current`);
    return status.data;
  } catch {
    return null;
  }
}

async function getNextVmid() {
  const clusterNext = await pveFetch(`/cluster/nextid`);
  return clusterNext.data;
}

async function waitForTask(node, upid, timeoutMs = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const status = await pveFetch(`/nodes/${node}/tasks/${encodeURIComponent(upid)}/status`);
    if (status.data.status === 'stopped') {
      if (status.data.exitstatus !== 'OK') {
        throw new Error(`Task failed: ${status.data.exitstatus}`);
      }
      return status.data;
    }
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error('Task timed out');
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  
  return parts.join(' ') || '0m';
}

async function getNodeStats() {
  const node = process.env.PVE_NODE;

  try {
    const [status, containers, rootfs] = await Promise.all([
      pveFetch(`/nodes/${node}/status`),
      pveFetch(`/nodes/${node}/lxc`),
      pveFetch(`/nodes/${node}/storage/${process.env.ROOTFS.split(':')[0]}/status`)
    ]);
    
    return {
      cpu_percent: (status.data.cpu * 100).toFixed(2),
      ram_used_gb: (status.data.memory.used / 1024 ** 3).toFixed(2),
      ram_total_gb: (status.data.memory.total / 1024 ** 3).toFixed(2),
      ram_percent: ((status.data.memory.used / status.data.memory.total) * 100).toFixed(2),
      rootfs_used_gb: (rootfs.data.used / 1024 ** 3).toFixed(2),
      rootfs_total_gb: (rootfs.data.total / 1024 ** 3).toFixed(2),
      rootfs_percent: ((rootfs.data.used / rootfs.data.total) * 100).toFixed(2),
      container_count: containers.data.length,
      load_avg: status.data.loadavg.join(' / '),
      core_count: status.data.cpuinfo.cpus,
      uptime: formatUptime(status.data.uptime),
    }
  } catch (err) {
    console.error('Failed to fetch node stats:', err.message);
  } 
}

const engine = new Liquid({
  root: './views',
  extname: '.liquid',
  outputEscape: "escape",
  cache: process.env.NODE_ENV == "production",
})




app.post('/password', async (c) => {
  return c.json({ success: false });
});

app.post('/pubkey', async (c) => {
  const body = await c.req.json();
  const username = body.username;
  const publicKey = body.publicKey;

  if (!username || !publicKey) return c.json({ success: false });

  const user = await db.findUserByUsername(username);
  if (!user || !user.ssh_keys || user.ssh_keys.length === 0) {
    return c.json({ success: false });
  }

  const clientKeyParts = publicKey.trim().split(' ');
  const clientKeyData = clientKeyParts.length >= 2 ? clientKeyParts[1] : publicKey;

  const matched = user.ssh_keys.some(k => {
    const parts = k.trim().split(' ');
    const data = parts.length >= 2 ? parts[1] : k;
    return data === clientKeyData;
  });

  if (matched) {
    return c.json({ success: true, authenticatedUsername: username });
  }

  return c.json({ success: false });
});

app.post('/config', async (c) => {
  const body = await c.req.json();
  const username = body.username;

  if (!username) return c.json({ config: {} });

  const user = await db.findUserByUsername(username);
  if (!user || !user.vmid) return c.json({ config: {} });

  const suspended = await isContainerSuspended(user.vmid);
  if (suspended) {
    return c.json({ config: {} });
  }

  let ip = await getContainerIP(user.vmid, user.ip);
  const statusRes = await getContainerStatus(user.vmid);
  const status = statusRes?.status;

  if (status !== 'running') {
    try {
      const node = process.env.PVE_NODE;
      const result = await pveFetch(`/nodes/${node}/lxc/${user.vmid}/status/start`, 'POST');
      await waitForTask(node, result.data);
      await new Promise(r => setTimeout(r, 3000));
      ip = await getContainerIP(user.vmid, null);
    } catch {
      return c.json({ config: {} });
    }
  }

  if (!ip) return c.json({ config: {} });

  const bastionPrivateKey = readFileSync(process.env.BASTION_PROXY_KEY || './bastion_proxy_key', 'utf-8');

  return c.json({
    config: {
      backend: "sshproxy",
      sshproxy: {
        server: ip,
        port: 22,
        usernamePassThrough: false,
        username: "root",
        privateKey: bastionPrivateKey,
        strictHostKeyChecking: false
      }
    }
  });
});

app.use('*', async (c, next) => {
  c.set('engine', engine)
  const session = c.get('session');

  // allowing sudo mode in development without 2fa
  if (process.env.NODE_ENV !== "production") session.flash("sudo", true);
  await next()
})

app.get('/', async (c) => {
  const html = await engine.renderFile('home')
  return c.html(html)
})

app.get('/dashboard', async (c) => {
  const session = c.get('session');
  const profile = session.get("profile");
  if (!profile) return c.redirect("/flow/authorization/login/start");

  const user = await db.findUserBySub(profile.sub);
  const admin = db.isAdmin(profile.email);
  let container = null;
  let domains = [];
  let suspended = false;
  let application = null;
  let eligible = false;

  if (user?.vmid) {
    container = await getContainerStatus(user.vmid);
    domains = await db.getDomainsForUser(user.id);
    suspended = await isContainerSuspended(user.vmid);
  } else if (!user) {
    application = await db.getApplicationBySub(profile.sub);
    if (!application || application.status === 'rejected') {
      eligible = profile.verification_status === "verified"
    }

    const inviteCode = session.get('invite_code');
    if (inviteCode && !eligible) {
      const invite = await db.getInvite(inviteCode);
      if (invite && (!invite.max_uses || invite.uses < invite.max_uses) && (!invite.expires_at || new Date() <= new Date(invite.expires_at))) {
        eligible = true;
      }
    }
  }

  const config = require('./config.js');
  const html = await engine.renderFile('dashboard', { profile, user, container, domains, admin, suspended, application, eligible, config });

  return c.html(html);
});

async function exchangeCodeForProfile(code, redirectUri) {
  const tokenResponse = await fetch("https://auth.hackclub.com/oauth/token", {
    headers: {
      "User-Agent": "Nest/1.0 (+https://hackclub.app)",
      'Content-Type': 'application/json'
    },
    method: "POST",
    body: JSON.stringify({
      client_id: process.env.OAUTH_CLIENT_ID,
      client_secret: process.env.OAUTH_CLIENT_SECRET,
      redirect_uri: redirectUri,
      code,
      grant_type: "authorization_code"
    })
  });

  if (!tokenResponse.ok) return null;
  const { access_token } = await tokenResponse.json();
  if (!access_token) return null;

  const profileResponse = await fetch("https://auth.hackclub.com/oauth/userinfo", {
    headers: {
      "User-Agent": "Nest/1.0 (+https://hackclub.app)",
      'Authorization': `Bearer ${access_token}`
    }
  });

  return profileResponse.ok ? await profileResponse.json() : null;
}

app.get('/flow/authorization/:mode/start', async (c) => {
  const mode = c.req.param('mode');
  const session = c.get('session');

  const state = generateState();
  session.set('oauth_state', { state, mode });

  const params = new URLSearchParams({
    client_id: process.env.OAUTH_CLIENT_ID,
    redirect_uri: process.env.OAUTH_CLIENT_REDIRECT_URI,
    response_type: "code",
    scope: "openid profile email verification_status",
    state: state
  });

  if (mode === 'sudo') params.append("prompt", "login");

  return c.redirect(`https://auth.hackclub.com/oauth/authorize?${params.toString()}`);
});

app.get('/flow/authorization/goalpost', async (c) => {
  const session = c.get('session');
  const code = c.req.query("code");
  const state = c.req.query("state");
  const stored = session.get('oauth_state');

  if (!code || !stored || state !== stored.state) return c.redirect("/flow/authorization/login/start");

  const profile = await exchangeCodeForProfile(code, process.env.OAUTH_CLIENT_REDIRECT_URI);

  if (!profile) return c.redirect("/flow/authorization/login/start");
  if (process.env.NODE_ENV != "production") profile.verification_status = "verified"
  session.set("profile", profile);

  // this allows one destructive action per 2fa login
  if (stored.mode === 'sudo') session.flash("sudo", true);

  return c.redirect("/dashboard")
});
app.get('/invite/:code', async (c) => {
  const code = c.req.param('code');
  const invite = await db.getInvite(code);
  if (!invite) return c.text('Invalid invite code', 404);
  if (invite.max_uses && invite.uses >= invite.max_uses) return c.text('Invite code depleted', 403);
  if (invite.expires_at && new Date() > new Date(invite.expires_at)) return c.text('Invite code expired', 403);

  c.get('session').set('invite_code', code);
  return c.redirect('/flow/authorization/login/start');
});

app.get('/api/username/check', async (c) => {
  const username = c.req.query('username')?.toLowerCase();
  if (!username || !/^[a-z][a-z0-9_-]{1,30}[a-z0-9]$/.test(username)) {
    return c.json({ available: false, error: 'Invalid username. 3-32 chars, lowercase alphanumeric, hyphens, underscores. Must start with a letter and end with a letter or number.' });
  }
  if (require("./reservedUsernames").includes(username.toLowerCase())) {
    return c.json({ available: false, error: 'This username is reserved.' });
  }

  const taken = await db.isUsernameTaken(username);
  return c.json({ available: !taken });
});

app.post('/api/application/submit', async (c) => {
  const profile = c.get('session').get('profile');

  if (!profile) { c.status(401); return c.json({ error: 'Unauthorized' }) }

  const existing = await db.findUserBySub(profile.sub);
  if (existing) { c.status(400); return c.json({ error: 'You already have an account' }) }

  const pendingApp = await db.getApplicationBySub(profile.sub);
  if (pendingApp?.status === 'pending') { c.status(400); return c.json({ error: 'You already have a pending application' }) }

  let eligible = profile.verification_status === "verified";
  const inviteCode = c.get('session').get('invite_code');
  if (inviteCode && !eligible) {
    const invite = await db.getInvite(inviteCode);
    if (invite && (!invite.max_uses || invite.uses < invite.max_uses) && (!invite.expires_at || new Date() <= new Date(invite.expires_at))) {
      eligible = true;
    }
  }

  if (!eligible) { c.status(403); return c.json({ error: 'You are not eligible. You must be verified on auth.hackclub.com or have a valid invite code.' }) }

  const body = await c.req.json();
  const username = body.username?.toLowerCase();
  const sshKey = body.sshKey?.trim();
  const reason = body.reason?.trim();
  const server = body.server;
  const template = body.template;

  if (!username || !/^[a-z][a-z0-9_-]{1,30}[a-z0-9]$/.test(username)) {
    c.status(400)
    return c.json({ error: 'Invalid username. 3-32 chars, lowercase alphanumeric, hyphens, underscores. Must start with a letter and end with a letter or number.' })
  }
  if (require("./reservedUsernames").includes(username.toLowerCase())) {
    return c.json({ rror: 'This username is reserved.' });
  }

  if (!sshKey || !/^ssh-(ed25519|rsa|ecdsa)\s+\S+/.test(sshKey)) {
    c.status(400)
    return c.json({ error: 'A valid SSH public key is required.' })
  }

  if (!reason || reason.length < 10) {
    c.status(400)
    return c.json({ error: 'Please provide a reason (at least 10 characters).' })
  }

  const taken = await db.isUsernameTaken(username);
  if (taken) { c.status(409); return c.json({ error: 'Username is already taken' }) }

  const app = await db.createApplication({ sub: profile.sub, email: profile.email, username, sshKey, reason, server, template });

  if (inviteCode && profile.verification_status !== "verified") {
    await db.incrementInvite(inviteCode);
    c.get('session').set('invite_code', null);
  }

  return c.json({ message: 'Application submitted', application: app });
});

app.post('/api/container/start', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile) { c.status(401); return c.json({ error: 'Unauthorized' }) }

  const user = await db.findUserBySub(profile.sub);
  if (!user?.vmid) { c.status(404); return c.json({ error: 'No container found' }) }

  if (await isContainerSuspended(user.vmid)) {
    c.status(403)
    return c.json({ error: 'Your container is suspended. Contact an admin.' })
  }

  const node = process.env.PVE_NODE;
  const result = await pveFetch(`/nodes/${node}/lxc/${user.vmid}/status/start`, 'POST');
  await waitForTask(node, result.data);
  return c.json({ message: 'Container started' });
});

app.post('/api/container/stop', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile) { c.status(401); return c.json({ error: 'Unauthorized' }) }

  const user = await db.findUserBySub(profile.sub);
  if (!user?.vmid) { c.status(404); return c.json({ error: 'No container found' }) }

  if (await isContainerSuspended(user.vmid)) {
    c.status(403)
    return c.json({ error: 'Your container is suspended. Contact an admin.' })
  }

  const node = process.env.PVE_NODE;
  const result = await pveFetch(`/nodes/${node}/lxc/${user.vmid}/status/stop`, 'POST');
  await waitForTask(node, result.data);
  return c.json({ message: 'Container stopped' });
});

app.post('/api/container/reboot', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile) { c.status(401); return c.json({ error: 'Unauthorized' }) }

  const user = await db.findUserBySub(profile.sub);
  if (!user?.vmid) { c.status(404); return c.json({ error: 'No container found' }) }

  if (await isContainerSuspended(user.vmid)) {
    c.status(403)
    return c.json({ error: 'Your container is suspended. Contact an admin.' })
  }

  const node = process.env.PVE_NODE;
  const result = await pveFetch(`/nodes/${node}/lxc/${user.vmid}/status/reboot`, 'POST');
  await waitForTask(node, result.data);
  return c.json({ message: 'Container rebooted' });
});

app.post('/api/container/delete', async (c) => {
  const session = c.get('session');
  const profile = session.get('profile');
  if (!profile) { c.status(401); return c.json({ error: 'Unauthorized' }) }

  const sudo = session.get('sudo');
  if (!sudo) { c.status(403); return c.json({ error: 'Sudo required', redirect: '/flow/authorization/sudo/start' }) }

  const user = await db.findUserBySub(profile.sub);
  if (!user?.vmid) { c.status(404); return c.json({ error: 'No container found' }) }

  if (await isContainerSuspended(user.vmid)) {
    c.status(403)
    return c.json({ error: 'Your container is suspended. You cannot delete it. Contact an admin.' })
  }

  const node = process.env.PVE_NODE;
  const status = await getContainerStatus(user.vmid);

  if (status?.status === 'running') {
    const stopResult = await pveFetch(`/nodes/${node}/lxc/${user.vmid}/status/stop`, 'POST');
    await waitForTask(node, stopResult.data);
  }

  const deleteResult = await pveFetch(`/nodes/${node}/lxc/${user.vmid}`, 'DELETE');
  await waitForTask(node, deleteResult.data);
  await db.deleteUser(profile.sub);

  return c.json({ message: 'Deleted', vmid: user.vmid });
});

app.get('/api/domains', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile) { c.status(401); return c.json({ error: 'Unauthorized' }) }

  const user = await db.findUserBySub(profile.sub);
  if (!user) { c.status(404); return c.json({ error: 'No account found' }) }

  const domains = await db.getDomainsForUser(user.id);
  return c.json(domains);
});

app.post('/api/domains/add', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile) { c.status(401); return c.json({ error: 'Unauthorized' }) }

  const user = await db.findUserBySub(profile.sub);
  if (!user?.vmid) { c.status(400); return c.json({ error: 'You need a container first' }) }

  const body = await c.req.json();
  const domain = body.domain?.toLowerCase()?.trim();
  const proxy = body.proxy?.trim() || null;

  if (!domain || !isFQDN(domain)) {
    c.status(400)
    return c.json({ error: 'Invalid domain name' })
  }

  if (await db.domainExists(domain)) {
    c.status(409)
    return c.json({ error: 'Domain is already taken' })
  }

  const ip = await getContainerIP(user.vmid, user.ip);
  if (!ip) { c.status(500); return c.json({ error: 'Could not determine container IP' }) }

  const whitelisted = isWhitelisted(domain, user.username);

  if (!whitelisted) {
    const userDomains = await db.getDomainsForUser(user.id);
    const isSubOfOwned = userDomains.some(d => domain.endsWith('.' + d.domain));

    if (!isSubOfOwned) {
      const verified = await checkDNSVerification(domain, user.username);
      if (!verified) {
        c.status(403)
        return c.json({
          error: `Domain not verified. Either add a TXT record "${domain}" → "domain-verification=${user.username}" or set a CNAME to "${user.username}.hackclub.app". Then try again.`
        });
      }
    }
  }

  const proxyTarget = proxy || `${ip}:80`;
  const row = await db.addDomain({ userId: user.id, domain, proxy: proxyTarget });

  if (process.env.DISABLE_SSL !== 'true') {
    try {
      await issueCertificate(domain);
      await reloadProxy();
    } catch (err) {
      console.error(`Failed to issue certificate for ${domain}:`, err.message);
    }
  }

  return c.json({ message: `${domain} added`, domain: row });
});

app.get('/api/tls-ask', async (c) => {
  const domain = c.req.query('domain');
  if (!domain) {
    c.status(400);
    return c.text('Missing domain');
  }
  if (domain.endsWith(".hackclub.app")) return c.text('OK');
  const appDomain = process.env.APP_DOMAIN;
  if (appDomain && domain === appDomain) return c.text('OK');

  const domainRow = await db.getDomainByName(domain);
  if (domainRow) return c.text('OK');

  c.status(404);
  return c.text('Not found');
});

app.post('/api/domains/remove', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile) { c.status(401); return c.json({ error: 'Unauthorized' }) }

  const user = await db.findUserBySub(profile.sub);
  if (!user) { c.status(404); return c.json({ error: 'No account found' }) }

  const body = await c.req.json();
  const domain = body.domain?.toLowerCase()?.trim();

  if (!domain) { c.status(400); return c.json({ error: 'Domain is required' }) }

  const removed = await db.removeDomain(user.id, domain);
  if (!removed) { c.status(404); return c.json({ error: 'Domain not found or not owned by you' }) }

  await db.deleteCertificate(domain);
  await reloadProxy();

  return c.json({ message: `${domain} removed` });
});

async function buildServerNames() {
  const certs = await db.getAllCertificates();
  const serverNames = {};
  for (const cert of certs) {
    serverNames[cert.domain] = { cert: cert.cert, key: cert.key };
  }
  return serverNames;
}

async function proxyRequest(req, target) {
  const url = new URL(req.url);
  const targetUrl = `http://${target}${url.pathname}${url.search}`;

  const headers = new Headers();
  for (const [k, v] of req.headers) {
    const lower = k.toLowerCase();
    if (lower !== 'host' && lower !== 'connection' && lower !== 'transfer-encoding') {
      headers.set(k, v);
    }
  }
  headers.set('X-Forwarded-For', req.headers.get('X-Forwarded-For') || '');
  headers.set('X-Forwarded-Proto', 'https');
  headers.set('X-Forwarded-Host', url.hostname);

  const proxyRes = await fetch(targetUrl, {
    method: req.method,
    headers,
    body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
  });

  const resHeaders = new Headers();
  for (const [k, v] of proxyRes.headers) {
    const lower = k.toLowerCase();
    if (lower !== 'transfer-encoding' && lower !== 'connection') {
      resHeaders.set(k, v);
    }
  }

  return new Response(proxyRes.body, { status: proxyRes.status, headers: resHeaders });
}

let proxyServer = null;

async function reloadProxy() {
  const serverNames = await buildServerNames();
  if (Object.keys(serverNames).length === 0) return;

  const appPort = parseInt(process.env.MOCINNO_PORT) || 3000;
  const appDomain = process.env.APP_DOMAIN;

  const proxyFetch = async (req) => {
    try {
      const host = new URL(req.url).hostname;
      if (appDomain && host === appDomain) {
        return proxyRequest(req, `127.0.0.1:${appPort}`);
      }
      const domainRow = await db.getDomainByName(host);
      if (!domainRow) return new Response('Not found', { status: 404 });
      return proxyRequest(req, domainRow.proxy);
    } catch (err) {
      console.error('Proxy error:', err.message);
      return new Response('Bad Gateway', { status: 502 });
    }
  };

  if (proxyServer) proxyServer.stop(true);

  if (process.env.DISABLE_SSL !== 'true') {
    proxyServer = Bun.serve({
      port: 443,
      hostname: '0.0.0.0',
      tls: { serverNames },
      fetch: proxyFetch,
    });
  }
}

Bun.serve({
  port: process.env.PORT || 80,
  hostname: '0.0.0.0',
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/.well-known/acme-challenge/')) {
      const token = url.pathname.split('/').pop();
      const keyAuth = getChallengeResponse(token);
      if (keyAuth) return new Response(keyAuth, { headers: { 'Content-Type': 'application/octet-stream' } });
      return new Response('Not found', { status: 404 });
    }
    const host = req.headers.get('host')?.split(':')[0] || '';
    if (process.env.DISABLE_SSL === 'true' || !isPublicDomain(host)) {
      try {
        const appDomain = process.env.APP_DOMAIN;
        if (appDomain && host === appDomain) {
          const appPort = parseInt(process.env.MOCINNO_PORT) || 3000;
          return proxyRequest(req, `127.0.0.1:${appPort}`);
        }
        const domainRow = await db.getDomainByName(host);
        if (!domainRow) return new Response('Not found', { status: 404 });
        return proxyRequest(req, domainRow.proxy);
      } catch (err) {
        console.error('HTTP proxy error:', err.message);
        return new Response('Bad Gateway', { status: 502 });
      }
    }
    return Response.redirect(`https://${req.headers.get('host')}${url.pathname}${url.search}`, 301);
  },
});

app.post('/api/proxy/reload', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile || !db.isAdmin(profile.email)) { c.status(403); return c.json({ error: 'Forbidden' }) }
  await reloadProxy();
  return c.json({ message: 'Proxy reloaded' });
});

app.get('/admin', async (c) => {
  const session = c.get('session');
  const profile = session.get("profile");
  if (!profile) return c.redirect("/flow/authorization/login/start");
  if (!db.isAdmin(profile.email)) { c.status(403); return c.text('Forbidden') }

  const users = [];
  const applications = await db.getPendingApplications();
  const allApplications = await db.getAllApplications();
  const invites = await db.getAllInvites();
  const stats = await getNodeStats();

  const html = await engine.renderFile('admin', {
    profile, users, applications,
    allApplications, invites, stats,
    appDomain: process.env.APP_DOMAIN || c.req.header('host')
  });
  
  return c.html(html);
});

app.post('/api/admin/invites/create', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile || !db.isAdmin(profile.email)) { c.status(403); return c.json({ error: 'Forbidden' }) }

  const body = await c.req.json();
  const code = crypto.randomBytes(8).toString('hex');
  const maxUses = parseInt(body.maxUses) || null;
  const expiresAt = body.expiresAt || null;

  const invite = await db.createInvite({ code, adminEmail: profile.email, maxUses, expiresAt });
  return c.json({ message: 'Invite created', invite });
});

app.post('/api/admin/invites/delete', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile || !db.isAdmin(profile.email)) { c.status(403); return c.json({ error: 'Forbidden' }) }

  const { code } = await c.req.json();
  await db.deleteInvite(code);
  return c.json({ message: 'Invite deleted' });
});

app.get('/api/admin/users', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile || !db.isAdmin(profile.email)) { c.status(403); return c.json({ error: 'Forbidden' }) }

  const query = c.req.query('q') || '';
  const page = Math.max(1, parseInt(c.req.query('page')) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(c.req.query('limit')) || 50));
  const offset = (page - 1) * limit;

  const { users, total } = await db.searchUsers({ query, limit, offset });

  const usersWithStatus = [];
  for (const user of users) {
    let container = null;
    let suspended = false;
    if (user.vmid) {
      container = await getContainerStatus(user.vmid);
      suspended = await isContainerSuspended(user.vmid);
    }
    usersWithStatus.push({ ...user, container, suspended });
  }

  return c.json({ users: usersWithStatus, total, page, limit, pages: Math.ceil(total / limit) });
});

app.get('/api/admin/applications', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile || !db.isAdmin(profile.email)) { c.status(403); return c.json({ error: 'Forbidden' }) }

  const applications = await db.getPendingApplications();
  return c.json(applications);
});

app.post('/api/admin/applications/approve', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile || !db.isAdmin(profile.email)) { c.status(403); return c.json({ error: 'Forbidden' }) }

  const body = await c.req.json();
  const appId = body.id;
  if (!appId) { c.status(400); return c.json({ error: 'Application ID required' }) }

  const application = await db.getApplicationById(appId);
  if (!application) { c.status(404); return c.json({ error: 'Application not found' }) }
  if (application.status !== 'pending') { c.status(400); return c.json({ error: 'Application already processed' }) }

  const config = require('./config.js');
  const serverConfig = config.servers.find(s => s.name === application.server) || config.servers[0];
  const templateConfig = Array.isArray(serverConfig.templates)
    ? serverConfig.templates.find(t => t.name === application.template) || serverConfig.templates[0]
    : serverConfig.templates;

  const vmid = await getNextVmid();
  const node = serverConfig.node || process.env.PVE_NODE;
  const password = crypto.randomBytes(12).toString('hex');
  const allocated = await db.allocateIP();
  const result = await pveFetch(`/nodes/${node}/lxc`, 'POST', {
    vmid,
    ostemplate: templateConfig.template || process.env.OS_TEMPLATE,
    rootfs: serverConfig.rootfs || process.env.ROOTFS,
    unprivileged: 1,
    features: 'nesting=1',
    cores: 1,
    memory: 512,
    swap: 512,
    net0: `name=eth0,bridge=vmbr4030,firewall=1,ip=${allocated.ip}/${allocated.prefix},gw=${serverConfig.gateway || allocated.gateway},ip6=auto`,
    hostname: application.username,
    'ssh-public-keys': `${bastionPubKey}\n${application.ssh_key}`,
    password,
    start: 1
  });

  await waitForTask(node, result.data);
  await db.createUser({ sub: application.sub, username: application.username, sshKeys: [application.ssh_key], vmid: parseInt(vmid), ip: allocated.ip });
  await db.updateApplicationStatus(appId, 'approved', profile.email);
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: application.email,
    subject: 'Nest account approved!',
    text: `Your Nest account was approved. Congrats!
    
Internal IP: ${allocated.ip}
Username: ${application.username}
Operating System: ${templateConfig.name || process.env.OS_TEMPLATE}

To login to Nest, you may use ssh ${application.username}@hackclub.app

From the Dashboard (https://dashboard.hackclub.app/dashboard), you can manage custom domains, reboot your container, stop your container, or even delete your Nest account.

By default, you have 512MB of RAM, 1 core of CPU, and 8 GB of storage. To increase this limit, you may contact the Nest team on slack via #nest-help`
  });
  return c.json({ message: 'Approved and container created', vmid, password });
});

app.post('/api/admin/applications/reject', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile || !db.isAdmin(profile.email)) { c.status(403); return c.json({ error: 'Forbidden' }) }

  const body = await c.req.json();
  const appId = body.id;
  if (!appId) { c.status(400); return c.json({ error: 'Application ID required' }) }

  const application = await db.getApplicationById(appId);
  if (!application) { c.status(404); return c.json({ error: 'Application not found' }) }
  if (application.status !== 'pending') { c.status(400); return c.json({ error: 'Application already processed' }) }

  await db.updateApplicationStatus(appId, 'rejected', profile.email);

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: application.email,
    subject: 'Nest account rejected',
    text: `Your Nest account was rejected.
    
You may contact the Nest team via #nest-help to learn more.`
  });
  return c.json({ message: 'Application rejected' });
});

app.post('/api/admin/users/suspend', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile || !db.isAdmin(profile.email)) { c.status(403); return c.json({ error: 'Forbidden' }) }

  const body = await c.req.json();
  const vmid = body.vmid;
  const reason = body.reason || 'Suspended by admin';
  if (!vmid) { c.status(400); return c.json({ error: 'VMID required' }) }

  const node = process.env.PVE_NODE;
  await setContainerDescription(vmid, `suspend: ${reason}`);

  try {
    const status = await getContainerStatus(vmid);
    if (status?.status === 'running') {
      const stopResult = await pveFetch(`/nodes/${node}/lxc/${vmid}/status/stop`, 'POST');
      await waitForTask(node, stopResult.data);
    }
  } catch { }

  return c.json({ message: `Container ${vmid} suspended` });
});

app.post('/api/admin/users/unsuspend', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile || !db.isAdmin(profile.email)) { c.status(403); return c.json({ error: 'Forbidden' }) }

  const body = await c.req.json();
  const vmid = body.vmid;
  if (!vmid) { c.status(400); return c.json({ error: 'VMID required' }) }

  await setContainerDescription(vmid, '');
  return c.json({ message: `Container ${vmid} unsuspended` });
});

app.post('/api/admin/users/update', async (c) => {
  const profile = c.get('session').get('profile');
  if (!profile || !db.isAdmin(profile.email)) { c.status(403); return c.json({ error: 'Forbidden' }) }

  const body = await c.req.json();
  const vmid = body.vmid;
  if (!vmid) { c.status(400); return c.json({ error: 'VMID required' }) }

  const node = process.env.PVE_NODE;
  const updates = {};

  if (body.cores !== undefined) {
    const cores = parseInt(body.cores);
    if (isNaN(cores) || cores < 1 || cores > 16) { c.status(400); return c.json({ error: 'Cores must be 1-16' }) }
    updates.cores = cores;
  }

  if (body.memory !== undefined) {
    const memory = parseInt(body.memory);
    if (isNaN(memory) || memory < 128 || memory > 32768) { c.status(400); return c.json({ error: 'Memory must be 128-32768 MB' }) }
    updates.memory = memory;
  }

  if (body.username !== undefined) {
    const username = body.username.toLowerCase();
    if (!/^[a-z][a-z0-9_-]{1,30}[a-z0-9]$/.test(username)) {
      c.status(400); return c.json({ error: 'Invalid username' })
    }
    const taken = await db.isUsernameTaken(username);
    if (taken) { c.status(409); return c.json({ error: 'Username already taken' }) }
    await db.updateUsername(vmid, username);
    updates.hostname = username;
  }

  if (Object.keys(updates).length > 0) {
    await pveFetch(`/nodes/${node}/lxc/${vmid}/config`, 'PUT', updates);
  }

  return c.json({ message: 'Updated' });
});

const serve = Bun.serve({
  fetch: app.fetch,
  port: process.env.MOCINNO_PORT || 3000,
  maxRequestBodySize: process.env.MOCINNO_MAX_BODY_REQUEST_SIZE || 1024 * 1024 * 128,
  hostname: process.env.MOCINNO_HOSTNAME || "127.0.0.1"
});

console.log('Mocinno is running on port %s (%s)', serve.port, serve.hostname);

(async () => {
  if (process.env.DISABLE_SSL !== 'true') {
    const appDomain = process.env.APP_DOMAIN;
    if (appDomain) {
      try {
        await getOrIssueCertificate(appDomain);
        console.log(`Certificate ready for ${appDomain}`);
      } catch (err) {
        console.error(`Failed to issue certificate for ${appDomain}:`, err.message);
      }
    }

    const domains = await db.getAllDomains();
    for (const d of domains) {
      try {
        await getOrIssueCertificate(d.domain);
      } catch (err) {
        console.error(`Failed to issue certificate for ${d.domain}:`, err.message);
      }
    }

    await reloadProxy();
    console.log('Proxy server running on port 443');

    setInterval(async () => {
      try {
        await renewExpiringCertificates();
        await reloadProxy();
      } catch (err) {
        console.error('Certificate renewal error:', err.message);
      }
    }, 12 * 60 * 60 * 1000);
  } else {
    console.log('[!] SSL is disabled. Please don\'t be stupid with this.');
  }
})();

process.on('uncaughtException', (error) => {
  console.error(error);
});

process.on('unhandledRejection', (error) => {
  console.error(error);
});
