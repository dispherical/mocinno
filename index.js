import { Hono } from 'hono'
import { sessionMiddleware, CookieStore } from 'hono-sessions'
import { Liquid } from 'liquidjs'
import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:dns/promises'
import * as db from './db.js'

const bastionPubKey = readFileSync(process.env.BASTION_PROXY_KEY_PUB || './bastion_proxy_key.pub', 'utf-8').trim();

function generateState(length = 16) {
  return crypto.randomBytes(length)
    .toString('base64')
    .replace(/[^a-zA-Z0-9]/g, '')
    .slice(0, length);
}



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


const engine = new Liquid({
  root: './views',
  extname: '.liquid',
  outputEscape: "escape",
  cache: process.env.NODE_ENV == "production",
})

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
    if (!application) {
      eligible = profile.verification_status === "verified_eligible"
    }
  }

  const html = await engine.renderFile('dashboard', { profile, user, container, domains, admin, suspended, application, eligible });
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

  session.set("profile", profile);

  // this allows one destructive action per 2fa login
  if (stored.mode === 'sudo') session.flash("sudo", true);

  return c.redirect("/dashboard")
});
app.get('/api/username/check', async (c) => {
  const username = c.req.query('username')?.toLowerCase();
  if (!username || !/^[a-z][a-z0-9_-]{1,30}[a-z0-9]$/.test(username)) {
    return c.json({ available: false, error: 'Invalid username. 3-32 chars, lowercase alphanumeric, hyphens, underscores. Must start with a letter and end with a letter or number.' });
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

  const eligible = profile.verification_status === "verified_eligible"
  if (!eligible) { c.status(403); return c.json({ error: 'You are not eligible. You must be verified on auth.hackclub.com.' }) }

  const body = await c.req.json();
  const username = body.username?.toLowerCase();
  const sshKey = body.sshKey?.trim();
  const reason = body.reason?.trim();

  if (!username || !/^[a-z][a-z0-9_-]{1,30}[a-z0-9]$/.test(username)) {
    c.status(400)
    return c.json({ error: 'Invalid username. 3-32 chars, lowercase alphanumeric, hyphens, underscores. Must start with a letter and end with a letter or number.' })
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

  const app = await db.createApplication({ sub: profile.sub, email: profile.email, username, sshKey, reason });
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

  await reloadCaddy();

  return c.json({ message: `${domain} added`, domain: row });
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

  await reloadCaddy();

  return c.json({ message: `${domain} removed` });
});

async function reloadCaddy() {
  const domains = await db.getAllDomains();

  const caddy = {
    admin: {
      listen: process.env.CADDY_ADMIN_LISTEN || "0.0.0.0:2019",
    },
    apps: {
      http: {
        servers: {
          srv0: {
            listen: [":443", ":80"],
            routes: [],
          },
        },
      },
      tls: {
        automation: {
          policies: [
            {
              subjects: ["*.hackclub.app"],
              on_demand: true,
            },
          ],
          on_demand: {
            permission: {
              endpoint: process.env.CADDY_ON_DEMAND_ENDPOINT || "https://hackclub.app/ok",
              module: "http",
            },
          },
        },
      },
    },
  };

  for (const domain of domains) {
    caddy.apps.http.servers.srv0.routes.push({
      match: [{ host: [domain.domain] }],
      handle: [
        {
          handler: "subroute",
          routes: [
            {
              handle: [
                {
                  handler: "reverse_proxy",
                  headers: {
                    request: {
                      set: {
                        "X-Forwarded-For": ["{http.request.remote.host}"],
                      },
                    },
                  },
                  upstreams: [{ dial: domain.proxy }],
                },
              ],
            },
          ],
        },
      ],
      terminal: true,
    });
  }

  const res = await fetch(process.env.CADDY_ADMIN_URL || "http://localhost:2019/load", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    timeout: false,
    body: JSON.stringify(caddy),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Caddy reload failed: ${res.status} - ${err}`);
  }
}

app.post('/api/caddy/reload', async (c) => {
  await reloadCaddy();
  return c.json({ message: 'Caddy config reloaded' });
});

app.get('/admin', async (c) => {
  const session = c.get('session');
  const profile = session.get("profile");
  if (!profile) return c.redirect("/flow/authorization/login/start");
  if (!db.isAdmin(profile.email)) { c.status(403); return c.text('Forbidden') }

  const users = [];
  const applications = await db.getPendingApplications();
  const allApplications = await db.getAllApplications();

  const html = await engine.renderFile('admin', { profile, users, applications, allApplications });
  return c.html(html);
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

  const vmid = await getNextVmid();
  const node = process.env.PVE_NODE;
  const password = crypto.randomBytes(12).toString('hex');
  const allocated = await db.allocateIP();
  const result = await pveFetch(`/nodes/${node}/lxc`, 'POST', {
    vmid,
    ostemplate: 'local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst',
    rootfs: 'local:8',
    unprivileged: 1,
    features: 'nesting=1',
    cores: 1,
    memory: 512,
    swap: 512,
    net0: `name=eth0,bridge=vmbr0,firewall=1,ip=${allocated.ip}/${allocated.prefix},gw=${allocated.gateway},ip6=auto`,
    hostname: application.username,
    'ssh-public-keys': `${bastionPubKey}\n${application.ssh_key}`,
    password,
    start: 1
  });

  await waitForTask(node, result.data);
  await db.createUser({ sub: application.sub, username: application.username, sshKey: application.ssh_key, vmid: parseInt(vmid), ip: allocated.ip });
  await db.updateApplicationStatus(appId, 'approved', profile.email);

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

export default app
