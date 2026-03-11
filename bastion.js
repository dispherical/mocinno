import { Server, Client as SSHClient, utils } from 'ssh2';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import * as db from './db.js';

const hostKey = readFileSync(process.env.BASTION_HOST_KEY || './bastion_host_key');
const bastionPrivateKey = readFileSync(process.env.BASTION_PROXY_KEY || './bastion_proxy_key');

async function pveFetch(path, method = 'GET', body = null) {
  const url = `${process.env.PVE_URL}${path}`;
  const options = {
    method,
    headers: {
      'Authorization': `PVEAPIToken=${process.env.PVE_TOKEN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json'
    },
    tls: { rejectUnauthorized: false }
  };
  if (body) {
    const params = new URLSearchParams();
    Object.entries(body).forEach(([k, v]) => params.append(k, v));
    options.body = params;
  }
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`PVE API Error: ${res.status}`);
  return res.json();
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

async function findContainerByUsername(username) {
  const user = await db.findUserByUsername(username);
  if (!user?.vmid) return null;

  const node = process.env.PVE_NODE;
  let status = 'unknown';
  let ip = user.ip || null;

  try {
    const statusRes = await pveFetch(`/nodes/${node}/lxc/${user.vmid}/status/current`);
    status = statusRes.data.status;
  } catch {}

  if (status === 'running' && !ip) {
    try {
      const ifaces = await pveFetch(`/nodes/${node}/lxc/${user.vmid}/interfaces`);
      const eth0 = ifaces.data?.find(i => i.name === 'eth0');
      ip = eth0?.['inet']?.split('/')[0] || null;
    } catch {}
  }

  const suspended = await isContainerSuspended(user.vmid);
  return { vmid: user.vmid, ip, status, sshKey: user.ssh_key, suspended };
}

function verifyClientKey(ctx, allowedKeyStr) {
  if (!allowedKeyStr) return false;
  const allowedKey = utils.parseKey(allowedKeyStr);
  if (allowedKey instanceof Error) return false;
  const parsed = Array.isArray(allowedKey) ? allowedKey[0] : allowedKey;
  if (ctx.key.algo !== parsed.type || !ctx.key.data.equals(parsed.getPublicSSH())) return false;
  if (ctx.signature && parsed.verify(ctx.blob, ctx.signature) !== true) return false;
  return true;
}

function writeAndClose(stream, message) {
  stream.write(`\r\n${message}\r\n`);
  stream.close();
}

async function resolveContainer(containerPromise, username, client, stream) {
  let container;
  try {
    container = await containerPromise;
  } catch (e) {
    console.error(`[bastion] Lookup failed for ${username}: ${e.message}`);
    if (stream) writeAndClose(stream, 'Error looking up your container.');
    client.end();
    return null;
  }

  if (!container) {
    console.warn(`[bastion] No container found for ${username}`);
    if (stream) writeAndClose(stream, 'No container found for your account.');
    client.end();
    return null;
  }

  if (container.suspended) {
    console.warn(`[bastion] Container for ${username} is suspended`);
    if (stream) writeAndClose(stream, 'Your container has been suspended. Please contact an admin for assistance.');
    client.end();
    return null;
  }

  if (container.status !== 'running') {
    console.log(`[bastion] Container for ${username} is ${container.status}, attempting to start...`);
    if (stream) stream.write(`\r\nYour container is ${container.status}. Starting it up...\r\n`);
    try {
      const node = process.env.PVE_NODE;
      const result = await pveFetch(`/nodes/${node}/lxc/${container.vmid}/status/start`, 'POST');
      await waitForTask(node, result.data);
      await new Promise(r => setTimeout(r, 3000));
      if (!container.ip) {
        try {
          const ifaces = await pveFetch(`/nodes/${node}/lxc/${container.vmid}/interfaces`);
          const eth0 = ifaces.data?.find(i => i.name === 'eth0');
          container.ip = eth0?.['inet']?.split('/')[0];
        } catch {}
      }
      if (!container.ip) {
        if (stream) writeAndClose(stream, 'Container started but could not determine IP. Try again in a moment.');
        client.end();
        return null;
      }
      if (stream) stream.write('Container started. Connecting...\r\n');
    } catch (e) {
      console.error(`[bastion] Failed to start container for ${username}: ${e.message}`);
      if (stream) writeAndClose(stream, 'Failed to start your container. Please try again later.');
      client.end();
      return null;
    }
  }

  if (!container.ip) {
    console.warn(`[bastion] No IP for ${username}`);
    if (stream) writeAndClose(stream, 'Could not determine your container IP. Try again in a moment.');
    client.end();
    return null;
  }

  console.log(`[bastion] Routing ${username} -> ${container.ip}:22 (vmid ${container.vmid})`);
  return container;
}

const server = new Server({ hostKeys: [hostKey] }, (client) => {
  let username = null;
  let containerPromise = null;

  client.on('authentication', async (ctx) => {
    username = ctx.username;

    if (ctx.method === 'none') {
      return ctx.reject(['publickey']);
    }

    if (ctx.method !== 'publickey') {
      return ctx.reject(['publickey']);
    }

    try {
      if (!containerPromise) containerPromise = findContainerByUsername(username);
      const container = await containerPromise;

      if (!container?.sshKey) {
        console.warn(`[bastion] No SSH key on record for ${username}`);
        return ctx.reject(['publickey']);
      }

      if (verifyClientKey(ctx, container.sshKey)) {
        return ctx.accept();
      }
    } catch (e) {
      console.error(`[bastion] Auth lookup failed for ${username}: ${e.message}`);
    }

    ctx.reject(['publickey']);
  });

  client.on('ready', () => {
    console.log(`[bastion] ${username} authenticated`);

    client.on('session', (accept) => {
      const session = accept();

      session.on('pty', (accept) => { accept(); });

      session.on('shell', async (accept) => {
        const stream = accept();
        const container = await resolveContainer(containerPromise, username, client, stream);
        if (!container) return;
        proxyToContainer(container.ip, stream, client);
      });

      session.on('exec', async (accept, reject, info) => {
        const stream = accept();
        const container = await resolveContainer(containerPromise, username, client, stream);
        if (!container) return;
        proxyToContainer(container.ip, stream, client, info.command);
      });

      session.on('subsystem', async (accept, reject, info) => {
        if (info.name === 'sftp') {
          const stream = accept();
          const container = await resolveContainer(containerPromise, username, client, stream);
          if (!container) return;
          proxyToContainer(container.ip, stream, client, null, 'sftp');
        } else {
          reject();
        }
      });
    });
  });

  client.on('error', (err) => {
    console.error(`[bastion] Client error: ${err.message}`);
  });
});

function proxyToContainer(ip, clientStream, client, command = null, subsystem = null) {
  const conn = new SSHClient();

  conn.on('ready', () => {
    const opts = { term: 'xterm-256color' };

    if (subsystem) {
      conn.subsys(subsystem, (err, containerStream) => {
        if (err) { clientStream.close(); conn.end(); return; }
        pipeStreams(clientStream, containerStream, conn, client);
      });
    } else if (command) {
      conn.exec(command, opts, (err, containerStream) => {
        if (err) { clientStream.close(); conn.end(); return; }
        pipeStreams(clientStream, containerStream, conn, client);
      });
    } else {
      conn.shell(opts, (err, containerStream) => {
        if (err) { clientStream.close(); conn.end(); return; }
        pipeStreams(clientStream, containerStream, conn, client);
      });
    }
  });

  conn.on('error', (err) => {
    console.error(`[bastion] Upstream error: ${err.message}`);
    try { clientStream.close(); } catch {}
    try { client.end(); } catch {}
  });

  conn.connect({
    host: ip,
    port: 22,
    username: 'root',
    privateKey: bastionPrivateKey
  });
}

function pipeStreams(clientStream, containerStream, upstreamConn, client) {
  clientStream.pipe(containerStream).pipe(clientStream);

  clientStream.on('close', () => {
    upstreamConn.end();
  });

  containerStream.on('close', () => {
    try { clientStream.close(); } catch {}
    try { client.end(); } catch {}
  });

  containerStream.on('exit', (code) => {
    clientStream.exit(code ?? 0);
    clientStream.close();
  });
}

const port = parseInt(process.env.BASTION_PORT || '2222');
server.listen(port, '0.0.0.0', () => {
  console.log(`[bastion] SSH bastion listening on port ${port}`);
});
