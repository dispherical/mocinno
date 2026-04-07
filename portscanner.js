const WINDOW_MS = 15 * 60 * 1000
const SLOW_BIG_HIT_THRESHOLD = 20
const SLOW_IP_THRESHOLD = 10
const FAST_BIG_HIT_THRESHOLD = 5
const FAST_IP_THRESHOLD = 3
const SEQUENTIAL_PORT_TRIGGER = 4
const UNIQUE_PORTS_THRESHOLD = 20

const SAFE_PORTS = new Set([80, 443])

const SUSPEND_COOLDOWN_MS = 60_000

const containers = new Map()
const recentPorts = {}
const lastSuspended = new Map()
const ipToVmid = new Map()
const vmidToName = new Map()

import * as db from './db.js'

async function pveFetch(path, method = 'GET', body = null) {
  const url = `${process.env.PVE_URL}${path}`
  const options = {
    method,
    headers: {
      'Authorization': `PVEAPIToken=${process.env.PVE_TOKEN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json'
    },
    tls: { rejectUnauthorized: false },
  }

  if (body) {
    const params = new URLSearchParams()
    Object.entries(body).forEach(([k, v]) => params.append(k, v))
    options.body = params
  }

  const res = await fetch(url, options)
  if (!res.ok) {
    const err = await res.text()
    throw new Error(`PVE API Error: ${res.status} - ${err}`)
  }
  return res.json()
}

async function refreshIPMap() {
  const node = process.env.PVE_NODE

  try {
    const users = await db.getAllUsers()
    for (const user of users) {
      if (user.ip && user.vmid) {
        ipToVmid.set(user.ip, user.vmid)
        vmidToName.set(user.vmid, user.username)
      }
    }
  } catch {}

  try {
    const list = await pveFetch(`/nodes/${node}/lxc`)
    for (const ct of list.data) {
      if (ct.name) vmidToName.set(ct.vmid, ct.name)
      if (ipToVmid.has(ct.vmid)) continue
      try {
        const ifaces = await pveFetch(`/nodes/${node}/lxc/${ct.vmid}/interfaces`)
        const eth0 = ifaces.data?.find(i => i.name === 'eth0')
        const ip = eth0?.['inet']?.split('/')[0]
        if (ip) ipToVmid.set(ip, ct.vmid)
      } catch {}
    }
    console.log(`IP map refreshed: ${ipToVmid.size} containers`)
  } catch (e) {
    console.error('failed to refresh IP map:', e.message)
  }
}

function getState(vmid) {
  const now = Date.now()
  let state = containers.get(vmid)
  if (!state || now - state.lastReset > WINDOW_MS) {
    state = { bigHits: 0, uniqueIPs: new Set(), portsPerDest: new Map(), lastReset: now }
    containers.set(vmid, state)
    for (const key of Object.keys(recentPorts)) {
      if (key.startsWith(`${vmid}:`)) delete recentPorts[key]
    }
  }
  return state
}

function isSequential(vmid, destIP, port) {
  const key = `${vmid}:${destIP}`
  if (!recentPorts[key]) recentPorts[key] = []
  const ports = recentPorts[key]
  ports.push(port)
  if (ports.length > SEQUENTIAL_PORT_TRIGGER + 1) ports.shift()
  if (ports.length < SEQUENTIAL_PORT_TRIGGER) return false
  return ports.every((p, i) => i === 0 || p === ports[i - 1] + 1)
}

async function setContainerDescription(vmid, description) {
  const node = process.env.PVE_NODE;
  await pveFetch(`/nodes/${node}/lxc/${vmid}/config`, 'PUT', { description });
}

async function suspendContainer(vmid, reason) {
  const now = Date.now()
  const last = lastSuspended.get(vmid)
  if (last && now - last < SUSPEND_COOLDOWN_MS) return
  lastSuspended.set(vmid, now)
  console.error(`suspend! vmid ${vmid} — ${reason}`)
  const node = process.env.PVE_NODE
  try {
    await setContainerDescription(vmid, `suspend: ${reason}`)
    await pveFetch(`/nodes/${node}/lxc/${vmid}/status/stop`, 'POST')
  } catch (e) {
    console.error(`failed to suspend! Failed to suspend vmid ${vmid}:`, e.message)
  }
  await notifySlack(vmid, reason)
}

async function notifySlack(vmid, reason) {
  const url = process.env.SLACK_WEBHOOK_URL
  if (!url) return
  const username = vmidToName.get(vmid) || 'unknown'
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: `Container ${vmid} (${username}) suspended: ${reason}`,
        blocks: [
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `:rotating_light: *Container Suspended*`,
            },
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*User*\n${username}` },
              { type: 'mrkdwn', text: `*VMID*\n${vmid}` },
            ],
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Reason*\n${reason}`,
            },
          },
        ],
      }),
    })
  } catch (e) {
    console.error(`error! Slack notification failed:`, e.message)
  }
}

function parseTcpdumpLine(line) {
  const match = line.match(/IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+):/)
  if (!match) return null

  const srcIP = match[1]
  const vmid = ipToVmid.get(srcIP)
  if (!vmid || vmid < 107) return null

  return {
    srcIP,
    destIP: match[3],
    destPort: parseInt(match[4], 10),
    vmid,
  }
}

function onConnection(vmid, destIP, destPort) {
  const state = getState(vmid)
  const isBigHit = !SAFE_PORTS.has(destPort)

  if (isBigHit) state.bigHits++
  state.uniqueIPs.add(destIP)

  if (isBigHit) {
    if (!state.portsPerDest.has(destIP)) state.portsPerDest.set(destIP, new Set())
    state.portsPerDest.get(destIP).add(destPort)

    if (state.portsPerDest.get(destIP).size >= UNIQUE_PORTS_THRESHOLD) {
      suspendContainer(vmid, `port scan on ${destIP}: ${state.portsPerDest.get(destIP).size} unique ports`)
      return
    }
  }

  if (isSequential(vmid, destIP, destPort)) {
    suspendContainer(vmid, `sequential port scan detected (reached port ${destPort})`)
    return
  }

  if (state.bigHits >= FAST_BIG_HIT_THRESHOLD && state.uniqueIPs.size >= FAST_IP_THRESHOLD) {
    suspendContainer(vmid, `fast threshold: ${state.bigHits} big hits across ${state.uniqueIPs.size} IPs`)
    return
  }

  if (state.bigHits >= SLOW_BIG_HIT_THRESHOLD && state.uniqueIPs.size >= SLOW_IP_THRESHOLD) {
    suspendContainer(vmid, `slow threshold: ${state.bigHits} big hits across ${state.uniqueIPs.size} IPs`)
  }
}

async function main() {
  console.log('starting tcpdump...')

  await refreshIPMap()
  setInterval(refreshIPMap, 60_000)

  const proc = Bun.spawn(['tcpdump', '-l', '-n', '-i', 'any', 'tcp[tcpflags] & tcp-syn != 0'], {
    stdout: 'pipe',
  })

  const decoder = new TextDecoder()
  let buffer = ''

  for await (const chunk of proc.stdout) {
    buffer += decoder.decode(chunk)
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? ''

    for (const line of lines) {
      if (!line.trim()) continue
      const parsed = parseTcpdumpLine(line)
      if (parsed) {
        onConnection(parsed.vmid, parsed.destIP, parsed.destPort)
      }
    }
  }
}

main()
