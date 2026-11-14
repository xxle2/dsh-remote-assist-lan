/**
 * dsh-remote-relay
 * 局域网 DSH 远程协助 / 监督 / 合作插件（v0.4）。
 *
 * 设计要点：
 *  - 每个装了本插件的 DSH 在局域网起一个独立 HTTP 服务（默认 0.0.0.0:37261），
 *    不依赖 DSH 自带的 localhost webServer，因此别的机器可以直接访问。
 *  - UDP 广播（默认 37262）做节点发现，无需手填 IP。
 *  - 授权模型：
 *      * 同账号（凭据 token 指纹一致）→ 自动配对；
 *      * 永久密码 / 临时密码 → 对方凭密码直接配对（不用确认）；
 *      * 其他 → 被协助方 DSH 弹窗确认（或配对码）。
 *  - 配对后双方共享 token，远程调用用 HMAC-SHA256 签名。
 *  - 能力：执行命令、系统状态、截图、文件传输（双向）、一键远程装插件、合作注入。
 *  - 设置页（客户端半边）通过 DSH 同源 webServer 路由读写：设备别名、显示/隐藏敏感信息、
 *    永久/临时密码、连接远程设备（输入设备代码+密码）、权限开关、待授权弹窗。
 *
 * 插件入口遵循 cordis 约定：export const name / inject / apply(ctx, config)。
 */

import http from 'node:http'
import dgram from 'node:dgram'
import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { execFile } from 'node:child_process'

export const name = 'dsh-remote-relay'
export const inject = ['tools', 'webServer']

const MAGIC = 'dsh-relay-v1'
const DEFAULT_PORT = 37261
const DEFAULT_DISCOVERY_PORT = 37262
const MAX_BODY = 1024 * 1024 // 1 MiB（普通 JSON 请求）
const TRANSFER_LIMIT = 32 * 1024 * 1024 // 32 MiB（文件传输，base64 JSON 体）
const EXEC_TIMEOUT_MS = 120 * 1000
const PAIR_CODE_TTL_MS = 10 * 60 * 1000
const DISCOVERY_INTERVAL_MS = 10 * 1000
const DISCOVERY_TTL_MS = 90 * 1000
const AUTH_SKEW_MS = 5 * 60 * 1000

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

const dshHome = () => {
  const envHome = process.env.DSH_HOME
  if (envHome && envHome.trim()) return envHome.trim()
  return path.join(os.homedir(), '.dsh')
}

const CONFIG_PATH = () => path.join(dshHome(), 'remote-relay.json')
const LOG_PATH = () => path.join(dshHome(), 'remote-relay.log')
const INBOX_PATH = () => path.join(dshHome(), 'remote-relay-inbox')

function ensureInbox() {
  const dir = INBOX_PATH()
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

function safeFileName(name) {
  const base = path.basename(String(name || 'file'))
  const clean = base
    .replace(/[\\/:*?"<>|\x00-\x1f]/g, '_')
    .trim()
  return clean || 'file'
}

function log(...args) {
  const line = new Date().toISOString() + ' ' + args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')
  try {
    fs.appendFileSync(LOG_PATH(), line + '\n')
  } catch {
    /* 日志失败不影响主流程 */
  }
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text).digest('hex')
}

function randomToken() {
  return crypto.randomBytes(32).toString('hex')
}

function randomCode() {
  // 6 位数字临时密码 / 配对码
  const n = crypto.randomInt(0, 1000000)
  return String(n).padStart(6, '0')
}

function isPrivateIp(raw) {
  if (!raw) return false
  let ip = String(raw)
  if (ip.startsWith('::ffff:')) ip = ip.slice(7)
  if (ip === '::1' || ip === 'localhost') return true
  const p = ip.split('.')
  if (p.length !== 4) return false
  const nums = p.map((x) => Number(x))
  if (nums.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return false
  const [a, b] = nums
  if (a === 127) return true
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  return false
}

function readJsonFile(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function writeJsonAtomic(file, value) {
  const tmp = file + '.tmp'
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), 'utf8')
  fs.renameSync(tmp, file)
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

const DEFAULT_CONFIG = {
  version: 1,
  enabled: true,
  port: DEFAULT_PORT,
  discoveryPort: DEFAULT_DISCOVERY_PORT,
  allowExec: true,
  allowScreenshot: true,
  allowInject: true,
  // 允许对方控制本设备（关闭后拒绝一切配对/执行）
  allowControl: true,
  // 设备别名（空则用计算机名；其他客户端看到的是这个）
  alias: '',
  // 永久密码：非空时，对方凭此密码直接配对（不用确认）
  pairPassword: '',
  // 临时随机密码：可显示/刷新，凭它也能配对（配对成功后自动刷新）
  tempPassword: '',
  // peers: nodeId -> { nodeId, hostname, accountFp, host, port, token, pairedAt, auto }
  peers: {},
  // pending: code -> { code, nodeId, hostname, accountFp, host, port, at }
  pending: {}
}

function loadConfig(overrides) {
  const base = readJsonFile(CONFIG_PATH()) || {}
  const merged = {
    ...DEFAULT_CONFIG,
    ...base,
    ...(overrides && typeof overrides === 'object' ? overrides : {}),
    peers: { ...(DEFAULT_CONFIG.peers), ...(base.peers || {}), ...((overrides && overrides.peers) || {}) },
    pending: { ...(base.pending || {}), ...((overrides && overrides.pending) || {}) },
  }
  if (!merged.alias) merged.alias = os.hostname()
  return merged
}

function saveConfig(cfg) {
  try {
    writeJsonAtomic(CONFIG_PATH(), cfg)
  } catch (err) {
    log('saveConfig failed:', err.message)
  }
}

// ---------------------------------------------------------------------------
// 身份：节点 ID / 账号指纹
// ---------------------------------------------------------------------------

function readCredentialsText() {
  try {
    return fs.readFileSync(path.join(dshHome(), '.credentials.yaml'), 'utf8')
  } catch {
    return ''
  }
}

function extractDeviceId(text) {
  const m = /deepseek-account-platform\/device:[\s\S]{0,400}?\bid:\s*['"]?([0-9a-fA-F-]{36})/.exec(text)
  return m ? m[1] : ''
}

function extractAccountToken(text) {
  const m = /deepseek-account-platform\/default:[\s\S]{0,600}?\btoken:\s*['"]?([^\s'"]+)/.exec(text)
  return m ? m[1] : ''
}

function accountFingerprint() {
  const override = process.env.DSH_RELAY_ACCOUNT_FP_OVERRIDE
  if (override && override.trim()) return override.trim()
  const token = extractAccountToken(readCredentialsText())
  if (!token) return 'anonymous'
  return sha256Hex(token).slice(0, 16)
}

function nodeId() {
  const override = process.env.DSH_RELAY_NODE_ID_OVERRIDE
  if (override && override.trim()) return override.trim()
  const cred = readCredentialsText()
  const deviceId = extractDeviceId(cred)
  if (deviceId) return deviceId
  return sha256Hex(os.hostname() + '|' + os.userInfo().username).slice(0, 16)
}

function identity(cfg) {
  const alias = String((cfg && cfg.alias) || '').trim() || os.hostname()
  return {
    magic: MAGIC,
    nodeId: nodeId(),
    accountFp: accountFingerprint(),
    hostname: alias,
    user: os.userInfo().username,
    platform: process.platform,
    port: cfg.port,
    dshVersion: process.env.DSH_VERSION || '',
  }
}

// ---------------------------------------------------------------------------
// HTTP 服务
// ---------------------------------------------------------------------------

function readBody(req, limit = MAX_BODY) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > limit) {
        reject(new Error('body too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

function json(res, status, value) {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) })
  res.end(body)
}

function sign(token, nodeIdValue, timestamp, body) {
  return crypto.createHmac('sha256', token).update(nodeIdValue + ':' + timestamp + ':' + body).digest('hex')
}

function verifyPeerRequest(cfg, req, body) {
  const remote = req.socket.remoteAddress || ''
  if (!isPrivateIp(remote)) return { ok: false, error: 'non-private client' }
  const peerNodeId = String(req.headers['x-node-id'] || '')
  const timestamp = String(req.headers['x-timestamp'] || '')
  const signature = String(req.headers['x-sign'] || '')
  if (!peerNodeId || !timestamp || !signature) return { ok: false, error: 'missing auth headers' }
  const peer = cfg.peers[peerNodeId]
  if (!peer) return { ok: false, error: 'peer not paired' }
  const ts = Number(timestamp)
  if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > AUTH_SKEW_MS) return { ok: false, error: 'stale timestamp' }
  const expect = sign(peer.token, peerNodeId, timestamp, body)
  const a = Buffer.from(expect, 'utf8')
  const b = Buffer.from(signature, 'utf8')
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, error: 'bad signature' }
  return { ok: true, peer }
}

function runCommand(command, timeoutMs) {
  return new Promise((resolve) => {
    const isWin = process.platform === 'win32'
    const shell = isWin ? 'powershell.exe' : '/bin/sh'
    const args = isWin
      ? ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', command]
      : ['-c', command]
    const child = execFile(
      shell,
      args,
      { timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024, windowsHide: true, encoding: 'utf8' },
      (err, stdout, stderr) => {
        const timedOut = !!(err && (err.killed || err.signal))
        resolve({
          exitCode: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
          timedOut,
          stdout: stdout || '',
          stderr: stderr || (err && !stdout ? String(err.message) : ''),
        })
      },
    )
    child.on('error', (err) => {
      resolve({ exitCode: 1, timedOut: false, stdout: '', stderr: String(err.message) })
    })
  })
}

async function takeScreenshot() {
  const file = path.join(os.tmpdir(), 'dsh-relay-shot-' + Date.now() + '.png')
  const script = [
    'Add-Type -AssemblyName System.Windows.Forms,System.Drawing',
    '$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds',
    '$b=New-Object Drawing.Bitmap $s.Width,$s.Height',
    '$g=[Drawing.Graphics]::FromImage($b)',
    '$g.CopyFromScreen($s.X,$s.Y,0,0,$b.Size)',
    `$b.Save('${file.replace(/'/g, "''")}',[Drawing.Imaging.ImageFormat]::Png)`,
    '$g.Dispose();$b.Dispose()',
  ].join('; ')
  const result = await runCommand(script, 30 * 1000)
  if (result.exitCode !== 0) {
    return { ok: false, error: result.stderr || 'screenshot failed' }
  }
  try {
    const buf = fs.readFileSync(file)
    fs.unlinkSync(file)
    return { ok: true, base64: buf.toString('base64'), bytes: buf.length, mime: 'image/png' }
  } catch (err) {
    return { ok: false, error: err.message }
  }
}

function systemStatus(cfg) {
  const cpus = os.cpus() || []
  const load = os.loadavg ? os.loadavg() : [0, 0, 0]
  const totalMem = os.totalmem()
  const freeMem = os.freemem()
  return {
    hostname: (cfg && cfg.alias) || os.hostname(),
    user: os.userInfo().username,
    platform: process.platform,
    arch: process.arch,
    release: os.release(),
    uptimeSec: Math.floor(os.uptime()),
    cpuCount: cpus.length,
    cpuModel: cpus[0] ? cpus[0].model : '',
    load1: load[0] ? Number(load[0].toFixed(2)) : 0,
    memTotalMb: Math.round(totalMem / 1048576),
    memFreeMb: Math.round(freeMem / 1048576),
    memUsedPct: Math.round(((totalMem - freeMem) / totalMem) * 100),
    process: {
      pid: process.pid,
      uptimeSec: Math.floor(process.uptime()),
      rssMb: Math.round(process.memoryUsage().rss / 1048576),
    },
  }
}

// ---------------------------------------------------------------------------
// UDP 发现
// ---------------------------------------------------------------------------

function broadcastAddresses() {
  const result = new Set()
  const ifaces = os.networkInterfaces()
  for (const list of Object.values(ifaces)) {
    for (const item of list || []) {
      if (!item || item.family !== 'IPv4' || item.internal) continue
      const ip = item.address
      const mask = item.netmask
      if (!ip || !mask) continue
      const ipNums = ip.split('.').map(Number)
      const maskNums = mask.split('.').map(Number)
      if (ipNums.length !== 4 || maskNums.length !== 4) continue
      const bcast = ipNums.map((n, i) => (n & maskNums[i]) | (255 ^ maskNums[i] & 255))
      result.add(bcast.join('.'))
    }
  }
  result.add('255.255.255.255')
  return [...result]
}

function startDiscovery(cfg, state) {
  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true })
  const discovered = new Map()

  const payload = () => JSON.stringify({ ...identity(cfg), discovery: cfg.discoveryPort })

  sock.on('error', (err) => log('discovery socket error:', err.message))
  sock.on('message', (msg, rinfo) => {
    let data
    try {
      data = JSON.parse(msg.toString('utf8'))
    } catch {
      return
    }
    if (!data || data.magic !== MAGIC) return
    if (data.nodeId === state.identity.nodeId) return
    if (!isPrivateIp(rinfo.address)) return
    discovered.set(data.nodeId, { ...data, host: rinfo.address, lastSeen: Date.now() })
  })
  const broadcastNow = () => {
    const buf = Buffer.from(payload(), 'utf8')
    for (const addr of broadcastAddresses()) {
      try {
        sock.send(buf, 0, buf.length, cfg.discoveryPort, addr, () => {})
      } catch {
        /* 单个地址失败忽略 */
      }
    }
  }

  sock.bind(cfg.discoveryPort, '0.0.0.0', () => {
    try {
      sock.setBroadcast(true)
    } catch (err) {
      log('setBroadcast failed:', err.message)
    }
    broadcastNow()
  })

  const interval = setInterval(() => {
    broadcastNow()
    const now = Date.now()
    for (const [id, item] of discovered) {
      if (now - item.lastSeen > DISCOVERY_TTL_MS) discovered.delete(id)
    }
  }, DISCOVERY_INTERVAL_MS)
  interval.unref?.()

  state.discovered = discovered
  state.discoverySocket = sock
  return { sock, interval, discovered }
}

// ---------------------------------------------------------------------------
// 主 apply
// ---------------------------------------------------------------------------

export function apply(ctx, pluginConfig) {
  const cfg = loadConfig(pluginConfig)
  const state = {
    identity: identity(cfg),
    server: null,
    discoverySocket: null,
    discovered: new Map(),
  }

  if (!cfg.enabled) {
    log('disabled by config')
    return
  }

  // ---------------- 工具实现（依赖 ctx.tools，稍后注册） ----------------

  const fmtPeer = (peer) => ({
    nodeId: peer.nodeId,
    hostname: peer.hostname,
    account: peer.accountFp === state.identity.accountFp ? 'same-account' : 'other-account',
    host: peer.host,
    port: peer.port,
    paired: !!peer.token,
    pairedAt: peer.pairedAt || '',
  })

  const listPeers = () => {
    const now = Date.now()
    const discovered = []
    for (const item of state.discovered.values()) {
      if (now - item.lastSeen > DISCOVERY_TTL_MS) continue
      const peer = cfg.peers[item.nodeId]
      discovered.push({
        nodeId: item.nodeId,
        hostname: item.hostname,
        host: item.host,
        port: item.port,
        account: item.accountFp === state.identity.accountFp ? 'same-account' : 'other-account',
        paired: !!peer,
      })
    }
    return {
      self: { nodeId: state.identity.nodeId, hostname: state.identity.hostname, port: cfg.port },
      discovered,
      paired: Object.values(cfg.peers).map(fmtPeer),
    }
  }

  const refreshTempPassword = () => {
    cfg.tempPassword = randomCode()
    saveConfig(cfg)
    return cfg.tempPassword
  }

  const pairPeer = async (target) => {
    // target: { host, port, nodeId, password }
    let host = target.host
    let port = target.port
    let nodeIdValue = target.nodeId
    if (nodeIdValue && (!host || !port)) {
      const found = state.discovered.get(nodeIdValue) || cfg.peers[nodeIdValue]
      if (!found) throw new Error('未发现该节点，请确认对面 DSH 已安装插件并在同一局域网（也可直接填 IP:端口）')
      host = found.host
      port = found.port
    }
    if (!host || !port) throw new Error('需要 host/port 或已发现的 nodeId')
    const res = await fetch(`http://${host}:${port}/api/pair`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nodeId: state.identity.nodeId,
        accountFp: state.identity.accountFp,
        hostname: state.identity.hostname,
        callbackPort: cfg.port,
        password: target.password || '',
      }),
      signal: AbortSignal.timeout(15000),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error('配对请求失败: HTTP ' + res.status + ' ' + JSON.stringify(data))
    if (data.paired && data.token) {
      cfg.peers[nodeIdValue || data.nodeId] = {
        nodeId: data.nodeId,
        hostname: data.hostname || '',
        accountFp: data.accountFp || '',
        host,
        port,
        token: data.token,
        pairedAt: new Date().toISOString(),
        auto: !!data.auto,
        viaPassword: !!data.viaPassword,
      }
      saveConfig(cfg)
      return { paired: true, nodeId: data.nodeId, hostname: data.hostname, auto: !!data.auto, viaPassword: !!data.viaPassword }
    }
    return {
      paired: false,
      needApproval: true,
      code: data.code,
      nodeId: data.nodeId,
      host,
      port,
      hint: '对方需要确认：请在对面的 DSH 设置页点「同意」，或让模型调用 remote_relay_approve，配对码 ' + data.code,
    }
  }

  const approvePending = (code) => {
    const item = cfg.pending[code]
    if (!item) return { ok: false, error: '配对码不存在或已过期' }
    if (Date.now() - item.at > PAIR_CODE_TTL_MS) {
      delete cfg.pending[code]
      saveConfig(cfg)
      return { ok: false, error: '配对码已过期' }
    }
    const token = randomToken()
    cfg.peers[item.nodeId] = {
      nodeId: item.nodeId,
      hostname: item.hostname || '',
      accountFp: item.accountFp || '',
      host: item.host,
      port: item.port,
      token,
      pairedAt: new Date().toISOString(),
      auto: false,
    }
    delete cfg.pending[code]
    saveConfig(cfg)
    return { ok: true, nodeId: item.nodeId, hostname: item.hostname }
  }

  const authedFetch = async (nodeIdValue, pathname, method = 'GET', body = '') => {
    const peer = cfg.peers[nodeIdValue]
    if (!peer || !peer.token) throw new Error('节点未配对: ' + nodeIdValue)
    const timestamp = String(Date.now())
    const headers = {
      'X-Node-Id': state.identity.nodeId,
      'X-Timestamp': timestamp,
      'X-Sign': sign(peer.token, state.identity.nodeId, timestamp, body),
      'Content-Type': 'application/json',
    }
    const res = await fetch(`http://${peer.host}:${peer.port}${pathname}`, {
      method,
      headers,
      body: method === 'GET' ? undefined : body,
      signal: AbortSignal.timeout(180 * 1000),
    })
    const text = await res.text()
    let data
    try {
      data = JSON.parse(text)
    } catch {
      data = { raw: text }
    }
    if (!res.ok) throw new Error('远端返回 HTTP ' + res.status + ': ' + JSON.stringify(data))
    return data
  }

  const execRemote = async (args) => {
    if (!cfg.allowExec) throw new Error('本机已关闭远程执行（配置 allowExec=false）')
    const peer = cfg.peers[args.nodeId]
    if (!peer) throw new Error('节点未配对: ' + args.nodeId)
    const body = JSON.stringify({ command: String(args.command || ''), timeoutSec: args.timeoutSec || 120 })
    return authedFetch(args.nodeId, '/api/exec', 'POST', body)
  }

  const transferFile = async (args) => {
    const peer = cfg.peers[args.nodeId]
    if (!peer) throw new Error('节点未配对: ' + args.nodeId)
    const localPath = String(args.localPath || '')
    if (!localPath) throw new Error('localPath required')
    const buf = fs.readFileSync(localPath)
    if (buf.length > TRANSFER_LIMIT) throw new Error('文件过大（上限 ' + Math.round(TRANSFER_LIMIT / 1048576) + 'MB）')
    const name = safeFileName(args.remoteName || path.basename(localPath))
    const body = JSON.stringify({ name, data: buf.toString('base64') })
    const data = await authedFetch(args.nodeId, '/api/transfer', 'POST', body)
    return { ok: true, ...data, localPath }
  }

  const downloadFile = async (args) => {
    const peer = cfg.peers[args.nodeId]
    if (!peer) throw new Error('节点未配对: ' + args.nodeId)
    const remotePath = String(args.remotePath || '')
    if (!remotePath) throw new Error('remotePath required')
    const data = await authedFetch(args.nodeId, '/api/transfer?path=' + encodeURIComponent(remotePath), 'GET')
    if (!data.ok) throw new Error(data.error || 'download failed')
    const buf = Buffer.from(data.data || '', 'base64')
    const target = args.localPath ? String(args.localPath) : path.join(os.tmpdir(), 'relay-dl-' + Date.now() + '-' + safeFileName(data.name))
    fs.writeFileSync(target, buf)
    return { ok: true, path: target, bytes: buf.length, name: data.name }
  }

  const installPlugin = async (args) => {
    const peer = cfg.peers[args.nodeId]
    if (!peer) throw new Error('节点未配对: ' + args.nodeId)
    const localPath = String(args.localPath || '')
    if (!localPath) throw new Error('localPath required')
    const pluginName = String(args.pluginName || 'dsh-remote-relay').trim()
    const up = await transferFile({ nodeId: args.nodeId, localPath, remoteName: path.basename(localPath) })
    const q = (s) => "'" + String(s).replace(/'/g, "''") + "'"
    const script = [
      "$ErrorActionPreference='Stop'",
      "$app = Join-Path $env:LOCALAPPDATA 'Programs\\DeepSeek Harness\\resources'",
      "$node = Join-Path $app 'runtime\\primary-runtime\\dependencies\\node\\bin\\node.exe'",
      "$pnpm = Join-Path $app 'runtime\\primary-runtime\\dependencies\\pnpm\\bin\\pnpm.cjs'",
      "$prof = Join-Path $env:USERPROFILE '.dsh\\profiles\\desktop'",
      "$pj = Join-Path $prof 'package.json'",
      "$orig = [IO.File]::ReadAllText($pj, [Text.Encoding]::UTF8) | ConvertFrom-Json",
      "$origBundles = @($orig.dsh.profile.bundles)",
      "& $node $pnpm add ('file:' + " + q(up.path) + ") --dir $prof | Out-Host",
      "if ($LASTEXITCODE -ne 0) { throw ('pnpm add failed: ' + $LASTEXITCODE) }",
      "$new = [IO.File]::ReadAllText($pj, [Text.Encoding]::UTF8) | ConvertFrom-Json",
      "$bundles = @($origBundles) + @(" + q(pluginName) + ") | Select-Object -Unique",
      "if (-not $new.dsh) { $new | Add-Member -NotePropertyName dsh -NotePropertyValue ([pscustomobject]@{}) -Force }",
      "if (-not $new.dsh.profile) { $new.dsh | Add-Member -NotePropertyName profile -NotePropertyValue ([pscustomobject]@{}) -Force }",
      "$new.dsh.profile | Add-Member -NotePropertyName bundles -NotePropertyValue $bundles -Force",
      "[IO.File]::WriteAllText($pj, ($new | ConvertTo-Json -Depth 20), (New-Object Text.UTF8Encoding($false)))",
      "Write-Output ('OK bundles=' + $bundles.Count)",
    ].join('; ')
    const result = await authedFetch(args.nodeId, '/api/exec', 'POST', JSON.stringify({ command: script, timeoutSec: 240 }))
    return {
      ok: result.exitCode === 0,
      uploaded: up,
      install: result,
      next: result.exitCode === 0 ? '已安装，需要（完全退出并重启）对面 DSH 才生效' : '安装失败，看 install.stderr',
    }
  }

  // ---------------- 注册工具 ----------------

  const registerTools = async () => {
    let defineTool
    try {
      ;({ defineTool } = await import('@deepseek-ai/dsh-tools'))
    } catch {
      defineTool = (def) => def
    }
    if (!ctx || typeof ctx.tools?.register !== 'function') {
      log('ctx.tools 未就绪，跳过工具注册')
      return
    }

    ctx.tools.register(
      defineTool({
        name: 'remote_relay_list',
        description:
          '列出局域网内其他安装了 dsh-remote-relay 插件的 DSH 节点（发现到的节点 + 已配对节点）。' +
          '返回节点 ID、设备别名、账号关系（同账号/异账号）、是否已配对。',
        parameters: {},
        output: {
          schema: { type: 'json' },
          render: (_args, value) => [{ type: 'text', text: '发现 ' + value.discovered.length + ' 个节点，已配对 ' + value.paired.length + ' 个' }],
        },
        async execute() {
          return listPeers()
        },
      }),
    )

    ctx.tools.register(
      defineTool({
        name: 'remote_relay_pair',
        description:
          '与局域网内一个节点配对。同账号自动通过；对方设置了永久/临时密码时传 password 可直接通过；' +
          '否则对方需要确认（设置页弹窗或 remote_relay_approve）。参数 nodeId 来自 remote_relay_list；' +
          '若网络禁止 UDP 广播，可显式传 host/port。',
        parameters: {
          nodeId: { type: 'string', description: '目标节点 ID（remote_relay_list 里拿）' },
          host: { type: 'string', description: '可选。目标 IP（UDP 发现不到时手动指定）' },
          port: { type: 'number', description: '可选。目标插件端口（默认 37261）' },
          password: { type: 'string', description: '可选。对面的永久密码或临时密码（可免确认直连）' },
        },
        output: {
          schema: { type: 'json' },
          render: (_args, value) =>
            [{ type: 'text', text: value.paired ? '已配对 ' + (value.hostname || value.nodeId) + (value.auto ? '（自动）' : '') : '需要对方确认，配对码 ' + value.code }],
        },
        async execute(args) {
          return pairPeer({ nodeId: args.nodeId, host: args.host, port: args.port, password: args.password })
        },
      }),
    )

    ctx.tools.register(
      defineTool({
        name: 'remote_relay_approve',
        description: '批准一个待授权的配对请求（本机作为被协助方时用）。配对码由对面的 remote_relay_pair 返回。',
        parameters: { code: { type: 'string', description: '6 位配对码' } },
        output: {
          schema: { type: 'json' },
          render: (_args, value) => [{ type: 'text', text: value.ok ? '已批准 ' + value.hostname : '批准失败: ' + value.error }],
        },
        async execute(args) {
          return approvePending(String(args.code || '').trim())
        },
      }),
    )

    ctx.tools.register(
      defineTool({
        name: 'remote_relay_exec',
        description:
          '在已配对的远程节点上执行 PowerShell 命令并返回 stdout/stderr/退出码。用于远程协助（安装软件、排障等）。',
        parameters: {
          nodeId: { type: 'string', description: '目标节点 ID' },
          command: { type: 'string', description: 'PowerShell 命令' },
          timeoutSec: { type: 'number', description: '超时秒数，默认 120' },
        },
        output: {
          schema: { type: 'json' },
          render: (_args, value) => [{ type: 'text', text: '退出码 ' + value.exitCode + '\n' + String(value.stdout || '').slice(0, 2000) }],
        },
        async execute(args) {
          return execRemote(args)
        },
      }),
    )

    ctx.tools.register(
      defineTool({
        name: 'remote_relay_status',
        description: '查询已配对远程节点的系统状态（CPU、内存、运行时长、DSH 进程信息等），用于监督。',
        parameters: { nodeId: { type: 'string', description: '目标节点 ID' } },
        output: {
          schema: { type: 'json' },
          render: (_args, value) => [{ type: 'text', text: value.hostname + ' 内存 ' + value.memUsedPct + '% 负载 ' + value.load1 }],
        },
        async execute(args) {
          return authedFetch(args.nodeId, '/api/status', 'GET')
        },
      }),
    )

    ctx.tools.register(
      defineTool({
        name: 'remote_relay_screenshot',
        description: '截取已配对远程节点的屏幕并返回 PNG（base64）。用于远程监督/协助时了解对方面。',
        parameters: { nodeId: { type: 'string', description: '目标节点 ID' } },
        output: {
          schema: { type: 'json' },
          render: (_args, value) => [{ type: 'text', text: value.ok ? '截图 ' + value.bytes + ' 字节' : '截图失败: ' + value.error }],
        },
        async execute(args) {
          if (!cfg.allowScreenshot) throw new Error('本机已关闭远程截图')
          return authedFetch(args.nodeId, '/api/screenshot', 'GET')
        },
      }),
    )

    ctx.tools.register(
      defineTool({
        name: 'remote_relay_upload',
        description: '把本机文件上传到已配对的远程节点（保存到对面 ~/.dsh/remote-relay-inbox/），返回对面路径。',
        parameters: {
          nodeId: { type: 'string', description: '目标节点 ID' },
          localPath: { type: 'string', description: '本机文件绝对路径' },
          remoteName: { type: 'string', description: '可选。对面保存的文件名（默认同本机文件名）' },
        },
        output: {
          schema: { type: 'json' },
          render: (_args, value) => [{ type: 'text', text: '已上传 ' + (value.name || '') + ' → ' + (value.path || '') }],
        },
        async execute(args) {
          return transferFile(args)
        },
      }),
    )

    ctx.tools.register(
      defineTool({
        name: 'remote_relay_download',
        description: '从已配对的远程节点下载文件到本机（保存到指定 localPath 或临时目录），返回本机路径。',
        parameters: {
          nodeId: { type: 'string', description: '目标节点 ID' },
          remotePath: { type: 'string', description: '对面文件绝对路径' },
          localPath: { type: 'string', description: '可选。本机保存路径（默认临时目录）' },
        },
        output: {
          schema: { type: 'json' },
          render: (_args, value) => [{ type: 'text', text: '已下载 ' + (value.bytes || 0) + ' 字节 → ' + (value.path || '') }],
        },
        async execute(args) {
          return downloadFile(args)
        },
      }),
    )

    ctx.tools.register(
      defineTool({
        name: 'remote_relay_install_plugin',
        description:
          '一键在远程节点安装 DSH 插件：上传本机 tgz → 在对面的 profile 里 pnpm add + 修复 bundles 列表（无 BOM）。' +
          '安装后需重启对面 DSH 才生效。',
        parameters: {
          nodeId: { type: 'string', description: '目标节点 ID' },
          localPath: { type: 'string', description: '本机插件 tgz 绝对路径' },
          pluginName: { type: 'string', description: '可选。插件包名（默认 dsh-remote-relay）' },
        },
        output: {
          schema: { type: 'json' },
          render: (_args, value) =>
            [{ type: 'text', text: value.ok ? '安装成功，重启对面 DSH 生效' : '安装失败: ' + String((value.install && value.install.stderr) || '').slice(0, 500) }],
        },
        async execute(args) {
          return installPlugin(args)
        },
      }),
    )

    log('tools registered: 9')
  }

  // ---------------- HTTP 服务（对外，给其它节点） ----------------

  const server = http.createServer(async (req, res) => {
    const remote = req.socket.remoteAddress || ''
    if (!isPrivateIp(remote)) {
      return json(res, 403, { error: 'only private network clients allowed' })
    }
    const url = new URL(req.url || '/', 'http://localhost')
    try {
      if (req.method === 'GET' && url.pathname === '/api/identity') {
        return json(res, 200, identity(cfg))
      }

      if (req.method === 'POST' && url.pathname === '/api/pair') {
        const bodyText = await readBody(req)
        let body
        try {
          body = JSON.parse(bodyText)
        } catch {
          return json(res, 400, { error: 'invalid json' })
        }
        if (!cfg.allowControl) return json(res, 403, { error: '本机已关闭「允许控制本设备」' })
        const peerNodeId = String(body.nodeId || '')
        if (!peerNodeId) return json(res, 400, { error: 'nodeId required' })
        // 已配对：幂等返回 token
        if (cfg.peers[peerNodeId] && cfg.peers[peerNodeId].token) {
          cfg.peers[peerNodeId].host = remote
          saveConfig(cfg)
          return json(res, 200, {
            paired: true,
            auto: !!cfg.peers[peerNodeId].auto,
            nodeId: state.identity.nodeId,
            hostname: state.identity.hostname,
            token: cfg.peers[peerNodeId].token,
          })
        }
        const given = String(body.password || '')
        // 永久密码 / 临时密码：直接配对
        const viaPermanent = !!cfg.pairPassword && given === cfg.pairPassword
        const viaTemp = !viaPermanent && !!cfg.tempPassword && given === cfg.tempPassword
        if (viaPermanent || viaTemp) {
          const token = randomToken()
          cfg.peers[peerNodeId] = {
            nodeId: peerNodeId,
            hostname: String(body.hostname || ''),
            accountFp: String(body.accountFp || ''),
            host: remote,
            port: Number(body.callbackPort) || 0,
            token,
            pairedAt: new Date().toISOString(),
            auto: true,
            viaPassword: true,
          }
          if (viaTemp) cfg.tempPassword = randomCode() // 临时密码用一次即换
          saveConfig(cfg)
          log('paired via password:', peerNodeId, viaTemp ? '(temp)' : '(permanent)')
          return json(res, 200, {
            paired: true,
            auto: true,
            viaPassword: true,
            nodeId: state.identity.nodeId,
            hostname: state.identity.hostname,
            token,
          })
        }
        // 同账号：自动配对
        if (String(body.accountFp || '') === state.identity.accountFp) {
          const token = randomToken()
          cfg.peers[peerNodeId] = {
            nodeId: peerNodeId,
            hostname: String(body.hostname || ''),
            accountFp: String(body.accountFp || ''),
            host: remote,
            port: Number(body.callbackPort) || 0,
            token,
            pairedAt: new Date().toISOString(),
            auto: true,
          }
          saveConfig(cfg)
          log('auto paired (same account):', peerNodeId)
          return json(res, 200, { paired: true, auto: true, nodeId: state.identity.nodeId, hostname: state.identity.hostname, token })
        }
        // 不同账号：生成配对码，等本机确认
        const code = randomCode()
        cfg.pending[code] = {
          code,
          nodeId: peerNodeId,
          hostname: String(body.hostname || ''),
          accountFp: String(body.accountFp || ''),
          host: remote,
          port: Number(body.callbackPort) || 0,
          at: Date.now(),
        }
        saveConfig(cfg)
        log('pair request pending, code:', code, 'from:', peerNodeId)
        return json(res, 200, {
          paired: false,
          needApproval: true,
          code,
          nodeId: state.identity.nodeId,
          hint: '请在被协助方 DSH 设置页点「同意」，或调用 remote_relay_approve 传入配对码 ' + code,
        })
      }

      if (req.method === 'POST' && url.pathname === '/api/exec') {
        const bodyText = await readBody(req)
        const auth = verifyPeerRequest(cfg, req, bodyText)
        if (!auth.ok) return json(res, 401, { error: auth.error })
        if (!cfg.allowControl || !cfg.allowExec) return json(res, 403, { error: 'exec disabled' })
        let body
        try {
          body = JSON.parse(bodyText)
        } catch {
          return json(res, 400, { error: 'invalid json' })
        }
        const command = String(body.command || '')
        if (!command.trim()) return json(res, 400, { error: 'command required' })
        const timeoutMs = Math.min(Math.max(Number(body.timeoutSec) * 1000 || EXEC_TIMEOUT_MS, 1000), 10 * 60 * 1000)
        log('exec from', auth.peer.nodeId, 'cmd:', command.slice(0, 120))
        return json(res, 200, await runCommand(command, timeoutMs))
      }

      if (req.method === 'GET' && url.pathname === '/api/status') {
        const auth = verifyPeerRequest(cfg, req, '')
        if (!auth.ok) return json(res, 401, { error: auth.error })
        return json(res, 200, { ...systemStatus(cfg), nodeId: state.identity.nodeId })
      }

      if (req.method === 'GET' && url.pathname === '/api/screenshot') {
        const auth = verifyPeerRequest(cfg, req, '')
        if (!auth.ok) return json(res, 401, { error: auth.error })
        if (!cfg.allowControl || !cfg.allowScreenshot) return json(res, 403, { error: 'screenshot disabled' })
        const shot = await takeScreenshot()
        return json(res, shot.ok ? 200 : 500, shot)
      }

      if (req.method === 'POST' && url.pathname === '/api/inject') {
        const bodyText = await readBody(req)
        const auth = verifyPeerRequest(cfg, req, bodyText)
        if (!auth.ok) return json(res, 401, { error: auth.error })
        if (!cfg.allowControl || !cfg.allowInject) return json(res, 403, { error: 'inject disabled' })
        let body
        try {
          body = JSON.parse(bodyText)
        } catch {
          return json(res, 400, { error: 'invalid json' })
        }
        const text = String(body.text || '').slice(0, 4000)
        if (!text) return json(res, 400, { error: 'text required' })
        state.injected = state.injected || []
        state.injected.push({ from: auth.peer.nodeId, text, at: Date.now() })
        if (state.injected.length > 20) state.injected.shift()
        log('inject from', auth.peer.nodeId, ':', text.slice(0, 120))
        return json(res, 200, { ok: true })
      }

      if (req.method === 'POST' && url.pathname === '/api/transfer') {
        const bodyText = await readBody(req, TRANSFER_LIMIT)
        const auth = verifyPeerRequest(cfg, req, bodyText)
        if (!auth.ok) return json(res, 401, { error: auth.error })
        let body
        try {
          body = JSON.parse(bodyText)
        } catch {
          return json(res, 400, { error: 'invalid json' })
        }
        const name = safeFileName(body.name || 'file.bin')
        let data
        try {
          data = Buffer.from(String(body.data || ''), 'base64')
        } catch {
          return json(res, 400, { error: 'invalid base64' })
        }
        if (!data.length) return json(res, 400, { error: 'empty data' })
        if (data.length > TRANSFER_LIMIT) return json(res, 413, { error: 'file too large' })
        const dir = ensureInbox()
        let target = path.join(dir, name)
        if (fs.existsSync(target)) target = path.join(dir, Date.now() + '-' + name)
        fs.writeFileSync(target, data)
        log('transfer received:', target, data.length)
        return json(res, 200, { ok: true, path: target, name: path.basename(target), bytes: data.length })
      }

      if (req.method === 'GET' && url.pathname === '/api/transfer') {
        const auth = verifyPeerRequest(cfg, req, '')
        if (!auth.ok) return json(res, 401, { error: auth.error })
        const remotePath = String(url.searchParams.get('path') || '')
        if (!remotePath) return json(res, 400, { error: 'path required' })
        try {
          const st = fs.statSync(remotePath)
          if (!st.isFile()) return json(res, 400, { error: 'not a file' })
          if (st.size > TRANSFER_LIMIT) return json(res, 413, { error: 'file too large' })
          const buf = fs.readFileSync(remotePath)
          return json(res, 200, { ok: true, name: path.basename(remotePath), data: buf.toString('base64'), bytes: buf.length })
        } catch (err) {
          return json(res, 404, { error: 'file not found: ' + String(err.message || err) })
        }
      }

      return json(res, 404, { error: 'not found' })
    } catch (err) {
      log('request error:', err.message)
      return json(res, 500, { error: String(err.message || err) })
    }
  })

  server.on('error', (err) => log('http server error:', err.message))
  server.listen(cfg.port, '0.0.0.0', () => {
    log('listening on 0.0.0.0:' + cfg.port, 'node:', state.identity.nodeId, 'alias:', state.identity.hostname)
  })
  state.server = server

  startDiscovery(cfg, state)

  // ---------------- 同源 WebServer 路由（设置页用） ----------------
  const sendJson = (res, code, body) => {
    try {
      res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
      res.end(JSON.stringify(body))
    } catch {
      /* 响应已结束 */
    }
  }
  const isLoopbackRequest = (req) => {
    const addr = String(req.socket.remoteAddress || '')
    return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1'
  }
  const denyForeignOrigin = (req, res) => {
    const origin = req.headers.origin
    if (!origin) return false
    const host = req.headers.host || ''
    try {
      if (new URL(origin).host === host) return false
    } catch {
      /* 非法 origin */
    }
    sendJson(res, 403, { error: 'origin not allowed' })
    return true
  }
  // 设置页数据源：脱敏（不返回账号指纹、不返回监听端口；nodeId 供「连接设备」使用）
  const publicState = () => ({
    identity: {
      nodeId: state.identity.nodeId,
      alias: state.identity.hostname,
      user: state.identity.user,
      platform: state.identity.platform,
    },
    peers: Object.values(cfg.peers).map((p) => ({
      nodeId: p.nodeId,
      hostname: p.hostname,
      host: p.host,
      pairedAt: p.pairedAt,
      auto: !!p.auto,
      viaPassword: !!p.viaPassword,
    })),
    pending: Object.values(cfg.pending).map((p) => ({ code: p.code, nodeId: p.nodeId, hostname: p.hostname, host: p.host, at: p.at })),
    password: cfg.pairPassword || '',
    tempPassword: cfg.tempPassword || '',
    allowControl: cfg.allowControl !== false,
    inbox: INBOX_PATH(),
    options: { allowExec: cfg.allowExec, allowScreenshot: cfg.allowScreenshot, allowInject: cfg.allowInject },
  })

  const registerWebRoutes = () => {
    const ws = ctx.webServer ?? (typeof ctx.get === 'function' ? ctx.get('webServer') : undefined)
    if (!ws || typeof ws.register !== 'function') {
      log('webServer 未就绪，跳过设置页路由')
      return
    }
    const addRoute = (path, method, handler) => {
      const disposer = ws.register({
        kind: 'exact',
        path,
        async handler(req, res) {
          try {
            if (!isLoopbackRequest(req)) return sendJson(res, 403, { error: 'loopback only' })
            if (req.method !== method) return sendJson(res, 405, { error: 'method not allowed' })
            if (denyForeignOrigin(req, res)) return
            await handler(req, res)
          } catch (err) {
            sendJson(res, 500, { error: String((err && err.message) || err) })
          }
        },
      })
      if (typeof disposer === 'function' && typeof ctx.effect === 'function') {
        ctx.effect(() => disposer)
      }
    }
    addRoute('/dsh-remote-relay/state', 'GET', async (req, res) => sendJson(res, 200, publicState()))
    addRoute('/dsh-remote-relay/alias', 'POST', async (req, res) => {
      const body = JSON.parse((await readBody(req)) || '{}')
      const alias = String(body.alias || '').trim().slice(0, 32)
      cfg.alias = alias || os.hostname()
      saveConfig(cfg)
      state.identity = identity(cfg)
      sendJson(res, 200, { ok: true, alias: state.identity.hostname })
    })
    addRoute('/dsh-remote-relay/temp-password', 'POST', async (req, res) => {
      const pw = refreshTempPassword()
      sendJson(res, 200, { ok: true, tempPassword: pw })
    })
    addRoute('/dsh-remote-relay/password', 'POST', async (req, res) => {
      const body = JSON.parse((await readBody(req)) || '{}')
      const action = String(body.action || '')
      if (action === 'set') {
        const pw = String(body.password || '').trim()
        if (pw.length > 64) return sendJson(res, 400, { error: '密码过长' })
        cfg.pairPassword = pw
        saveConfig(cfg)
        return sendJson(res, 200, { ok: true, password: cfg.pairPassword })
      }
      if (action === 'generate') {
        cfg.pairPassword = crypto.randomBytes(12).toString('base64url').slice(0, 16)
        saveConfig(cfg)
        return sendJson(res, 200, { ok: true, password: cfg.pairPassword })
      }
      if (action === 'clear') {
        cfg.pairPassword = ''
        saveConfig(cfg)
        return sendJson(res, 200, { ok: true, password: '' })
      }
      return sendJson(res, 400, { error: 'unknown action' })
    })
    addRoute('/dsh-remote-relay/control', 'POST', async (req, res) => {
      const body = JSON.parse((await readBody(req)) || '{}')
      if (typeof body.allowControl === 'boolean') cfg.allowControl = body.allowControl
      saveConfig(cfg)
      sendJson(res, 200, { ok: true, allowControl: cfg.allowControl !== false })
    })
    addRoute('/dsh-remote-relay/options', 'POST', async (req, res) => {
      const body = JSON.parse((await readBody(req)) || '{}')
      for (const key of ['allowExec', 'allowScreenshot', 'allowInject']) {
        if (typeof body[key] === 'boolean') cfg[key] = body[key]
      }
      saveConfig(cfg)
      sendJson(res, 200, { ok: true, options: publicState().options })
    })
    addRoute('/dsh-remote-relay/approve', 'POST', async (req, res) => {
      const body = JSON.parse((await readBody(req)) || '{}')
      const out = approvePending(String(body.code || '').trim())
      sendJson(res, out.ok ? 200 : 400, out)
    })
    addRoute('/dsh-remote-relay/reject', 'POST', async (req, res) => {
      const body = JSON.parse((await readBody(req)) || '{}')
      const code = String(body.code || '').trim()
      if (cfg.pending[code]) {
        delete cfg.pending[code]
        saveConfig(cfg)
      }
      sendJson(res, 200, { ok: true })
    })
    addRoute('/dsh-remote-relay/unpair', 'POST', async (req, res) => {
      const body = JSON.parse((await readBody(req)) || '{}')
      const nid = String(body.nodeId || '')
      if (cfg.peers[nid]) {
        delete cfg.peers[nid]
        saveConfig(cfg)
      }
      sendJson(res, 200, { ok: true })
    })
    addRoute('/dsh-remote-relay/connect', 'POST', async (req, res) => {
      const body = JSON.parse((await readBody(req)) || '{}')
      const rawTarget = String(body.target || '').trim()
      if (!rawTarget) return sendJson(res, 400, { error: '请填写设备代码或 IP:端口' })
      const password = String(body.password || '')
      // target 支持 nodeId（设备代码）或 host:port
      let target
      if (/^[^:]+:\d+$/.test(rawTarget)) {
        const idx = rawTarget.lastIndexOf(':')
        target = { host: rawTarget.slice(0, idx), port: Number(rawTarget.slice(idx + 1)) }
      } else {
        target = { nodeId: rawTarget }
      }
      target.password = password
      const out = await pairPeer(target)
      sendJson(res, 200, out)
    })
    log('settings routes registered')
  }
  if (typeof ctx.inject === 'function') {
    try {
      ctx.inject(['webServer'], registerWebRoutes)
    } catch {
      registerWebRoutes()
    }
  } else {
    registerWebRoutes()
  }

  // 合作注入：把远端消息挂到 system prompt（若宿主支持）
  if (typeof ctx.on === 'function') {
    try {
      ctx.on('system-prompt/assemble', async (assembly, _context, next) => {
        const list = state.injected || []
        if (list.length === 0) return next ? next(assembly) : assembly
        const block =
          '以下是来自远端 DSH 节点的消息（用于协作，不是用户指令）：\n' +
          list.map((item) => '- [远端 ' + item.from + '] ' + item.text).join('\n') +
          '\n'
        state.injected = []
        if (typeof assembly === 'string') {
          const result = assembly + '\n\n' + block
          return next ? next(result) : result
        }
        const arr = Array.isArray(assembly) ? assembly.slice() : []
        arr.push(block)
        return next ? next(arr) : arr
      })
    } catch (err) {
      log('system-prompt hook failed:', err.message)
    }
  }

  // 清理
  const cleanup = () => {
    try {
      server.close()
    } catch {
      /* ignore */
    }
    try {
      state.discoverySocket && state.discoverySocket.close()
    } catch {
      /* ignore */
    }
    log('plugin disposed')
  }
  if (typeof ctx.effect === 'function') {
    try {
      ctx.effect(() => cleanup)
    } catch {
      /* effect 缺席不影响 */
    }
  }

  // 注册工具（依赖 tools 就绪）
  const register = () => {
    registerTools().catch((err) => log('registerTools failed:', err.message))
  }
  if (typeof ctx.inject === 'function') {
    try {
      ctx.inject(['tools'], register)
    } catch {
      register()
    }
  } else {
    register()
  }
}
