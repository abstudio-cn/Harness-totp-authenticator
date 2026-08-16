/**
 * TOTP Authenticator + Critical-Operation Gate + First-Use Binding
 * — DSH (DeepSeek Harness) dynamic Cordis Plugin
 * =====================================================================
 * Conversion of the openclaw skill (scripts/totp.py + scripts/totp.js)
 * into a Harness dynamic Plugin. Registers four Host tools and one
 * pre-execution guard:
 *
 *   1. `totp`             — RFC 6238 TOTP code generator (base32 secret
 *                           or otpauth:// URI, digits/interval/verify/time).
 *   2. `totp_gate_bind`   — FIRST-USE BINDING, step 1: generates a new
 *                           secret key, persists it locally in the plugin
 *                           directory (state file .totp-gate.json), and
 *                           emits a scannable QR code (SVG file
 *                           totp-gate-qrcode.svg + Unicode preview) plus a
 *                           manual-entry key and otpauth:// URI. Tells the
 *                           user to add the account in Microsoft
 *                           Authenticator or Google Authenticator.
 *   3. `totp_gate_confirm` — step 2: verifies the 6-digit code the user
 *                           read from their authenticator app (±1 time
 *                           step); on success the binding becomes active.
 *   4. `totp_gate_unlock` — submits the user's authenticator code to
 *                           unlock ONE blocked critical operation (one-shot,
 *                           expires after GATE_WINDOW_MS = 90 s).
 *   5. tools/pre-execute guard — blocks destructive pwsh/bash commands
 *                           (recursive deletion, wildcard deletion, disk
 *                           formatting, git clean/reset --hard, robocopy
 *                           /MIR, find -delete, dd/mkfs/shred, ...).
 *                           Before first binding it denies with binding
 *                           instructions; after binding it requires an
 *                           unlock for every critical operation.
 *
 * Why pure JavaScript: dynamic Host code runs in a restricted VM realm
 * with no Node `crypto` module, no `Buffer`, and no subprocess access —
 * so SHA-1, HMAC-SHA1, HOTP, base32, and even the QR encoder (byte mode,
 * EC level L, versions 1..6, mask 0, Reed-Solomon) are implemented inline
 * (standard ECMAScript only: Math, Date, String).
 *
 * Persistence: the state file and QR SVG are written through the Host fs
 * service into the plugin directory under the session workspace
 * (`<session cwd>/totp-authenticator/.totp-gate.json`), resolved from
 * exec.agent.session.header.cwd — the same source the official fs tools
 * use. If the fs service is unavailable the gate still works in-memory
 * for the lifetime of the Plugin run.
 *
 * Verified:
 *   - TOTP: RFC 6238 Appendix B vectors (T=59 -> 94287082, ...) and the
 *     Google demo vector (JBSWY3DPEHPK3PXP @ t=0 -> 282760).
 *   - QR: decoded successfully by OpenCV QRCodeDetector; module matrix
 *     byte-identical to the python-qrcode reference (optimize=0, v6-L,
 *     mask 0) including the Reed-Solomon ECC.
 *   - Gate: recursive delete denied before binding, denied while locked,
 *     allowed once after totp_gate_unlock, denied again afterwards.
 *
 * ⚠ Honest scope: this is a safety interlock against accidental
 * destructive commands, not a security boundary against a malicious
 * agent — the agent owns the plugin and can stop it or read the files.
 * The intended flow involves a HUMAN reading the code from their phone.
 *
 * Loading into the harness (session-scoped, process-local):
 *   1. cordis_define with this file's content below the header as
 *      `code.host` (it is a plain-JS function body returning the Plugin).
 *   2. cordis_run with the returned pluginId/packageId.
 * The tools and guard disappear when the plugin is stopped or the
 * process restarts (the state file keeps the binding across restarts).
 */

// =====================================================================
// GATE CONFIGURATION
// =====================================================================
const GATE_DIGITS = 6
const GATE_INTERVAL = 30
const GATE_WINDOW_MS = 90000 // an unlock authorizes ONE critical op, retried within 90 s
const GATE_ISSUER = 'DSH'
const GATE_LABEL = 'totp-gate'
const GATE_DIR = 'totp-authenticator' // plugin directory, resolved against the session cwd
const STATE_FILE = '.totp-gate.json'
const QR_FILE = 'totp-gate-qrcode.svg'

// Tool names whose commands are scanned for destructive patterns.
const GATED_TOOLS = ['pwsh', 'bash', 'bash-persistent']

// Destructive command patterns (case-insensitive). Any match blocks the call.
const CRITICAL_PATTERNS = [
  /\b(remove-item|rm|ri|rd)\b[^\r\n]*(?:-recurse|-rf?\b)/i,
  /\brm\s+(?:-[a-z]*r[a-z]*|-r\b|--recursive)\b/i,
  /\b(rd|rmdir|deltree)\b[^\r\n]*\/s\b/i,
  /\b(del|erase)\b[^\r\n]*\/s\b/i,
  /\b(remove-item|rm|ri|del|erase)\b[^\r\n]*\*/i,
  /\|+\s*(?:remove-item|rm|ri|del|erase)\b/i,
  /\[\s*(?:system\.)?io\.directory\s*\]\s*::\s*delete\s*\([^,]+,\s*\$?true\)/i,
  /\b(format-volume|clear-disk|initialize-disk|remove-partition)\b/i,
  /\bformat\s+[a-z]:/i,
  /\bdiskpart\b/i,
  /\bgit\s+clean\b[^\r\n]*\s-f/i,
  /\bgit\s+reset\s+--hard\b/i,
  /\brobocopy\b[^\r\n]*\/mir\b/i,
  /\bfind\s[^\r\n]*(?:-delete|-exec\s+rm\b)/i,
  /\bdd\s+if=/i,
  /\bmkfs\.?\w*\b/i,
  /\b(shred|sdelete)\b/i
]

// ---- RFC 4648 base32 (decode + encode) ----
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32Decode(input) {
  const s = String(input).replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase()
  let bits = 0
  let bitsLen = 0
  const out = []
  for (let i = 0; i < s.length; i++) {
    const ch = s.charAt(i)
    const idx = B32.indexOf(ch)
    if (idx === -1) throw new Error('invalid base32 character "' + ch + '" in secret')
    bits = (bits << 5) | idx
    bitsLen += 5
    if (bitsLen >= 8) {
      bitsLen -= 8
      out.push((bits >>> bitsLen) & 0xff)
    }
  }
  if (out.length === 0) throw new Error('secret decoded to an empty key')
  return out
}

function base32Encode(bytes) {
  let bits = 0
  let bitsLen = 0
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    bits = (bits << 8) | (bytes[i] & 0xff)
    bitsLen += 8
    while (bitsLen >= 5) {
      bitsLen -= 5
      out += B32[(bits >>> bitsLen) & 31]
    }
  }
  if (bitsLen > 0) out += B32[(bits << (5 - bitsLen)) & 31]
  return out
}

// ---- random secret bytes: webcrypto when present, else V8 PRNG mixed with time jitter ----
function randomBytes(n) {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    const arr = new Uint8Array(n)
    globalThis.crypto.getRandomValues(arr)
    const out = []
    for (let i = 0; i < n; i++) out.push(arr[i])
    return out
  }
  const out = []
  let seed = (Date.now() * 2654435761) >>> 0
  for (let i = 0; i < n; i++) {
    seed ^= seed << 13
    seed ^= seed >>> 17
    seed ^= seed << 5
    seed = seed >>> 0
    const t = Date.now() % 65536
    out.push((Math.floor(Math.random() * 256) ^ (seed & 0xff) ^ (t & 0xff)) & 0xff)
  }
  return out
}

// ---- pure-JS SHA-1 (FIPS 180-1): byte array in, byte array out ----
function rotl32(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0
}

function sha1Bytes(bytes) {
  const padded = bytes.slice()
  padded.push(0x80)
  while (padded.length % 64 !== 56) padded.push(0)
  const bitLen = bytes.length * 8
  const hi = Math.floor(bitLen / 0x100000000)
  const lo = bitLen >>> 0
  for (let i = 3; i >= 0; i--) padded.push((hi >>> (i * 8)) & 0xff)
  for (let i = 3; i >= 0; i--) padded.push((lo >>> (i * 8)) & 0xff)
  let h0 = 0x67452301
  let h1 = 0xefcdab89
  let h2 = 0x98badcfe
  let h3 = 0x10325476
  let h4 = 0xc3d2e1f0
  const w = new Array(80)
  for (let off = 0; off < padded.length; off += 64) {
    for (let t = 0; t < 16; t++) {
      const j = off + t * 4
      w[t] = ((padded[j] << 24) | (padded[j + 1] << 16) | (padded[j + 2] << 8) | padded[j + 3]) >>> 0
    }
    for (let t = 16; t < 80; t++) w[t] = rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1)
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4
    for (let t = 0; t < 80; t++) {
      let f
      let k
      if (t < 20) {
        f = (b & c) | (~b & d)
        k = 0x5a827999
      } else if (t < 40) {
        f = b ^ c ^ d
        k = 0x6ed9eba1
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d)
        k = 0x8f1bbcdc
      } else {
        f = b ^ c ^ d
        k = 0xca62c1d6
      }
      const temp = (rotl32(a, 5) + f + e + k + w[t]) >>> 0
      e = d
      d = c
      c = rotl32(b, 30)
      b = a
      a = temp
    }
    h0 = (h0 + a) >>> 0
    h1 = (h1 + b) >>> 0
    h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0
  }
  const out = []
  const words = [h0, h1, h2, h3, h4]
  for (let i = 0; i < words.length; i++) {
    const word = words[i]
    out.push((word >>> 24) & 0xff, (word >>> 16) & 0xff, (word >>> 8) & 0xff, word & 0xff)
  }
  return out
}

// ---- RFC 2104 HMAC-SHA1 ----
function hmacSha1Bytes(key, msg) {
  let k = key.slice()
  if (k.length > 64) k = sha1Bytes(k)
  const inner = []
  const outer = []
  for (let i = 0; i < 64; i++) {
    const b = i < k.length ? k[i] : 0
    inner.push(b ^ 0x36)
    outer.push(b ^ 0x5c)
  }
  for (let i = 0; i < msg.length; i++) inner.push(msg[i])
  const innerHash = sha1Bytes(inner)
  for (let i = 0; i < innerHash.length; i++) outer.push(innerHash[i])
  return sha1Bytes(outer)
}

// ---- RFC 4226 HOTP ----
function hotp(key, counter, digits) {
  const msg = [0, 0, 0, 0, 0, 0, 0, 0]
  let c = Math.floor(counter)
  for (let i = 7; i >= 0; i--) {
    msg[i] = c % 256
    c = Math.floor(c / 256)
  }
  const digest = hmacSha1Bytes(key, msg)
  const offset = digest[19] & 0x0f
  const truncated = ((digest[offset] & 0x7f) * 0x1000000) +
    ((digest[offset + 1] & 0xff) * 0x10000) +
    ((digest[offset + 2] & 0xff) * 0x100) +
    (digest[offset + 3] & 0xff)
  const code = truncated % Math.pow(10, digits)
  return String(code).padStart(digits, '0')
}

// ---- otpauth:// URI parsing ----
function parseOtpauthUri(uri) {
  if (!uri.startsWith('otpauth://')) throw new Error('not an otpauth:// URI')
  let rest = uri.slice('otpauth://'.length)
  const slash = rest.indexOf('/')
  if (slash === -1) throw new Error('not a valid otpauth://totp URI')
  const type = rest.slice(0, slash)
  if (type !== 'totp') throw new Error('unsupported otpauth type "' + type + '" (only totp is supported)')
  rest = rest.slice(slash + 1)
  const qIndex = rest.indexOf('?')
  const labelPart = qIndex === -1 ? rest : rest.slice(0, qIndex)
  const query = qIndex === -1 ? '' : rest.slice(qIndex + 1)
  const params = {}
  const pairs = query.split('&')
  for (let i = 0; i < pairs.length; i++) {
    const pair = pairs[i]
    if (pair === '') continue
    const eq = pair.indexOf('=')
    const rawKey = eq === -1 ? pair : pair.slice(0, eq)
    const rawVal = eq === -1 ? '' : pair.slice(eq + 1)
    let key
    let val
    try {
      key = decodeURIComponent(rawKey)
      val = decodeURIComponent(rawVal)
    } catch (err) {
      throw new Error('malformed percent-encoding in otpauth URI')
    }
    params[key] = val
  }
  if (typeof params.secret !== 'string' || params.secret === '') throw new Error('otpauth URI has no secret')
  let label = labelPart
  try {
    label = decodeURIComponent(labelPart)
  } catch (err) {
    throw new Error('malformed label encoding in otpauth URI')
  }
  const issuer = typeof params.issuer === 'string' && params.issuer !== '' ? params.issuer : undefined
  const algorithm = typeof params.algorithm === 'string' ? params.algorithm.toUpperCase() : 'SHA1'
  if (algorithm !== 'SHA1') throw new Error('unsupported otpauth algorithm "' + algorithm + '" (only SHA1 is supported)')
  const digits = typeof params.digits === 'string' && params.digits !== '' ? Number(params.digits) : undefined
  const period = typeof params.period === 'string' && params.period !== '' ? Number(params.period) : undefined
  return { secret: params.secret, issuer: issuer, label: label, digits: digits, period: period }
}

// =====================================================================
// Minimal QR encoder: byte mode, EC level L, versions 1..6, mask 0.
// Output: 0/1 module matrix (no quiet zone).
// =====================================================================
const QR_CAPACITY_L = [0, 17, 32, 53, 78, 106, 134] // byte-mode payload capacity, version selection only
const QR_BLOCKS_L = {
  1: [[19, 7]],
  2: [[34, 10]],
  3: [[55, 15]],
  4: [[80, 20]],
  5: [[108, 26]],
  6: [[68, 18], [68, 18]]
}
const QR_ALIGN = { 1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34] }
const GF_EXP = new Array(512)
const GF_LOG = new Array(256)
;(function () {
  let x = 1
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x
    GF_LOG[x] = i
    x <<= 1
    if (x & 0x100) x ^= 0x11d
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255]
})()

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0
  return GF_EXP[GF_LOG[a] + GF_LOG[b]]
}

// generator polynomial, coefficients HIGH-to-LOW, monic (leading 1)
function rsGeneratorHi(degree) {
  let poly = [1]
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0)
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j] // multiply by x
      next[j + 1] ^= gfMul(poly[j], GF_EXP[i]) // multiply by alpha^i
    }
    poly = next
  }
  return poly
}

// Reed-Solomon remainder: polynomial long division, coefficients high-to-low.
// Returns the eccLen remainder bytes (lowest-degree coefficients, zero-padded).
function rsEncode(data, eccLen) {
  const gen = rsGeneratorHi(eccLen)
  let working = data.slice()
  for (let i = 0; i < eccLen; i++) working.push(0) // data * x^eccLen
  const genLen = gen.length
  while (working.length >= genLen) {
    const ratio = ((GF_LOG[working[0]] - GF_LOG[gen[0]]) % 255 + 255) % 255
    const tmp = []
    for (let i = 0; i < genLen; i++) tmp.push(working[i] ^ gfMul(gen[i], GF_EXP[ratio]))
    working = tmp.concat(working.slice(genLen))
    let lead = 0
    while (lead < working.length && working[lead] === 0) lead++
    working = working.slice(lead)
  }
  const ecc = []
  for (let i = 0; i < eccLen - working.length; i++) ecc.push(0)
  for (let i = 0; i < working.length; i++) ecc.push(working[i])
  return ecc
}

function qrCodewords(text, version) {
  const payloadCapacity = QR_CAPACITY_L[version]
  // total data codewords for the RS blocks (pad target, NOT the payload capacity)
  let totalData = 0
  const specs = QR_BLOCKS_L[version]
  for (let i = 0; i < specs.length; i++) totalData += specs[i][0]
  const bytes = []
  for (let i = 0; i < text.length; i++) {
    let c = text.charCodeAt(i)
    if (c > 255) c = 0x3f
    bytes.push(c)
  }
  if (bytes.length > payloadCapacity) throw new Error('QR payload too long for version ' + version)
  const bits = []
  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1)
  }
  pushBits(4, 4) // byte mode indicator
  pushBits(bytes.length, 8) // 8-bit count for versions 1..9
  for (let i = 0; i < bytes.length; i++) pushBits(bytes[i], 8)
  const term = Math.min(4, totalData * 8 - bits.length)
  for (let i = 0; i < term; i++) bits.push(0)
  while (bits.length % 8 !== 0) bits.push(0)
  const data = []
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j]
    data.push(b)
  }
  const pads = [0xec, 0x11]
  let p = 0
  while (data.length < totalData) {
    data.push(pads[p])
    p = (p + 1) % 2
  }
  return data
}

function qrBlocks(text, version) {
  const data = qrCodewords(text, version)
  const specs = QR_BLOCKS_L[version]
  const blocks = []
  let offset = 0
  for (let i = 0; i < specs.length; i++) {
    const d = specs[i][0]
    const e = specs[i][1]
    const block = data.slice(offset, offset + d)
    offset += d
    blocks.push({ data: block, ecc: rsEncode(block, e) })
  }
  const out = []
  let maxD = 0
  let maxE = 0
  for (let i = 0; i < blocks.length; i++) {
    if (blocks[i].data.length > maxD) maxD = blocks[i].data.length
    if (blocks[i].ecc.length > maxE) maxE = blocks[i].ecc.length
  }
  for (let i = 0; i < maxD; i++) {
    for (let b = 0; b < blocks.length; b++) if (i < blocks[b].data.length) out.push(blocks[b].data[i])
  }
  for (let i = 0; i < maxE; i++) {
    for (let b = 0; b < blocks.length; b++) if (i < blocks[b].ecc.length) out.push(blocks[b].ecc[i])
  }
  const remainderBits = version >= 2 && version <= 6 ? 7 : 0
  return { codewords: out, remainderBits: remainderBits }
}

function drawFinder(m, top, left) {
  const size = m.length
  for (let r = 0; r < 7; r++) {
    for (let c = 0; c < 7; c++) {
      const dark = r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4)
      m[top + r][left + c] = dark ? 1 : 0
    }
  }
  for (let i = -1; i <= 7; i++) {
    const rr = top + i
    if (rr >= 0 && rr < size) {
      if (left - 1 >= 0) m[rr][left - 1] = 0
      if (left + 7 < size) m[rr][left + 7] = 0
    }
    const cc = left + i
    if (cc >= 0 && cc < size) {
      if (top - 1 >= 0) m[top - 1][cc] = 0
      if (top + 7 < size) m[top + 7][cc] = 0
    }
  }
}

function drawTiming(m) {
  const size = m.length
  for (let i = 8; i < size - 8; i++) {
    const bit = i % 2 === 0 ? 1 : 0
    if (m[6][i] === null) m[6][i] = bit
    if (m[i][6] === null) m[i][6] = bit
  }
}

function drawAlignment(m, r, c) {
  const size = m.length
  for (let dr = -2; dr <= 2; dr++) {
    for (let dc = -2; dc <= 2; dc++) {
      const rr = r + dr
      const cc = c + dc
      if (rr < 0 || cc < 0 || rr >= size || cc >= size) continue
      const dark = Math.max(Math.abs(dr), Math.abs(dc)) !== 1
      m[rr][cc] = dark ? 1 : 0
    }
  }
}

function qrFormatBits(ecLevel, mask) {
  const data = (ecLevel << 3) | mask
  let g = data << 10
  const gen = 0x537
  for (let i = 14; i >= 10; i--) {
    if (g & (1 << i)) g ^= gen << (i - 10)
  }
  return ((data << 10) | g) ^ 0x5412
}

function drawFormat(m, bits) {
  const size = m.length
  for (let i = 0; i <= 5; i++) m[i][8] = (bits >> i) & 1
  m[7][8] = (bits >> 6) & 1
  m[8][8] = (bits >> 7) & 1
  m[8][7] = (bits >> 8) & 1
  for (let i = 9; i <= 14; i++) m[8][14 - i] = (bits >> i) & 1
  for (let i = 0; i <= 7; i++) m[8][size - 1 - i] = (bits >> i) & 1
  for (let i = 8; i <= 14; i++) m[size - 15 + i][8] = (bits >> i) & 1
  m[size - 8][8] = 1 // dark module
}

function qrMatrix(text) {
  let version = 0
  for (let v = 1; v <= 6; v++) {
    if (text.length <= QR_CAPACITY_L[v]) {
      version = v
      break
    }
  }
  if (version === 0) throw new Error('QR payload too long')
  const size = 17 + version * 4
  const m = []
  for (let r = 0; r < size; r++) m.push(new Array(size).fill(null))
  drawFinder(m, 0, 0)
  drawFinder(m, 0, size - 7)
  drawFinder(m, size - 7, 0)
  drawTiming(m)
  const aligns = QR_ALIGN[version]
  for (let i = 0; i < aligns.length; i++) {
    for (let j = 0; j < aligns.length; j++) {
      const r = aligns[i]
      const c = aligns[j]
      const nearFinder = (r === 6 && c === 6) || (r === 6 && c === size - 7) || (r === size - 7 && c === 6)
      if (!nearFinder) drawAlignment(m, r, c)
    }
  }
  drawFormat(m, qrFormatBits(1, 0)) // EC level L (01), mask 0
  const isFunction = []
  for (let r = 0; r < size; r++) {
    const row = []
    for (let c = 0; c < size; c++) row.push(m[r][c] !== null)
    isFunction.push(row)
  }
  const encoded = qrBlocks(text, version)
  const bits = []
  for (let i = 0; i < encoded.codewords.length; i++) {
    for (let j = 7; j >= 0; j--) bits.push((encoded.codewords[i] >>> j) & 1)
  }
  for (let i = 0; i < encoded.remainderBits; i++) bits.push(0)
  let bit = 0
  let col = size - 1
  let upward = true
  while (col > 0) {
    if (col === 6) col--
    for (let k = 0; k < size; k++) {
      const row = upward ? size - 1 - k : k
      for (let dc = 0; dc < 2; dc++) {
        const c = col - dc
        if (!isFunction[row][c]) {
          m[row][c] = bit < bits.length ? bits[bit] : 0
          bit++
        }
      }
    }
    upward = !upward
    col -= 2
  }
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!isFunction[r][c] && (r + c) % 2 === 0) m[r][c] ^= 1 // mask 0
    }
  }
  return m
}

function qrToSvg(matrix) {
  const size = matrix.length
  const quiet = 4
  const dim = size + quiet * 2
  const rects = []
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c] === 1) rects.push('M' + (c + quiet) + ' ' + (r + quiet) + 'h1v1h-1z')
    }
  }
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + dim + ' ' + dim + '" shape-rendering="crispEdges"><rect width="' + dim + '" height="' + dim + '" fill="#fff"/><path d="' + rects.join('') + '" fill="#000"/></svg>'
}

function qrToUnicode(matrix) {
  const size = matrix.length
  const quiet = 2
  const lines = []
  const blank = '  '.repeat(size + quiet * 2)
  for (let i = 0; i < quiet; i++) lines.push(blank)
  for (let r = 0; r < size; r++) {
    let line = ''
    for (let i = 0; i < quiet; i++) line += '  '
    for (let c = 0; c < size; c++) line += matrix[r][c] === 1 ? '██' : '  '
    for (let i = 0; i < quiet; i++) line += '  '
    lines.push(line)
  }
  for (let i = 0; i < quiet; i++) lines.push(blank)
  return lines.join('\n')
}

return {
  name: 'totp-authenticator',
  apply(ctx) {
    // ---- persisted gate state, loaded lazily ----
    const state = { bound: false, secret: null, pendingSecret: null, pendingAt: 0, boundAt: 0 }
    let unlockedUntil = 0
    let unlockConsumed = false
    let readyPromise = null

    const fsService = () => ctx.get('fs')

    // session cwd from the tool execution (same source the official fs tools use)
    const sessionCwd = (exec) => {
      try {
        const agent = exec && exec.agent
        const header = agent && agent.session && agent.session.header
        if (header && typeof header.cwd === 'string' && header.cwd !== '') return header.cwd
      } catch (err) {
        /* fall through */
      }
      return undefined
    }

    const gateFile = async (name, exec) => {
      const fs = fsService()
      if (fs === undefined) return null
      try {
        const cwd = sessionCwd(exec)
        const target = cwd !== undefined ? await fs.resolve(GATE_DIR + '/' + name, { cwd: cwd }) : await fs.resolve(GATE_DIR + '/' + name)
        return { fs: fs, target: target }
      } catch (err) {
        return null
      }
    }

    const persistState = async (exec) => {
      const file = await gateFile(STATE_FILE, exec)
      if (file === null) return false
      try {
        const json = JSON.stringify({
          version: 1,
          bound: state.bound,
          secret: state.bound ? state.secret : null,
          pendingSecret: state.pendingSecret,
          boundAt: state.boundAt
        })
        await file.fs.writeText(file.target, json)
        return true
      } catch (err) {
        console.error('totp-gate: could not persist state:', err && err.message ? err.message : String(err))
        return false
      }
    }

    const ready = (exec) => {
      if (readyPromise === null) {
        readyPromise = (async () => {
          const file = await gateFile(STATE_FILE, exec)
          if (file === null) return state
          try {
            const text = await file.fs.readText(file.target)
            const parsed = JSON.parse(text)
            if (parsed && typeof parsed === 'object' && parsed.version === 1) {
              if (parsed.bound === true && typeof parsed.secret === 'string' && parsed.secret !== '') {
                state.bound = true
                state.secret = parsed.secret
                state.boundAt = typeof parsed.boundAt === 'number' ? parsed.boundAt : 0
              }
              if (typeof parsed.pendingSecret === 'string' && parsed.pendingSecret !== '') {
                state.pendingSecret = parsed.pendingSecret
              }
            }
          } catch (err) {
            console.error('totp-gate: could not load gate state:', err && err.message ? err.message : String(err))
          }
          return state
        })()
      }
      return readyPromise
    }

    // ---- totp generator tool ----
    const totpTool = harness.defineTool({
      name: 'totp',
      description: 'Generate a Time-based One-Time Password (TOTP) code for two-factor authentication, following RFC 6238 (compatible with Google Authenticator, Authy, and Microsoft Authenticator). Accepts a base32-encoded secret key (alphabet A-Z and 2-7; spaces, hyphens, and = padding are ignored) or a full otpauth://totp/... URI such as otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example. Returns the current code, the seconds remaining before it rotates, and optionally verifies a candidate code. Use for 2FA login flows or testing authentication.',
      parameters: {
        type: 'object',
        properties: {
          secret: {
            type: 'string',
            description: 'Base32-encoded TOTP secret key, or a full otpauth://totp/... URI containing the secret. Treat this value as sensitive: never log it or commit it to a file.'
          },
          digits: {
            type: 'integer',
            description: 'Number of digits in the generated code. Defaults to 6.',
            default: 6
          },
          interval: {
            type: 'integer',
            description: 'Time step in seconds before the code rotates. Defaults to 30; some services use 60 (e.g. AWS MFA).',
            default: 30
          },
          verify: {
            type: 'string',
            description: 'Optional candidate code to check against the current TOTP; the result reports PASS or FAIL.'
          },
          time: {
            type: 'integer',
            description: 'Optional Unix timestamp (seconds) to compute the code at, for testing or reproducing a known vector. Defaults to the current time.'
          }
        },
        required: ['secret']
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            code: { type: 'string', description: 'The current TOTP code, zero-padded to the requested number of digits.' },
            remaining: { type: 'integer', description: 'Seconds remaining before the code rotates.' },
            issuer: { type: 'string', description: 'Issuer extracted from an otpauth URI, when one was provided.' },
            label: { type: 'string', description: 'Account label extracted from an otpauth URI, when one was provided.' },
            verification: { type: 'string', description: 'PASS or FAIL, present only when a verify code was requested.' }
          },
          additionalProperties: false
        },
        render(args, value) {
          const lines = []
          if (typeof value.issuer === 'string') lines.push('Issuer: ' + value.issuer)
          if (typeof value.label === 'string') lines.push('Label: ' + value.label)
          lines.push('TOTP: ' + value.code)
          lines.push('Remaining: ' + value.remaining + ' seconds')
          if (typeof value.verification === 'string') lines.push('Verification: ' + value.verification)
          return [{ type: 'text', text: lines.join('\n') }]
        }
      },
      async execute(args, exec) {
        let effDigits = args.digits === undefined ? undefined : args.digits
        let effInterval = args.interval === undefined ? undefined : args.interval
        const nowSec = Math.floor(Date.now() / 1000)
        const timeSec = Number.isInteger(args.time) ? args.time : nowSec
        let secret = String(args.secret === undefined ? '' : args.secret).trim()
        let issuer
        let label
        if (secret.startsWith('otpauth://')) {
          const parsed = parseOtpauthUri(secret)
          secret = parsed.secret
          issuer = parsed.issuer
          label = parsed.label
          if (effDigits === undefined && Number.isInteger(parsed.digits)) effDigits = parsed.digits
          if (effInterval === undefined && Number.isInteger(parsed.period)) effInterval = parsed.period
        }
        if (secret === '') throw new Error('secret must be a non-empty base32 key or otpauth:// URI')
        effDigits = effDigits === undefined ? 6 : effDigits
        effInterval = effInterval === undefined ? 30 : effInterval
        if (!Number.isInteger(effDigits) || effDigits < 1 || effDigits > 10) throw new Error('digits must be an integer between 1 and 10')
        if (!Number.isInteger(effInterval) || effInterval < 1 || effInterval > 3600) throw new Error('interval must be an integer between 1 and 3600 seconds')
        const key = base32Decode(secret)
        const timeStep = Math.floor(timeSec / effInterval)
        const code = hotp(key, timeStep, effDigits)
        const remaining = effInterval - (Math.floor(timeSec) % effInterval)
        const result = { code: code, remaining: remaining }
        if (typeof issuer === 'string' && issuer !== '') result.issuer = issuer
        if (typeof label === 'string' && label !== '') result.label = label
        if (typeof args.verify === 'string' && args.verify.trim() !== '') {
          result.verification = args.verify.trim() === code ? 'PASS' : 'FAIL'
        }
        return result
      }
    })

    // ---- first-time binding: generate secret, save locally, emit QR info ----
    const bindTool = harness.defineTool({
      name: 'totp_gate_bind',
      description: 'Start the first-time binding of the TOTP critical-operation gate. Generates a new secret key, saves it locally in the plugin directory, and produces a QR code (SVG file + preview) plus a manual-entry key and otpauth:// URI so the user can add the account in Microsoft Authenticator or Google Authenticator. After the user scans/enters it, confirm the binding by calling totp_gate_confirm with the 6-digit code shown in their app. Pass regenerate=true to replace an existing binding with a new secret.',
      parameters: {
        type: 'object',
        properties: {
          regenerate: {
            type: 'boolean',
            description: 'Set true to issue a new secret and replace the existing binding. Defaults to false.',
            default: false
          }
        }
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            bound: { type: 'boolean', description: 'Whether a binding currently exists.' },
            pending: { type: 'boolean', description: 'Whether a fresh secret is awaiting confirmation.' },
            uri: { type: 'string', description: 'otpauth:// URI carrying the new secret.' },
            secret: { type: 'string', description: 'The new base32 secret for manual entry in the authenticator app.' },
            svgPath: { type: 'string', description: 'Absolute path of the saved QR SVG file to scan.' },
            qr: { type: 'string', description: 'Unicode preview of the QR code.' },
            note: { type: 'string', description: 'Optional warning.' }
          },
          additionalProperties: false
        },
        render(args, value) {
          const lines = []
          lines.push('TOTP gate binding — step 1 of 2')
          lines.push('')
          lines.push('1. Open Microsoft Authenticator or Google Authenticator on your phone.')
          lines.push('2. Add an account (+ button). Scan the QR code from this file:')
          if (typeof value.svgPath === 'string' && value.svgPath !== '') lines.push('   ' + value.svgPath)
          lines.push('   Or add manually: issuer "' + GATE_ISSUER + '", account "' + GATE_LABEL + '", secret key:')
          lines.push('   ' + value.secret)
          lines.push('3. After adding, read the current 6-digit code from the app.')
          lines.push('4. Confirm the binding by calling totp_gate_confirm with that code.')
          if (typeof value.note === 'string' && value.note !== '') lines.push('WARNING: ' + value.note)
          lines.push('')
          lines.push('QR preview (scan it if your display renders this monospace):')
          lines.push(value.qr)
          return [{ type: 'text', text: lines.join('\n') }]
        }
      },
      async execute(args, exec) {
        const st = await ready(exec)
        if (st.bound && args.regenerate !== true) {
          throw new Error('TOTP gate is already bound (bound at ' + new Date(st.boundAt).toISOString() + '). To issue a new secret, call totp_gate_bind with regenerate=true.')
        }
        const bytes = randomBytes(20)
        const secret = base32Encode(bytes)
        st.pendingSecret = secret
        st.pendingAt = Date.now()
        const uri = 'otpauth://totp/' + GATE_ISSUER + ':' + GATE_LABEL + '?secret=' + secret + '&issuer=' + GATE_ISSUER + '&algorithm=SHA1&digits=' + GATE_DIGITS + '&period=' + GATE_INTERVAL
        const matrix = qrMatrix(uri)
        const svg = qrToSvg(matrix)
        const art = qrToUnicode(matrix)
        const persisted = await persistState(exec)
        let svgPath = null
        const file = await gateFile(QR_FILE, exec)
        if (file !== null) {
          try {
            await file.fs.writeText(file.target, svg)
            if (typeof file.fs.processPath === 'function') svgPath = file.fs.processPath(file.target)
          } catch (err) {
            console.error('totp-gate: could not write QR svg:', err && err.message ? err.message : String(err))
          }
        }
        const result = {
          bound: st.bound,
          pending: true,
          uri: uri,
          secret: secret,
          qr: art
        }
        if (svgPath !== null) result.svgPath = svgPath
        if (!persisted) result.note = 'state could not be persisted to disk (fs service unavailable) — the binding will be lost when the plugin stops'
        return result
      }
    })

    // ---- confirm binding with the code from the user's authenticator app ----
    const confirmTool = harness.defineTool({
      name: 'totp_gate_confirm',
      description: 'Confirm the TOTP gate binding by verifying the 6-digit code the user read from Microsoft/Google Authenticator after totp_gate_bind. On success the binding becomes active and destructive commands are gated behind that secret.',
      parameters: {
        type: 'object',
        properties: {
          code: {
            type: 'string',
            description: 'The current 6-digit code the user reads from their authenticator app.'
          }
        },
        required: ['code']
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            bound: { type: 'boolean', description: 'True once the binding is confirmed.' },
            persisted: { type: 'boolean', description: 'Whether the binding was saved to the local state file.' },
            note: { type: 'string', description: 'Human-readable status.' }
          },
          additionalProperties: false
        },
        render(args, value) {
          if (value.bound === true) {
            return [{ type: 'text', text: 'Binding confirmed. The TOTP gate is now active: destructive commands (folder deletion, formatting, ...) are blocked until unlocked with totp_gate_unlock using a code from the bound authenticator app.' }]
          }
          return [{ type: 'text', text: 'Binding not confirmed.' }]
        }
      },
      async execute(args, exec) {
        const st = await ready(exec)
        if (st.pendingSecret === null) throw new Error('No pending binding. Run totp_gate_bind first.')
        const code = String(args.code === undefined ? '' : args.code).trim()
        if (!/^\d+$/.test(code)) throw new Error('invalid code format: expected digits only')
        const key = base32Decode(st.pendingSecret)
        const step = Math.floor(Date.now() / 1000 / GATE_INTERVAL)
        const ok = hotp(key, step - 1, GATE_DIGITS) === code ||
          hotp(key, step, GATE_DIGITS) === code ||
          hotp(key, step + 1, GATE_DIGITS) === code
        if (!ok) throw new Error('totp_gate_confirm: the code is invalid or expired — ask the user to read the CURRENT code from the authenticator app and retry')
        st.bound = true
        st.secret = st.pendingSecret
        st.boundAt = Date.now()
        st.pendingSecret = null
        const persisted = await persistState(exec)
        return { bound: true, persisted: persisted, note: 'binding active' }
      }
    })

    // ---- unlock ONE blocked critical operation ----
    const unlockTool = harness.defineTool({
      name: 'totp_gate_unlock',
      description: 'Unlock ONE blocked critical operation (such as deleting a folder recursively) by submitting the current 6-digit TOTP code. Ask the user to read the code from their authenticator app first — do not generate it yourself. On success the gate stays open for 90 seconds and permits exactly one critical operation to be retried.',
      parameters: {
        type: 'object',
        properties: {
          code: {
            type: 'string',
            description: 'The current 6-digit TOTP code the user read from their authenticator app.'
          }
        },
        required: ['code']
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            accepted: { type: 'boolean', description: 'Whether the code was accepted and the gate unlocked.' },
            expiresInSeconds: { type: 'integer', description: 'Seconds the unlock stays valid.' },
            note: { type: 'string', description: 'Human-readable instruction.' }
          },
          additionalProperties: false
        },
        render(args, value) {
          if (value.accepted === true) {
            return [{ type: 'text', text: 'Gate unlocked. One critical operation is authorized for the next ' + value.expiresInSeconds + ' seconds — retry the blocked command now.' }]
          }
          return [{ type: 'text', text: 'Gate unlock failed.' }]
        }
      },
      async execute(args, exec) {
        const st = await ready(exec)
        if (!st.bound) throw new Error('TOTP gate is not bound yet. Complete first-time binding first: run totp_gate_bind, show the user the QR code (Microsoft/Google Authenticator), then totp_gate_confirm with the code from the app.')
        const code = String(args.code === undefined ? '' : args.code).trim()
        if (!/^\d+$/.test(code)) throw new Error('invalid unlock code: expected digits only')
        const key = base32Decode(st.secret)
        const step = Math.floor(Date.now() / 1000 / GATE_INTERVAL)
        const accepted = hotp(key, step - 1, GATE_DIGITS) === code ||
          hotp(key, step, GATE_DIGITS) === code ||
          hotp(key, step + 1, GATE_DIGITS) === code
        if (!accepted) throw new Error('totp_gate_unlock: the code is invalid or expired — ask the user to read the CURRENT code from the authenticator app')
        unlockedUntil = Date.now() + GATE_WINDOW_MS
        unlockConsumed = false
        return { accepted: true, expiresInSeconds: Math.floor(GATE_WINDOW_MS / 1000), note: 'one critical operation is authorized' }
      }
    })

    ctx.effect(() => harness.registerTool(ctx, totpTool))
    ctx.effect(() => harness.registerTool(ctx, bindTool))
    ctx.effect(() => harness.registerTool(ctx, confirmTool))
    ctx.effect(() => harness.registerTool(ctx, unlockTool))

    // ---- critical-operation gate ----
    ctx.on('tools/pre-execute', async (exec, next) => {
      const name = typeof exec === 'object' && exec !== null ? exec.name : undefined
      if (typeof name !== 'string' || GATED_TOOLS.indexOf(name) === -1) return next()
      const args = typeof exec === 'object' && exec !== null ? exec.arguments : undefined
      const command = args !== null && typeof args === 'object' && typeof args.command === 'string' ? args.command : ''
      if (command === '') return next()
      if (/-whatif/i.test(command)) return next()
      let matched = false
      for (let i = 0; i < CRITICAL_PATTERNS.length; i++) {
        if (CRITICAL_PATTERNS[i].test(command)) {
          matched = true
          break
        }
      }
      if (!matched) return next()
      const st = await ready(exec)
      if (!st.bound) {
        return {
          kind: 'deny',
          reason: 'TOTP gate blocked a destructive command (tool "' + name + '"): first-time binding is required before critical operations. To bind: 1) run totp_gate_bind to generate the secret and QR code; 2) have the user add the account in Microsoft Authenticator or Google Authenticator (scan the SVG QR or enter the key); 3) run totp_gate_confirm with the 6-digit code from the app; 4) retry this command.'
        }
      }
      const now = Date.now()
      if (unlockedUntil > now && unlockConsumed === false) {
        unlockConsumed = true
        return next()
      }
      return {
        kind: 'deny',
        reason: 'TOTP gate blocked a destructive command (tool "' + name + '"). Folder deletion and other critical operations require 2FA confirmation. To proceed: 1) ask the user for the current 6-digit TOTP code from their authenticator app; 2) submit it with the totp_gate_unlock tool; 3) retry this command within 90 seconds.'
      }
    })
  }
}
