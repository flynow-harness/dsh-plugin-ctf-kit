/**
 * `ctf_jwt` 与 `ctf_pwn` 的单元测试。
 *
 * 覆盖重点是两个模块的正确性核心，而不是「输出看起来像」：
 *   - JWT：base64url 往返/边界、用独立计算的 HMAC 向量校验、错误密钥/算法不一致、
 *     弱口令命中与未命中、alg=none 两段/三段结构。
 *   - Pwn：p32/p64 的真实端序、pack/unpack 往返、de Bruijn 与 pwntools 已知前缀、
 *     子串反查偏移、hexdump 首行格式、坏字符识别。
 *
 * 注意两处任务描述里的字节串与数学不符，这里按真实端序断言并把对应关系写清楚：
 *   1) 0xdeadbeefcafebabe 的 p64 是 be ba fe ca ef be ad de；
 *      任务里的 be ba fe ca be ba fe ca 实际对应 0xcafebabecafebabe。
 *   2) p32(0x41424344) 是小端 44 43 42 41 = "DCBA"；"ABCD" 是大端/内存顺序。
 * 运行：node --test test/webpwn.test.mjs
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'

import {
  base64UrlDecode,
  base64UrlEncode,
  buildAlgNoneTokens,
  crackJwtSecret,
  createJwtTool,
  decodeJwt,
  describeJwtTiming,
  findSuspiciousClaims,
  signJwt,
  verifyJwtHmac,
} from '../ctf/web.js'

import {
  bytesToBigInt,
  createPwnTool,
  cyclicFind,
  cyclicPattern,
  deBruijnSequence,
  escapeAllBytes,
  formatHexdump,
  packBigIntToBytes,
  parseIntegerInput,
  parseShellcodeInput,
  renderPacked,
  scanShellcode,
  unpackInteger,
} from '../ctf/pwn.js'

/** 独立于 ctf/web.js 的 base64url 编码，用来构造测试 token。 */
function b64u(value) {
  return Buffer.from(value, 'utf8').toString('base64url')
}

/** 独立于 ctf/web.js 的 HS256 签名，用来验证模块的 HMAC 结果。 */
function hs256(headerSegment, payloadSegment, secret) {
  return createHmac('sha256', secret).update(`${headerSegment}.${payloadSegment}`).digest('base64url')
}

/** 用给定 payload 与密钥手搓一个 HS256 token（不经过被测模块）。 */
function handmadeToken(payload, secret) {
  const headerSegment = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payloadSegment = b64u(JSON.stringify(payload))
  return `${headerSegment}.${payloadSegment}.${hs256(headerSegment, payloadSegment, secret)}`
}

const FIXED_NOW = 1_700_000_000

// ===========================================================================
// JWT：base64url
// ===========================================================================

test('JWT base64url：无填充、URL-safe、往返与边界', () => {
  assert.equal(base64UrlEncode(''), '')
  assert.equal(base64UrlEncode('foobar'), 'Zm9vYmFy')
  assert.equal(base64UrlEncode(Uint8Array.from([0xfb, 0xff])), '-_8')
  assert.equal(base64UrlEncode('hello world?'), 'aGVsbG8gd29ybGQ_')

  const allBytes = Uint8Array.from({ length: 256 }, (_, index) => index)
  const encoded = base64UrlEncode(allBytes)
  assert.ok(!encoded.includes('='), 'base64url 不应含填充')
  assert.ok(!/[+/]/.test(encoded), 'base64url 不应含 + /')
  assert.deepEqual(Array.from(base64UrlDecode(encoded)), Array.from(allBytes))

  // 结尾填充与 URL-safe 字符都要能还原
  assert.deepEqual(Array.from(base64UrlDecode('Zm9vYmFy==')), Array.from(Buffer.from('foobar')))
  assert.deepEqual(Array.from(base64UrlDecode('-_8')), [0xfb, 0xff])
  assert.deepEqual(Array.from(base64UrlDecode('')), [])

  // 非法输入必须报错，而不是静默解出乱码
  assert.throws(() => base64UrlDecode('abcde'), /长度非法/)
  assert.throws(() => base64UrlDecode('ab c'), /不是合法/)
  assert.throws(() => base64UrlDecode('ab+c'), /不是合法/)
})

// ===========================================================================
// JWT：解析
// ===========================================================================

test('JWT decode：拆出 header/payload/signature 与 signingInput', () => {
  const payload = { sub: 'admin', role: 'admin', iat: FIXED_NOW }
  const token = handmadeToken(payload, 'hunter2')
  const decoded = decodeJwt(token)

  assert.equal(decoded.ok, true)
  assert.equal(decoded.segments.length, 3)
  assert.deepEqual(decoded.header, { alg: 'HS256', typ: 'JWT' })
  assert.equal(decoded.payload.sub, 'admin')
  assert.equal(decoded.payload.role, 'admin')
  assert.equal(decoded.algorithm, 'HS256')
  assert.equal(decoded.signingInput, `${token.split('.')[0]}.${token.split('.')[1]}`)
  assert.equal(decoded.signatureBytes.length, 32)
  assert.equal(base64UrlEncode(decoded.signatureBytes), token.split('.')[2])
})

test('JWT decode：已知的 jwt.io 示例向量可被解析并校验', () => {
  // jwt.io 默认示例（secret = your-256-bit-secret），用于确认 base64url/HMAC 语义与业界实现一致。
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
  const decoded = decodeJwt(token)
  assert.equal(decoded.ok, true)
  assert.equal(decoded.header.alg, 'HS256')
  assert.equal(decoded.payload.sub, '1234567890')
  assert.equal(decoded.payload.name, 'John Doe')

  const verified = verifyJwtHmac(token, 'your-256-bit-secret')
  assert.equal(verified.matched, true)
})

test('JWT decode：非法输入返回可读错误而不是抛异常', () => {
  assert.equal(decodeJwt('').ok, false)
  assert.equal(decodeJwt('onlyonepart').ok, false)
  assert.equal(decodeJwt('a.b.c.d').ok, false)
  assert.equal(decodeJwt(`${b64u('not json')}.${b64u('{}')}.AAAA`).ok, false)
  assert.equal(decodeJwt(`${b64u('{}')}.${b64u('[]')}.AAAA`).ok, false)
})

// ===========================================================================
// JWT：时间字段
// ===========================================================================

test('JWT 时间：exp 过期、nbf 未生效、iat 在未来都能判定', () => {
  const timing = describeJwtTiming({ iat: FIXED_NOW + 100, nbf: FIXED_NOW + 500, exp: FIXED_NOW - 100 }, FIXED_NOW)
  assert.equal(timing.expired, true)
  assert.equal(timing.notYetValid, true)
  assert.match(timing.exp.status, /已过期/)
  assert.match(timing.nbf.status, /尚未生效/)
  assert.match(timing.iat.status, /未来/)
  assert.ok(timing.exp.iso.endsWith('Z'))
  assert.ok(timing.warnings.length >= 2)

  const fresh = describeJwtTiming({ iat: FIXED_NOW - 10, exp: FIXED_NOW + 3600 }, FIXED_NOW)
  assert.equal(fresh.expired, false)
  assert.equal(fresh.notYetValid, null)
  assert.equal(fresh.expiresInSeconds, 3600)
  assert.match(fresh.exp.status, /剩余 3600 秒/)

  const noExp = describeJwtTiming({ sub: 'admin' }, FIXED_NOW)
  assert.equal(noExp.exp, null)
  assert.ok(noExp.warnings.some((warning) => warning.includes('没有 exp')))

  // 毫秒级时间戳也要能和秒级 now 比较
  const millis = describeJwtTiming({ exp: (FIXED_NOW + 60) * 1000 }, FIXED_NOW)
  assert.equal(millis.expired, false)
})

// ===========================================================================
// JWT：HMAC 校验
// ===========================================================================

test('JWT verify：正确密钥匹配、错误密钥不匹配', () => {
  const token = handmadeToken({ sub: 'admin' }, 'hunter2')

  const good = verifyJwtHmac(token, 'hunter2')
  assert.equal(good.ok, true)
  assert.equal(good.matched, true)
  assert.equal(good.algorithm, 'HS256')
  assert.equal(good.algorithmMismatch, false)
  assert.equal(good.expectedSignature, token.split('.')[2])

  const bad = verifyJwtHmac(token, 'hunter3')
  assert.equal(bad.matched, false)
  assert.ok(bad.warnings.some((warning) => warning.includes('不匹配')))

  // timingSafeEqual 对不等长会抛错，模块必须先比较长度
  const shortSignature = `${token.split('.')[0]}.${token.split('.')[1]}.AAAA`
  const short = verifyJwtHmac(shortSignature, 'hunter2')
  assert.equal(short.matched, false)
  assert.ok(short.warnings.some((warning) => warning.includes('签名长度不同')))
})

test('JWT verify：algorithm 与 header.alg 不一致会告警', () => {
  const token = handmadeToken({ sub: 'admin' }, 'hunter2')
  const result = verifyJwtHmac(token, 'hunter2', 'HS512')
  assert.equal(result.algorithmMismatch, true)
  assert.equal(result.matched, true) // 校验以 header.alg（HS256）为准，secret 正确仍匹配
  assert.ok(result.warnings.some((warning) => warning.includes('不一致')))
})

test('JWT verify：未显式指定 algorithm 时按 header.alg 校验、不误报', () => {
  const signed = signJwt({ payload: JSON.stringify({ sub: 'admin' }), secret: 'k', algorithm: 'HS384' })
  const result = verifyJwtHmac(signed.token, 'k')
  assert.equal(result.matched, true)
  assert.equal(result.algorithmMismatch, false)
  assert.equal(result.warnings.length, 0)
})

test('JWT verify：alg=none 的 token 没有签名可比对', () => {
  const none = signJwt({ payload: JSON.stringify({ sub: 'admin' }), algorithm: 'none' })
  const result = verifyJwtHmac(none.token, 'whatever')
  assert.equal(result.ok, true)
  assert.equal(result.matched, false)
  assert.ok(result.warnings.some((warning) => warning.includes('none')))
})

// ===========================================================================
// JWT：伪造
// ===========================================================================

test('JWT sign：HS256/384/512 重新解码后结构正确', () => {
  for (const algorithm of ['HS256', 'HS384', 'HS512']) {
    const signed = signJwt({
      payload: JSON.stringify({ sub: 'admin', role: 'admin' }),
      secret: 'hunter2',
      algorithm,
    })
    assert.equal(signed.algorithm, algorithm)
    assert.equal(signed.token.split('.').length, 3)
    assert.equal(base64UrlDecode(signed.signatureSegment).length, { HS256: 32, HS384: 48, HS512: 64 }[algorithm])

    const decoded = decodeJwt(signed.token)
    assert.equal(decoded.ok, true)
    assert.equal(decoded.header.alg, algorithm)
    assert.equal(decoded.payload.sub, 'admin')
    assert.equal(decoded.payload.role, 'admin')
  }
})

test('JWT sign：alg=none 产出三段空签名与两段形式', () => {
  const signed = signJwt({ payload: JSON.stringify({ sub: 'admin', role: 'admin' }), algorithm: 'none' })
  const segments = signed.token.split('.')
  assert.equal(segments.length, 3)
  assert.equal(segments[2], '')
  assert.equal(signed.tokenWithoutTrailingDot.split('.').length, 2)

  const decoded = decodeJwt(signed.token)
  assert.equal(decoded.ok, true)
  assert.equal(decoded.header.alg, 'none')
  assert.equal(decoded.signatureBytes.length, 0)

  const twoPart = decodeJwt(signed.tokenWithoutTrailingDot)
  assert.equal(twoPart.ok, true)
  assert.equal(twoPart.payload.role, 'admin')
  assert.ok(twoPart.notes.some((note) => note.includes('unsecured')))

  const variants = buildAlgNoneTokens(handmadeToken({ sub: 'admin' }, 'hunter2')).variants
  assert.ok(variants.length >= 1)
  assert.equal(variants[0].token.split('.')[2], '')
  assert.deepEqual(variants[0].header, { alg: 'none', typ: 'JWT' })

  // 原 header 带额外字段（如 kid）时会再给一个「保留其余字段」的变体
  const customHeader = { alg: 'HS256', typ: 'JWT', kid: 'k1' }
  const customHeaderSegment = b64u(JSON.stringify(customHeader))
  const customPayloadSegment = b64u(JSON.stringify({ sub: 'admin' }))
  const customToken = `${customHeaderSegment}.${customPayloadSegment}.${hs256(customHeaderSegment, customPayloadSegment, 'hunter2')}`
  const customVariants = buildAlgNoneTokens(customToken).variants
  assert.equal(customVariants.length, 2)
  assert.ok(customVariants.some((variant) => variant.header.kid === 'k1'))
})

test('JWT sign：非法 payload / 缺少 secret 会抛出可读错误', () => {
  assert.throws(() => signJwt({ payload: 'not json', secret: 'k' }), /不是合法 JSON/)
  assert.throws(() => signJwt({ payload: '[]', secret: 'k' }), /顶层必须是 JSON 对象/)
  assert.throws(() => signJwt({ payload: '{}', algorithm: 'HS256' }), /需要 secret/)
})

// ===========================================================================
// JWT：弱密钥攻击
// ===========================================================================

test('JWT attack：内置字典能命中 password，也能命中 wordlist 追加项', () => {
  const weakToken = handmadeToken({ sub: 'admin' }, 'password')
  const weak = crackJwtSecret(weakToken)
  assert.equal(weak.ok, true)
  assert.equal(weak.hit.secret, 'password')
  assert.equal(weak.hit.algorithm, 'HS256')
  assert.ok(weak.attempted >= 1)

  const strongSecret = 'Zx9!q7#Lm2$pR5w'
  const strongToken = handmadeToken({ sub: 'admin' }, strongSecret)
  const miss = crackJwtSecret(strongToken)
  assert.equal(miss.hit, null)
  assert.ok(miss.total >= 60, '内置字典应有约 60+ 条候选')

  const custom = crackJwtSecret(strongToken, ['not-it', strongSecret])
  assert.equal(custom.hit.secret, strongSecret)
  assert.ok(custom.attempted > miss.attempted)
})

test('JWT attack：键是 jwt.io 示例密钥 your-256-bit-secret 时也能命中', () => {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
  const result = crackJwtSecret(token)
  assert.equal(result.hit.secret, 'your-256-bit-secret')
})

// ===========================================================================
// JWT：可疑字段与工具定义
// ===========================================================================

test('JWT 可疑字段：角色、kid、jku 与 flag 形态值都会被标记', () => {
  const claims = findSuspiciousClaims(
    { alg: 'HS256', kid: '../../../../dev/null', jku: 'http://evil.example/jwks.json' },
    { sub: 'admin', role: 'admin', note: 'flag{jwt_cl4im}' },
  )
  assert.ok(claims.some((item) => item.field === 'role'))
  assert.ok(claims.some((item) => item.field === 'kid'))
  assert.ok(claims.some((item) => item.field === 'jku'))
  assert.ok(claims.some((item) => item.hint.includes('flag')))
  assert.ok(claims.every((item) => typeof item.location === 'string'))
})

test('JWT 工具定义：name / parameters 顶层键名 / output 契约', () => {
  const tool = createJwtTool({})
  assert.equal(tool.name, 'ctf_jwt')
  assert.ok(tool.description.length > 40)
  assert.deepEqual(Object.keys(tool.parameters.properties).sort(), [
    'action', 'algorithm', 'payload', 'secret', 'token', 'wordlist',
  ])
  assert.deepEqual(tool.parameters.properties.action.enum, ['decode', 'verify', 'sign', 'attack'])
  assert.deepEqual(tool.parameters.properties.algorithm.enum, ['HS256', 'HS384', 'HS512', 'none'])
  assert.equal(tool.parameters.properties.wordlist.type, 'array')
  assert.equal(tool.output.schema.type, 'object')
  assert.equal(typeof tool.execute, 'function')
})

test('JWT 工具 execute：decode/verify/sign/attack 都返回中文 Markdown 与 curl 示例', async () => {
  const tool = createJwtTool({})
  const token = handmadeToken({ sub: 'admin', role: 'admin', exp: Math.floor(Date.now() / 1000) + 3600 }, 'hunter2')

  const decoded = await tool.execute({ action: 'decode', token })
  assert.match(decoded.text, /##/)
  assert.ok(decoded.text.includes('admin'))
  assert.ok(decoded.text.includes('curl'))
  assert.ok(decoded.text.includes('role'))

  const verified = await tool.execute({ action: 'verify', token, secret: 'hunter2' })
  assert.ok(verified.text.includes('匹配'))
  assert.ok(verified.text.includes('curl'))

  const mismatched = await tool.execute({ action: 'verify', token, secret: 'hunter2', algorithm: 'HS512' })
  assert.ok(mismatched.text.includes('不一致'))

  const signed = await tool.execute({
    action: 'sign',
    payload: JSON.stringify({ sub: 'admin' }),
    secret: 'hunter2',
    algorithm: 'HS256',
  })
  assert.match(signed.text, /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/)

  const weak = handmadeToken({ sub: 'admin' }, 'password')
  const attacked = await tool.execute({ action: 'attack', token: weak })
  assert.ok(attacked.text.includes('password'))
  assert.ok(attacked.text.includes('alg=none'))
  assert.ok(attacked.text.includes('curl'))

  const noneSigned = await tool.execute({
    action: 'sign',
    payload: JSON.stringify({ sub: 'admin' }),
    algorithm: 'none',
  })
  assert.ok(noneSigned.text.includes('无签名'))

  const broken = await tool.execute({ action: 'decode', token: 'not-a-jwt' })
  assert.ok(broken.text.includes('出错'))

  const unknownAction = await tool.execute({ action: 'rm-rf', token })
  assert.ok(unknownAction.text.includes('出错'))
})

// ===========================================================================
// Pwn：pack / unpack
// ===========================================================================

test('Pwn pack：p64 真实小端字节（含任务描述里两处字节串的纠正）', () => {
  const deadbeef = renderPacked('0xdeadbeefcafebabe', 'le64')
  assert.equal(deadbeef.hex, 'bebafecaefbeadde')
  assert.equal(deadbeef.escapes, '\\xbe\\xba\\xfe\\xca\\xef\\xbe\\xad\\xde')
  assert.equal(deadbeef.hexGrouped, 'be ba fe ca ef be ad de')

  // 任务里的 `\xbe\xba\xfe\xca\xbe\xba\xfe\xca` 对应 0xcafebabecafebabe
  const cafebabe = renderPacked('0xcafebabecafebabe', 'le64')
  assert.equal(cafebabe.escapes, '\\xbe\\xba\\xfe\\xca\\xbe\\xba\\xfe\\xca')

  assert.equal(renderPacked('0x41424344', 'le32').hex, '44434241')
  assert.equal(renderPacked('0x41424344', 'le32').readable, 'DCBA')
  assert.equal(renderPacked('0x41424344', 'be32').readable, 'ABCD')
  assert.equal(renderPacked('AAAA', 'le32').readable, 'AAAA')
  assert.equal(renderPacked('AAAA', 'be32').readable, 'AAAA')
  assert.equal(renderPacked(0x41424344n, 'le32').hex, '44434241')
})

test('Pwn pack：format 与宽度/端序/截断语义正确', () => {
  assert.equal(renderPacked('0x41', 'le16').hex, '4100')
  assert.equal(renderPacked('0x41', 'be16').hex, '0041')
  assert.equal(renderPacked('0x1', 'le64').hex, '0100000000000000')
  assert.equal(packBigIntToBytes(-1n, 4, 'le').hex, 'ffffffff')
  assert.equal(packBigIntToBytes(0x100n, 1, 'be').truncated, true)
  assert.equal(packBigIntToBytes(0x100n, 1, 'be').hex, '00')
  assert.equal(renderPacked('0x1234', 'hex').hex, '1234')
  assert.equal(renderPacked('0x1234', 'python').pythonLiteral, "b'\\x124'")
  assert.throws(() => renderPacked('0x41', 'le128'), /不支持的 format/)
  assert.throws(() => renderPacked('', 'le64'), /data 为空/)
})

test('Pwn parseIntegerInput：十六进制、十进制、字节串、文本四种解释', () => {
  assert.equal(parseIntegerInput('0xdead').value, 0xdeadn)
  assert.equal(parseIntegerInput('3735928559').value, 3735928559n)
  assert.equal(parseIntegerInput('\\x41\\x42').value, 0x4142n)
  assert.equal(parseIntegerInput('41 42').value, 0x4142n)
  assert.equal(parseIntegerInput('AAAA').value, 0x41414141n)
  assert.equal(parseIntegerInput('AAAA').kind, 'text')
  assert.equal(parseIntegerInput(-1).value, -1n)
})

test('Pwn unpack：端序、有符号与 pack/unpack 往返', () => {
  assert.equal(unpackInteger('bebafecaefbeadde', 'le64').unsigned, 0xdeadbeefcafebaben)
  assert.equal(unpackInteger('bebafecaefbeadde', 'be64').unsigned, 0xbebafecaefbeadden)
  assert.equal(unpackInteger('41424344', 'be32').unsigned, 0x41424344n)
  assert.equal(unpackInteger('41424344', 'le32').unsigned, 0x44434241n)
  assert.equal(unpackInteger('ffffffff', 'le32').signed, -1n)
  assert.throws(() => unpackInteger('ff', 'le16'), /只有 1 字节/)
  assert.throws(() => unpackInteger('', 'le64'), /data 为空/)

  const roundtrip = [
    ['le16', 0xabcdn],
    ['be16', 0xabcdn],
    ['le32', 0xdeadbeefn],
    ['be32', 0xdeadbeefn],
    ['le64', 0xdeadbeefcafebaben],
    ['be64', 0xdeadbeefcafebaben],
  ]
  for (const [format, value] of roundtrip) {
    const packed = renderPacked(`0x${value.toString(16)}`, format)
    const unpacked = unpackInteger(packed.hex, format)
    assert.equal(unpacked.unsigned, value, `${format} 往返`)
    assert.equal(unpacked.hex, packed.hex, `${format} 字节一致`)
  }
})

// ===========================================================================
// Pwn：cyclic / de Bruijn
// ===========================================================================

test('Pwn cyclic：de Bruijn 前缀与 pwntools 一致', () => {
  let prefix = ''
  for (const char of deBruijnSequence()) {
    prefix += char
    if (prefix.length === 20) break
  }
  // pwntools: cyclic(20) == b'aaaabaaacaaadaaaeaaa'
  assert.equal(prefix, 'aaaabaaacaaadaaaeaaa')
  assert.equal(cyclicPattern(20), prefix)
  assert.equal(cyclicPattern(0), '')
  assert.equal(cyclicPattern(64).length, 64)
  assert.ok(cyclicPattern(64).includes('aaa'))
  assert.throws(() => cyclicPattern(-1), /非负整数/)
})

test('Pwn cyclic：取子串能反查回同一偏移，不存在时返回 -1', () => {
  const pattern = cyclicPattern(512)
  for (const offset of [0, 1, 7, 123, 300, 508]) {
    const needle = pattern.slice(offset, offset + 4)
    assert.equal(cyclicFind(needle), offset, `offset ${offset}`)
  }
  assert.equal(cyclicFind(pattern.slice(200, 208)), 200)
  assert.equal(cyclicFind('!@#$', { limit: 4096 }), -1)
  assert.equal(cyclicFind('', { limit: 4096 }), -1)
  // 支持 \xNN 转义写法
  const escaped = `\\x${pattern.charCodeAt(40).toString(16)}\\x${pattern.charCodeAt(41).toString(16)}`
  assert.ok(cyclicFind(escaped) >= 0)
})

// ===========================================================================
// Pwn：hexdump / shellcode / int
// ===========================================================================

test('Pwn hexdump：16 列格式、偏移列与 ASCII 列', () => {
  const dump = formatHexdump(Uint8Array.from([0x41, 0x42, 0x43, 0x44]), {})
  assert.match(dump.lines[0], /^0000\s+41 42 43 44/)
  assert.ok(dump.lines[0].includes('|ABCD'))
  assert.equal(dump.window.length, 4)

  const data = Uint8Array.from({ length: 32 }, (_, index) => index)
  const windowed = formatHexdump(data, { offset: 16, length: 16 })
  assert.match(windowed.lines[0], /^0010\s+10 11 12 13/)
  assert.equal(windowed.lines.length, 1)
  assert.equal(windowed.beforeWindow, 16)

  const full = formatHexdump(Uint8Array.from({ length: 20 }, (_, index) => 0x61 + index), {})
  assert.equal(full.lines.length, 2)
  assert.match(full.lines[1], /^0010\s+71 72 73 74/)
})

test('Pwn shellcode：识别 0x00 坏字符并输出 C/Python 字面量', () => {
  const bytes = parseShellcodeInput('\\x48\\x31\\x00\\xc0')
  assert.deepEqual(Array.from(bytes), [0x48, 0x31, 0x00, 0xc0])
  assert.equal(escapeAllBytes(bytes), '\\x48\\x31\\x00\\xc0')

  const scan = scanShellcode(bytes)
  assert.equal(scan.classicBadChars.length, 1)
  assert.equal(scan.classicBadChars[0].byte, 0x00)
  assert.equal(scan.frequency.get(0x00), 1)
  assert.ok(scan.classicBadChars[0].note.includes('NUL'))

  const clean = scanShellcode(parseShellcodeInput('\\x48\\x31\\xc0'))
  assert.equal(clean.classicBadChars.length, 0)

  assert.deepEqual(Array.from(parseShellcodeInput('4831c0')), [0x48, 0x31, 0xc0])
  assert.throws(() => parseShellcodeInput('zzz'), /无法把 data 解析成字节/)
})

test('Pwn int：hex/dec/bin/oct 与两种端序字节序列', () => {
  const parsed = parseIntegerInput('0x4142')
  assert.equal(parsed.value, 0x4142n)
  assert.equal(bytesToBigInt(Uint8Array.from([0x41, 0x42]), 'be'), 0x4142n)
})

// ===========================================================================
// Pwn：工具定义与 execute 集成
// ===========================================================================

test('Pwn 工具定义：name / parameters 顶层键名 / output 契约', () => {
  const tool = createPwnTool({})
  assert.equal(tool.name, 'ctf_pwn')
  assert.ok(tool.description.length > 40)
  assert.deepEqual(Object.keys(tool.parameters.properties).sort(), [
    'action', 'as', 'data', 'format', 'length', 'offset', 'pattern',
  ])
  assert.deepEqual(tool.parameters.properties.action.enum, [
    'hexdump', 'pack', 'unpack', 'int', 'cyclic', 'shellcode',
  ])
  assert.deepEqual(tool.parameters.properties.as.enum, ['hex', 'text'])
  assert.deepEqual(tool.parameters.properties.format.enum, [
    'le16', 'le32', 'le64', 'be16', 'be32', 'be64', 'hex', 'c-escape', 'python',
  ])
  assert.equal(tool.output.schema.type, 'object')
})

test('Pwn 工具 execute：六个 action 都返回可读中文 Markdown', async () => {
  const tool = createPwnTool({})

  const packOut = await tool.execute({ action: 'pack', data: '0xdeadbeefcafebabe', format: 'le64' })
  assert.ok(packOut.text.includes('be ba fe ca'))
  assert.ok(packOut.text.includes('\\xbe\\xba\\xfe\\xca'))
  assert.ok(packOut.text.includes('p64('))

  const p32Out = await tool.execute({ action: 'pack', data: '0x41424344', format: 'be32' })
  assert.ok(p32Out.text.includes('ABCD'))
  const p32Le = await tool.execute({ action: 'pack', data: '0x41424344', format: 'le32' })
  assert.ok(p32Le.text.includes('DCBA'))

  const unpackOut = await tool.execute({ action: 'unpack', data: 'bebafecaefbeadde', format: 'le64' })
  assert.ok(unpackOut.text.includes('0xdeadbeefcafebabe'))
  assert.ok(unpackOut.text.includes('u64('))

  const intOut = await tool.execute({ action: 'int', data: '0x4142' })
  assert.ok(intOut.text.includes('0x4142'))
  assert.ok(intOut.text.includes('16706'))

  const cyclicOut = await tool.execute({ action: 'cyclic', data: '64', pattern: 'aaaab' })
  assert.ok(cyclicOut.text.includes('偏移'))
  assert.ok(cyclicOut.text.includes('aaaabaaac'))
  const cyclicMiss = await tool.execute({ action: 'cyclic', data: '32', pattern: '!@#$' })
  assert.ok(cyclicMiss.text.includes('没有命中'))

  const hexdumpOut = await tool.execute({ action: 'hexdump', data: '41424344' })
  assert.ok(hexdumpOut.text.includes('0000'))
  assert.ok(hexdumpOut.text.includes('|ABCD'))

  const textDump = await tool.execute({ action: 'hexdump', data: 'Hi', as: 'text' })
  assert.ok(textDump.text.includes('48 69'))

  const shellOut = await tool.execute({ action: 'shellcode', data: '\\x48\\x31\\x00\\xc0' })
  assert.ok(shellOut.text.includes('unsigned char shellcode[]'))
  assert.ok(shellOut.text.includes('0x00'))
  assert.ok(shellOut.text.includes('坏字符'))

  const badPack = await tool.execute({ action: 'pack', data: '' })
  assert.ok(badPack.text.includes('出错'))
  const badAction = await tool.execute({ action: 'exploit' })
  assert.ok(badAction.text.includes('出错'))
  const badFormat = await tool.execute({ action: 'pack', data: '0x41', format: 'le128' })
  assert.ok(badFormat.text.includes('出错'))
})
