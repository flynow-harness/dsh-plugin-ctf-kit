/**
 * 集成冒烟测试：不起 DSH，直接 import index.js 的 buildTools()，用真实参数跑七个工具。
 *
 * 它的职责不是覆盖每个算法（各模块自带 node:test 单测），而是回答两个集成问题：
 *   1. 七个工具都注册出来了，名字与参数契约对得上；
 *   2. 每个工具在典型输入下真的返回可读文本，而不是抛错或空串。
 *
 * 运行：node test/smoke.mjs
 */
import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import zlib from 'node:zlib'
import { buildTools } from '../index.js'

const EXPECTED = ['ctf_codec', 'ctf_cipher', 'ctf_file', 'ctf_hash', 'ctf_jwt', 'ctf_pwn', 'ctf_stego']

const tools = buildTools()
const byName = new Map(tools.map((definition) => [definition.name, definition]))

assert.deepEqual([...byName.keys()].sort(), [...EXPECTED].sort(), 'tool names must match the declared contract')

for (const definition of tools) {
  assert.equal(typeof definition.description, 'string')
  assert.ok(definition.description.length > 40, `${definition.name} needs a real model-facing description`)
  assert.equal(typeof definition.parameters, 'object')
  assert.equal(definition.parameters.type, 'object')
  assert.equal(typeof definition.execute, 'function')
  assert.equal(typeof definition.output?.render, 'function')
}

/** 调用一个工具并断言返回了像样的文本。 */
async function run(name, args, needle, label) {
  const definition = byName.get(name)
  const result = await definition.execute(args, {})
  assert.equal(typeof result?.text, 'string', `${name} must return { text }`)
  assert.ok(result.text.length > 20, `${name} returned suspiciously little text`)
  if (needle !== undefined) {
    assert.ok(
      result.text.includes(needle),
      `${label ?? name}: expected output to contain ${JSON.stringify(needle)}\n---\n${result.text.slice(0, 800)}`,
    )
  }
  return result.text
}

/** 最小 PNG 编码器：给 ctf_file / ctf_stego 造真实素材，避免测试依赖外部文件。 */
function crc32(bytes) {
  let table = crc32.table
  if (table === undefined) {
    table = new Uint32Array(256)
    for (let n = 0; n < 256; n += 1) {
      let c = n
      for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
      table[n] = c >>> 0
    }
    crc32.table = table
  }
  let crc = 0xffffffff
  for (const byte of bytes) crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

function chunk(type, data) {
  const typeBytes = Buffer.from(type, 'latin1')
  const body = Buffer.concat([typeBytes, Buffer.from(data)])
  // 一个 chunk = 4 字节长度 + 4 字节类型 + data + 4 字节 CRC。
  const out = Buffer.alloc(8 + body.length)
  out.writeUInt32BE(data.length, 0)
  body.copy(out, 4)
  out.writeUInt32BE(crc32(body), 4 + body.length)
  return out
}

/** 生成 width x height 的 8-bit RGB PNG；`pixel` 决定每个像素的三通道值。 */
function makePng(width, height, pixel) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(width, 0)
  ihdr.writeUInt32BE(height, 4)
  ihdr[8] = 8 // bit depth
  ihdr[9] = 2 // color type: truecolour
  ihdr[10] = 0
  ihdr[11] = 0
  ihdr[12] = 0
  const raw = Buffer.alloc(height * (1 + width * 3))
  for (let y = 0; y < height; y += 1) {
    const rowStart = y * (1 + width * 3)
    raw[rowStart] = 0 // filter: none
    for (let x = 0; x < width; x += 1) {
      const [r, g, b] = pixel(x, y)
      const at = rowStart + 1 + x * 3
      raw[at] = r
      raw[at + 1] = g
      raw[at + 2] = b
    }
  }
  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ])
}

const workdir = await mkdtemp(path.join(tmpdir(), 'ctf-kit-smoke-'))
const checks = []

try {
  // 1) ctf_codec：flag 过一层 base64，auto 模式应该能把它捞回来。
  const flag = 'flag{sm0ke_test_c0dec}'
  const encoded = Buffer.from(flag, 'utf8').toString('base64')
  await run('ctf_codec', { action: 'auto', text: encoded }, 'flag{', 'codec auto should recover the flag')
  checks.push('ctf_codec auto recovered base64 flag')

  // 2) ctf_codec encode 分支。
  const encodedOut = await run('ctf_codec', { action: 'encode', encoding: 'base16', text: 'AB' }, '4142', 'codec encode hex')
  assert.equal(encodedOut.trim().length > 0, true)
  checks.push('ctf_codec encode base16')

  // 3) ctf_cipher：凯撒暴力应该给出 shift=3 的明文。
  await run('ctf_cipher', { action: 'bruteforce', cipher: 'caesar', text: 'iodj{v0gu4_pbqre}' }, 'flag{', 'caesar brute force')
  checks.push('ctf_cipher caesar brute force found flag')

  // 4) ctf_hash：识别 + 破解一个已知 MD5。
  await run('ctf_hash', { action: 'identify', value: '5f4dcc3b5aa765d61d8327deb882cf99' }, 'MD5', 'hash identify')
  await run('ctf_hash', { action: 'crack', value: '5f4dcc3b5aa765d61d8327deb882cf99' }, 'password', 'hash crack')
  checks.push('ctf_hash identify + crack')

  // 5) ctf_file：一个 PNG 尾部追加 flag 文本，应该同时报类型、尾随数据与 flag 命中。
  const png = makePng(4, 3, () => [10, 20, 30])
  const appendPath = path.join(workdir, 'appended.png')
  await writeFile(appendPath, Buffer.concat([png, Buffer.from(`\n${flag}\n`, 'utf8')]))
  await run('ctf_file', { path: appendPath, includeStrings: true }, 'PNG', 'file magic')
  const fileText = await run('ctf_file', { path: appendPath, includeStrings: true }, 'flag{', 'file flag scan')
  // 断言「真的定位到了 IEND 之后的追加字节」，而不是只匹配到一句"未发现"。
  assert.ok(
    /尾部附加数据[：:]\s*发现\s*\d+\s*字节/.test(fileText),
    `ctf_file should positively report the appended bytes after IEND\n---\n${fileText.slice(0, 900)}`,
  )
  checks.push('ctf_file magic + flag + appended data')

  // 6) ctf_stego：合法 PNG 应当解析出 IHDR。
  const cleanPath = path.join(workdir, 'clean.png')
  await writeFile(cleanPath, png)
  const stegoText = await run('ctf_stego', { path: cleanPath, action: 'info' }, 'IHDR', 'stego info')
  assert.ok(/4\s*(x|×)\s*3|width/i.test(stegoText), 'ctf_stego should report the image dimensions')
  checks.push('ctf_stego info parsed IHDR')

  // 7) ctf_jwt：自己签一个 HS256 再解回来。
  const jwtSigned = await run('ctf_jwt', {
    action: 'sign',
    payload: JSON.stringify({ sub: 'admin', role: 'ctf' }),
    secret: 'ctf-smoke-secret',
    algorithm: 'HS256',
  }, 'eyJ', 'jwt sign')
  const tokenMatch = jwtSigned.match(/eyJ[A-Za-z0-9_\-.]{20,}/)
  assert.ok(tokenMatch !== null, 'jwt sign should print a token')
  await run('ctf_jwt', { action: 'decode', token: tokenMatch[0] }, 'admin', 'jwt decode round trip')
  await run('ctf_jwt', { action: 'verify', token: tokenMatch[0], secret: 'ctf-smoke-secret' }, undefined, 'jwt verify')
  checks.push('ctf_jwt sign + decode + verify round trip')

  // 8) ctf_pwn：p64 little-endian 的字节序必须对（0xdeadbeefcafebabe 的真实 LE 顺序）。
  await run('ctf_pwn', { action: 'pack', data: '0xdeadbeefcafebabe', format: 'le64' }, 'be ba fe ca', 'pwn p64 low half')
  await run('ctf_pwn', { action: 'pack', data: '0xdeadbeefcafebabe', format: 'le64' }, 'ef be ad de', 'pwn p64 high half')
  await run('ctf_pwn', { action: 'cyclic', data: '64' }, 'aaa', 'pwn cyclic')
  checks.push('ctf_pwn pack + cyclic')

  console.log('smoke: OK')
  for (const line of checks) console.log(`  - ${line}`)
} finally {
  await rm(workdir, { recursive: true, force: true })
}
