/**
 * CTF 解题工具箱的 Host 半边。
 *
 * 七个确定性工具 + 一段系统提示。设计原则和 `@local/java-engineer` 一致：
 *
 *   1. 全部是纯本地计算或只读文件探测，不联网、不启动子进程、不 attach 任何进程；
 *      唯一会写盘的是 `ctf_file` 在显式 `extractEmbedded: true` 时，把内嵌对象释放到
 *      输入文件同目录的 `<basename>_extracted/` 里。
 *   2. 每个工具的知识编码在代码里（magic 表、hashcat 模式号、弱口令字典、PNG 过滤器），
 *      所以同样的输入永远得到同样的报告，结论可以在 diff 里复核。
 *   3. 工具输出是给人和模型一起读的 Markdown：先给结论，再给证据，最后给下一步。
 *
 * 这里不 import 任何第三方依赖：插件装载在 DSH 进程里，缺依赖会让整个 profile 起不来。
 */
import * as codecModule from './ctf/codec.js'
import * as cipherModule from './ctf/cipher.js'
import * as hashModule from './ctf/hash.js'
import * as forensicsModule from './ctf/forensics.js'
import * as stegoModule from './ctf/stego.js'
import * as webModule from './ctf/web.js'
import * as pwnModule from './ctf/pwn.js'

export const name = 'ctf-kit'

/** 硬依赖工具注册表；工作目录服务按需读取，缺失时退回进程目录。 */
export const inject = ['tools']

const PROMPT_SECTION = `## CTF solving toolkit

Seven deterministic CTF tools are available. Prefer them over ad-hoc shell one-liners for decoding, cipher brute force, hash checks, file triage, PNG LSB extraction, JWT work, and endianness/packing: they return ranked, reviewable evidence instead of a single guess.

- \`ctf_codec\` — decode one layer, encode, or auto-crack a chain (base64/base32/base16/base85/binary/decimal/octal/URL/HTML/Morse/Bacon/ROT13/UUencode/quoted-printable/unicode escapes). Auto mode recurses and ranks candidates by printable score, so run it first on unknown strings.
- \`ctf_cipher\` — apply or brute-force classical ciphers (Caesar/ROT-N, ROT47, Atbash, rail fence, Vigenere, columnar, Bacon, Morse, keyboard shift).
- \`ctf_hash\` — identify a hash by length/prefix, produce hashes, or check a small built-in common/CTF wordlist. It is not a GPU cracker; report its dictionary limits when it misses.
- \`ctf_file\` — file triage: hashes, magic bytes versus extension, embedded-object offsets, appended data after EOF, flag-shaped strings, strings summary, long base64 blobs; \`extractEmbedded\` releases carved objects to a sibling directory.
- \`ctf_stego\` — PNG chunk/IHDR inventory (including text chunks and bytes after IEND) and LSB extraction for 8-bit non-interlaced PNGs (bit and channel selectable).
- \`ctf_jwt\` — decode header/payload with timing checks, verify an HS256/384/512 secret, sign a token, or test weak secrets plus the alg=none confusion.
- \`ctf_pwn\` — hexdump, int/endian conversion, p32/p64 packing to escaped shellcode, de Bruijn cyclic patterns with offset lookup, and bad-character scans.

Work from evidence: quote the exact byte offsets, decoded values, or candidate scores a tool reported, and say which steps are still unverified. A tool that finds no candidate has not proven the input is not encoded — try the next layer, or a different tool.

The plugin also ships a challenge board in the Web sidebar (flag/status/notes per challenge, plus a quick codec and a cheat sheet). Mention it when the user wants to track multiple flags; the board is browser-local and the tools do not write to it.`

/** 每个模块用一组候选名找工厂函数，容忍 teammate 之间命名风格的微小差异。 */
function pickFactory(module, candidates) {
  for (const key of candidates) {
    if (typeof module?.[key] === 'function') return module[key]
  }
  for (const [key, value] of Object.entries(module ?? {})) {
    if (typeof value === 'function' && /^create\w*Tool$/.test(key)) return value
  }
  return undefined
}

/**
 * 把一份模块变成一个工具定义，并在名字不符合预期时报错。
 * 工具名是模型侧的稳定契约，拼错比装不上更难排查，所以这里直接炸。
 * `ctx` 传给工厂：`ctf_file` / `ctf_stego` 需要它去解析会话工作目录。
 */
function resolveTool(label, module, candidates, expectedName, ctx) {
  const factory = pickFactory(module, candidates)
  if (factory === undefined) {
    throw new Error(`ctf-kit: ${label} does not export a tool factory (checked: ${candidates.join(', ')})`)
  }
  const definition = factory(ctx)
  if (definition === null || typeof definition !== 'object') {
    throw new Error(`ctf-kit: ${label} factory returned ${typeof definition}`)
  }
  if (definition.name !== expectedName) {
    throw new Error(`ctf-kit: ${label} registered tool name ${JSON.stringify(definition.name)}, expected ${JSON.stringify(expectedName)}`)
  }
  return definition
}

/**
 * 组装全部工具定义。导出给测试用：不需要起 DSH 就能跑真实工具。
 * @param {any} [ctx] 插件上下文；省略时工具退回进程目录（冒烟测试就是这么跑的）
 * @returns {Array<object>} 工具定义数组
 */
export function buildTools(ctx) {
  return [
    resolveTool('codec.js', codecModule, ['createCodecTool', 'createDecodeTool', 'createCodec'], 'ctf_codec', ctx),
    resolveTool('cipher.js', cipherModule, ['createCipherTool', 'createCipher'], 'ctf_cipher', ctx),
    resolveTool('hash.js', hashModule, ['createHashTool', 'createHash'], 'ctf_hash', ctx),
    resolveTool('forensics.js', forensicsModule, ['createFileTool', 'createForensicsTool', 'createFile'], 'ctf_file', ctx),
    resolveTool('stego.js', stegoModule, ['createStegoTool', 'createStego'], 'ctf_stego', ctx),
    resolveTool('web.js', webModule, ['createJwtTool', 'createWebTool', 'createJwt'], 'ctf_jwt', ctx),
    resolveTool('pwn.js', pwnModule, ['createPwnTool', 'createPwn'], 'ctf_pwn', ctx),
  ]
}

export function apply(ctx) {
  const tools = buildTools(ctx)
  for (const definition of tools) {
    ctx.effect(() => ctx.tools.register(definition))
  }

  const systemPrompt = ctx.get('systemPrompt')
  if (systemPrompt !== undefined) {
    ctx.effect(() => systemPrompt.section({
      name: 'ctf-kit-toolkit',
      order: 890,
      text: PROMPT_SECTION,
    }))
  }
}
