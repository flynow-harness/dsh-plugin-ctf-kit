/**
 * CTF 工具箱的共享底座：模型侧输出契约、字节/十六进制/二进制互转、可打印性打分、
 * 路径解析与宽度对齐表格。
 *
 * 这里只依赖 Node 内置模块，刻意不引第三方库：插件装载发生在 DSH 进程里，
 * 一个缺失依赖会让整个 profile 起不来，而 CTF 里这些换算本来就不需要外部库。
 */
import { readFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

/** 本 bundle 所有工具共用的模型侧输出形状：一段可直接阅读的 Markdown 文本。 */
export const TEXT_OUTPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    text: { type: 'string', description: 'Human-readable report for the model and the user.' },
  },
  required: ['text'],
}

/**
 * 构造工具定义的 `output` 字段：把 `{ text }` 渲染成一个文本内容块。
 * @param {string} [title] 预留的展示标题（当前仅作文档用）
 */
export function textOutput(title) {
  void title
  return {
    schema: TEXT_OUTPUT_SCHEMA,
    render(_args, value) {
      return [{ type: 'text', text: String(value?.text ?? '') }]
    },
  }
}

/** 展开开头的 `~`，并规范化结果。 */
export function expandHome(input) {
  if (typeof input !== 'string' || input.length === 0) return input
  if (input === '~') return os.homedir()
  if (input.startsWith('~/')) return path.join(os.homedir(), input.slice(2))
  return input
}

/**
 * 把用户给的路径解析成绝对路径：相对路径基于会话工作目录。
 * @param {string | undefined} input 用户输入（可为相对路径、可含 `~`）
 * @param {string} cwd 会话工作目录
 */
export function resolveUserPath(input, cwd) {
  const raw = typeof input === 'string' && input.trim().length > 0 ? input.trim() : ''
  if (raw.length === 0) return cwd
  return path.resolve(cwd, expandHome(raw))
}

/** 读取二进制文件，失败时返回 `{ ok: false, error }` 而不是抛错。 */
export async function readBytesSafe(target) {
  try {
    const buffer = await readFile(target)
    return { ok: true, bytes: new Uint8Array(buffer) }
  } catch (error) {
    const code = error?.code ?? 'UNKNOWN'
    const reason = error?.message ?? String(error)
    return { ok: false, error: `${code}: ${reason}` }
  }
}

/** 人类可读的字节数，用于报告文件大小。 */
export function formatBytes(value) {
  const n = Number(value) || 0
  if (n < 1024) return `${n} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let size = n / 1024
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${size.toFixed(2)} ${units[unit]}`
}

/** 把整数夹到闭区间，非法输入返回 fallback。 */
export function clampInt(value, min, max, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(max, Math.max(min, parsed))
}

/** 判断一个字节是否是可打印 ASCII（含制表/换行在外部的单独处理）。 */
export function isPrintableAscii(code) {
  return code >= 0x20 && code <= 0x7e
}

/**
 * 把十六进制字符串解析成字节。宽容处理大小写、空格、`0x` 前缀、`\x41` 转义、
 * 逗号和下划线；长度为奇数时抛出可读错误。
 * @param {string} input 十六进制文本
 * @returns {Uint8Array}
 */
export function hexToBytes(input) {
  if (typeof input !== 'string') throw new Error('hex input must be a string')
  let cleaned = input
    .replace(/\\x/gi, '')
    .replace(/0x/gi, '')
    .replace(/[\s,;:_-]/g, '')
  if (cleaned.length === 0) return new Uint8Array(0)
  if (!/^[0-9a-fA-F]+$/.test(cleaned)) {
    const bad = cleaned.split('').find((char) => !/[0-9a-fA-F]/.test(char))
    throw new Error(`not a hex string: unexpected character ${JSON.stringify(bad)}`)
  }
  if (cleaned.length % 2 !== 0) throw new Error('hex string has an odd number of digits')
  const out = new Uint8Array(cleaned.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(cleaned.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

/**
 * 字节转十六进制。
 * @param {Uint8Array} bytes
 * @param {{upper?: boolean, group?: number, prefix?: string}} [options]
 */
export function bytesToHex(bytes, options = {}) {
  const upper = options.upper === true
  const group = options.group ?? 0
  const prefix = options.prefix ?? ''
  const parts = []
  for (const byte of bytes) {
    const text = byte.toString(16).padStart(2, '0')
    parts.push(prefix + (upper ? text.toUpperCase() : text))
  }
  if (group > 0) {
    const grouped = []
    for (let i = 0; i < parts.length; i += group) grouped.push(parts.slice(i, i + group).join(' '))
    return grouped.join('\n')
  }
  return parts.join('')
}

/** 二进制字符串（每字节 8 位）转字节。 */
export function binaryToBytes(input) {
  if (typeof input !== 'string') throw new Error('binary input must be a string')
  const cleaned = input.replace(/[\s_]/g, '')
  if (cleaned.length === 0) return new Uint8Array(0)
  if (!/^[01]+$/.test(cleaned)) throw new Error('binary input may only contain 0 and 1')
  if (cleaned.length % 8 !== 0) throw new Error('binary input length is not a multiple of 8')
  const out = new Uint8Array(cleaned.length / 8)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(cleaned.slice(i * 8, i * 8 + 8), 2)
  }
  return out
}

/** 字节转二进制字符串，默认每 8 位一组、不留分隔。 */
export function bytesToBinary(bytes, separator = '') {
  return [...bytes].map((byte) => byte.toString(2).padStart(8, '0')).join(separator)
}

/** 十进制码点串（如 `72 101 108`）转字节。 */
export function decimalsToBytes(input) {
  const parts = String(input).trim().split(/[\s,;]+/).filter(Boolean)
  return Uint8Array.from(parts.map((part) => {
    const value = Number.parseInt(part, 10)
    if (!Number.isFinite(value) || value < 0 || value > 255) {
      throw new Error(`decimal byte out of range: ${part}`)
    }
    return value
  }))
}

/** UTF-8 解码，替换非法序列而不是抛错——CTF 里半截乱码很常见。 */
export function decodeUtf8(bytes) {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
}

/** UTF-8 编码。 */
export function encodeUtf8(text) {
  return new TextEncoder().encode(text)
}

/**
 * 可打印性打分：给一行解码结果判断「像不像人话」。
 *
 * 打分只做启发式排序，不承诺正确性——它的用途是在一堆候选里把最像答案的排前面，
 * 最终仍由人/模型判断。
 * @param {string} text
 */
export function printableScore(text) {
  const value = String(text ?? '')
  if (value.length === 0) return { score: 0, printable: 0, flagLike: false }
  let printable = 0
  let flagLike = 0
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0
    if (code === 0x09 || code === 0x0a || code === 0x0d || isPrintableAscii(code)) printable += 1
    else if (code > 0x7f) printable += 0.6 // 非 ASCII 可能是合法中文，但不如纯 ASCII 可信
  }
  // 形如 flag{...} / CTF{...} / key= 的片段直接加权：这是 CTF 里最常见的答案形态。
  if (/(?:flag|ctf|key|pass|secret)\s*[\{\(\[=:]/i.test(value)) flagLike = 1
  const ratio = printable / value.length
  const score = Math.round((ratio * 100) + (flagLike === 1 ? 25 : 0))
  return { score, printable: ratio, flagLike: flagLike === 1 }
}

/**
 * 从字节里抽取可打印字符串（like `strings`）。
 * @param {Uint8Array} bytes
 * @param {{minLength?: number, limit?: number}} [options]
 * @returns {Array<{offset: number, text: string}>}
 */
export function extractStrings(bytes, options = {}) {
  const minLength = Math.max(3, options.minLength ?? 4)
  const limit = Math.max(1, options.limit ?? 200)
  const found = []
  let run = []
  let start = 0
  const flush = () => {
    if (run.length >= minLength) found.push({ offset: start, text: run.join('') })
    run = []
  }
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i]
    if (isPrintableAscii(byte) || byte === 0x09) {
      if (run.length === 0) start = i
      run.push(String.fromCharCode(byte))
    } else {
      flush()
    }
    if (found.length >= limit) break
  }
  flush()
  return found
}

/** 把不可打印字节转成 `\xNN` 转义，保证报告里一行不乱码。 */
export function escapeNonPrintable(bytes, limit = 4096) {
  let out = ''
  const end = Math.min(bytes.length, limit)
  for (let i = 0; i < end; i += 1) {
    const byte = bytes[i]
    if (isPrintableAscii(byte) || byte === 0x0a) out += String.fromCharCode(byte)
    else if (byte === 0x0d) continue
    else out += `\\x${byte.toString(16).padStart(2, '0')}`
  }
  if (bytes.length > end) out += `… (${bytes.length - end} more bytes)`
  return out
}

/** 终端显示宽度：CJK 与全角字符占两列。 */
export function displayWidth(text) {
  let width = 0
  for (const char of String(text)) {
    const code = char.codePointAt(0) ?? 0
    const wide = code >= 0x1100 && (
      code <= 0x115f
      || (code >= 0x2e80 && code <= 0xa4cf && code !== 0x303f)
      || (code >= 0xac00 && code <= 0xd7a3)
      || (code >= 0xf900 && code <= 0xfaff)
      || (code >= 0xfe30 && code <= 0xfe6f)
      || (code >= 0xff00 && code <= 0xff60)
      || (code >= 0xffe0 && code <= 0xffe6)
      || (code >= 0x20000 && code <= 0x3fffd)
    )
    width += wide ? 2 : 1
  }
  return width
}

/** 把行数组排成对齐表格（按显示宽度补齐）。 */
export function formatRows(rows, headers) {
  const all = headers ? [headers, ...rows] : rows
  const widths = []
  for (const row of all) {
    row.forEach((cell, index) => {
      widths[index] = Math.max(widths[index] ?? 0, displayWidth(cell))
    })
  }
  return all.map((row) => row.map((cell, index) => {
    const text = String(cell)
    return text + ' '.repeat(Math.max(0, (widths[index] ?? 0) - displayWidth(text)))
  }).join('  ').trimEnd()).join('\n')
}

/** 截断长文本用于报告预览。 */
export function preview(text, limit = 240) {
  const value = String(text ?? '')
  if (value.length <= limit) return value
  return `${value.slice(0, limit)}… (${value.length} chars total)`
}

/**
 * 解析工具应该操作的工作目录：优先会话工作目录，取不到则退回进程目录。
 * @param {any} ctx 插件上下文（可能带 workingDirectory 服务）
 * @param {any} exec 工具运行上下文（带 agent）
 */
export function resolveSessionCwd(ctx, exec) {
  try {
    const workingDirectory = typeof ctx?.get === 'function' ? ctx.get('workingDirectory') : undefined
    const session = exec?.agent?.session
    if (workingDirectory !== undefined && session !== undefined) {
      const dir = workingDirectory.get(session)
      if (typeof dir === 'string' && dir.length > 0) return dir
    }
  } catch {
    // 探测类工具绝不能因为取不到目录而失败，退回进程目录。
  }
  return process.cwd()
}
