/**
 * `ctf_codec` — 编解码与编码链自动爆破。
 *
 * CTF 里最耗时的往往不是某个编码本身，而是「这串东西到底是什么、要不要再解一层」。
 * 这里把 16 种常见编码实现成可逆的纯函数（base64/base64url/base32/base16/base85、
 * binary/decimal/octal、URL/HTML 实体、Morse/Bacon/ROT13、quoted-printable、
 * unicode 转义、uuencode），再用深度受限的候选搜索把编码链拼出来：
 * 每一层解码都用共享的 `printableScore` 打分剪枝，最后按「疑似 flag → 无替换字符 →
 * 可读度 → 长度」排序，给出可操作的候选表而不是一堆裸数据。
 *
 * 设计约束：
 * - 只用 Node 内置模块，除 `./util.js` 外不引任何依赖；
 * - `execute` 不向调用方抛原始异常，参数/输入问题一律渲染成中文 Markdown 报告；
 * - 纯函数（`decodeBase64` 等）会抛带中文说明的 `Error`，方便测试与上层复用。
 */
import {
  binaryToBytes,
  bytesToBinary,
  bytesToHex,
  clampInt,
  decodeUtf8,
  encodeUtf8,
  formatRows,
  hexToBytes,
  preview,
  printableScore,
  textOutput,
} from './util.js'

/** `ctf_codec` 的 encoding 枚举；顺序即工具报告里的尝试顺序（高频编码靠前）。 */
export const CODEC_ENCODINGS = Object.freeze([
  'auto',
  'base64',
  'base64url',
  'base32',
  'base16',
  'base85',
  'binary',
  'decimal',
  'octal',
  'url',
  'html',
  'morse',
  'bacon',
  'rot13',
  'quoted-printable',
  'unicode-escape',
  'uuencode',
])

/** 去掉 `auto` 后的具体编码，供自动爆破与枚举校验使用。 */
const CONCRETE_ENCODINGS = CODEC_ENCODINGS.filter((encoding) => encoding !== 'auto')

const BASE64_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const BASE64_URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** Bacon 两套字母表：26 字母版保留 J/U，24 字母版按经典约定合并 I/J 与 U/V。 */
const BACON_ALPHABETS = Object.freeze({
  26: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  24: 'ABCDEFGHIKLMNOPQRSTUVWXYZ',
})

const MORSE_TABLE = Object.freeze({
  A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....',
  I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.',
  Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-',
  Y: '-.--', Z: '--..',
  0: '-----', 1: '.----', 2: '..---', 3: '...--', 4: '....-',
  5: '.....', 6: '-....', 7: '--...', 8: '---..', 9: '----.',
  '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
  '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
  ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
  '"': '.-..-.', '$': '...-..-', '@': '.--.-.',
})

/** 反向莫尔斯表：`.-` → `A`，供解码使用。 */
const MORSE_REVERSE = new Map(Object.entries(MORSE_TABLE).map(([char, code]) => [code, char]))

/** 常见 HTML 命名实体（只收录 CTF 里高频出现的，未知实体保持原样）。 */
const HTML_ENTITIES = Object.freeze({
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0',
  copy: '©', reg: '®', trade: '™', hellip: '…', mdash: '—', ndash: '–',
  lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', middot: '·', bull: '•',
  deg: '°', times: '×', divide: '÷', euro: '€', yen: '¥', cent: '¢', pound: '£',
  sect: '§', para: '¶', dagger: '†', laquo: '«', raquo: '»', plusmn: '±', frac12: '½',
})

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/** 百分比显示。 */
function percent(ratio) {
  return `${Math.round((Number(ratio) || 0) * 100)}%`
}

/**
 * 把任意结果压成单行预览：转义换行/制表/控制字符，并转义 Markdown 表格里的 `|`。
 * @param {unknown} value
 * @param {number} [limit]
 */
function oneLine(value, limit = 110) {
  const text = String(value ?? '')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\t/g, '\\t')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, (char) => `\\x${char.codePointAt(0).toString(16).padStart(2, '0')}`)
    .replace(/\|/g, '\\|')
  return preview(text, limit)
}

/**
 * 把结果放进 Markdown 代码块；过长的结果截断并提示总长度。
 * @param {unknown} value
 * @param {number} [limit]
 */
function blockText(value, limit = 2000) {
  const text = String(value ?? '')
  if (text.length <= limit) return text
  return `${text.slice(0, limit)}\n… (共 ${text.length} 字符，已截断)`
}

/**
 * 校验枚举参数：缺省回退到默认值，非法值抛中文说明。
 * @param {unknown} value
 * @param {readonly string[]} allowed
 * @param {string} fallback
 * @param {string} label
 */
function normalizeEnum(value, allowed, fallback, label) {
  if (value === undefined || value === null || value === '') return fallback
  if (typeof value === 'string' && allowed.includes(value)) return value
  throw new Error(`${label} 只能是：${allowed.join(' / ')}`)
}

/** 把 util 里英文的 hex 错误翻译成可读中文。 */
function hexErrorToChinese(error) {
  const message = String(error?.message ?? '')
  if (message.includes('odd number')) return 'base16/hex 位数为奇数，无法按字节解析'
  if (message.includes('unexpected character')) return 'base16/hex 含非十六进制字符（只允许 0-9a-fA-F）'
  if (message.includes('must be a string')) return 'base16/hex 输入必须是字符串'
  return `base16/hex 解码失败：${message}`
}

/** 把 util 里英文的 binary 错误翻译成可读中文。 */
function binaryErrorToChinese(error) {
  const message = String(error?.message ?? '')
  if (message.includes('only contain 0 and 1')) return '二进制字符串只能包含 0 和 1'
  if (message.includes('multiple of 8')) return '二进制字符串长度不是 8 的倍数，无法按字节解析'
  if (message.includes('must be a string')) return '二进制输入必须是字符串'
  return `二进制解码失败：${message}`
}

// ---------------------------------------------------------------------------
// base64 / base64url
// ---------------------------------------------------------------------------

/**
 * 把输入整理成 base64 兼容文本：去掉 data URL 前缀与空白，把 URL-safe 字符
 * `-`/`_` 统一成 `+`/`/`（两种字母表解码结果相同，所以解码侧可以共用）。
 * @param {unknown} input
 */
function normalizeBase64Input(input) {
  const raw = String(input ?? '')
  const dataUrl = /^data:[^,]*;base64,/i.exec(raw)
  const body = dataUrl ? raw.slice(dataUrl[0].length) : raw
  return body.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
}

/**
 * 字节转 base64。
 * @param {Uint8Array} bytes
 * @param {string} alphabet
 * @param {{pad?: boolean}} [options]
 */
function bytesToBase64(bytes, alphabet, options = {}) {
  const pad = options.pad !== false
  let out = ''
  for (let index = 0; index < bytes.length; index += 3) {
    const b0 = bytes[index]
    const b1 = bytes[index + 1]
    const b2 = bytes[index + 2]
    const hasSecond = b1 !== undefined
    const hasThird = b2 !== undefined
    out += alphabet[b0 >> 2]
    out += alphabet[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)]
    out += hasSecond ? alphabet[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)] : (pad ? '=' : '')
    out += hasThird ? alphabet[b2 & 0x3f] : (pad ? '=' : '')
  }
  return out
}

/**
 * base64 解码（宽容空白、缺省 padding、URL-safe 字符与 data URL 前缀）。
 * @param {unknown} input
 * @returns {string} 按 UTF-8 解出的文本（非法序列用替换字符表示）
 */
export function decodeBase64(input) {
  const cleaned = normalizeBase64Input(input).replace(/=+$/, '')
  if (cleaned.length === 0) throw new Error('base64 输入为空')
  const bad = [...cleaned].find((char) => !BASE64_STD.includes(char))
  if (bad !== undefined) throw new Error(`base64 含非法字符 ${JSON.stringify(bad)}`)
  if (cleaned.length % 4 === 1) throw new Error('base64 长度非法（长度模 4 余 1）')
  const out = new Uint8Array(Math.floor((cleaned.length * 3) / 4))
  const value = (char) => BASE64_STD.indexOf(char)
  let offset = 0
  let index = 0
  for (; index + 4 <= cleaned.length; index += 4) {
    const chunk = (value(cleaned[index]) << 18)
      | (value(cleaned[index + 1]) << 12)
      | (value(cleaned[index + 2]) << 6)
      | value(cleaned[index + 3])
    out[offset++] = (chunk >> 16) & 0xff
    out[offset++] = (chunk >> 8) & 0xff
    out[offset++] = chunk & 0xff
  }
  const remainder = cleaned.length - index
  if (remainder === 2) {
    out[offset++] = ((value(cleaned[index]) << 2) | (value(cleaned[index + 1]) >> 4)) & 0xff
  } else if (remainder === 3) {
    const chunk = (value(cleaned[index]) << 12)
      | (value(cleaned[index + 1]) << 6)
      | value(cleaned[index + 2])
    out[offset++] = (chunk >> 10) & 0xff
    out[offset++] = (chunk >> 2) & 0xff
  }
  return decodeUtf8(out.subarray(0, offset))
}

/**
 * 编码成标准 base64（带 padding）。
 * @param {unknown} input
 */
export function encodeBase64(input) {
  return bytesToBase64(encodeUtf8(String(input ?? '')), BASE64_STD)
}

/**
 * 编码成 base64url（不带 padding）。
 * @param {unknown} input
 */
export function encodeBase64Url(input) {
  return bytesToBase64(encodeUtf8(String(input ?? '')), BASE64_URL, { pad: false })
}

// ---------------------------------------------------------------------------
// base32（RFC 4648，手写实现，解码容忍缺省 padding 与小写）
// ---------------------------------------------------------------------------

/**
 * 编码成 RFC 4648 base32（`A-Z2-7`，按 8 字符补齐 padding）。
 * @param {unknown} input
 */
export function encodeBase32(input) {
  const bytes = encodeUtf8(String(input ?? ''))
  let bits = 0
  let buffer = 0
  let out = ''
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 0x1f]
      bits -= 5
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f]
  while (out.length % 8 !== 0) out += '='
  return out
}

/**
 * 解码 RFC 4648 base32：容忍空白、缺省 padding、大小写混写。
 * @param {unknown} input
 * @returns {string}
 */
export function decodeBase32(input) {
  let cleaned = String(input ?? '').replace(/\s+/g, '').replace(/=+$/, '')
  if (cleaned.length === 0) throw new Error('base32 输入为空')
  cleaned = cleaned.toUpperCase()
  const bad = [...cleaned].find((char) => !BASE32_ALPHABET.includes(char))
  if (bad !== undefined) throw new Error(`base32 含非法字符 ${JSON.stringify(bad)}（只允许 A-Z 与 2-7）`)
  const remainder = cleaned.length % 8
  if (remainder === 1 || remainder === 3 || remainder === 6) {
    throw new Error('base32 长度非法（不可能是合法的分组余数）')
  }
  const out = new Uint8Array(Math.floor((cleaned.length * 5) / 8))
  let bits = 0
  let buffer = 0
  let offset = 0
  for (const char of cleaned) {
    buffer = (buffer << 5) | BASE32_ALPHABET.indexOf(char)
    bits += 5
    if (bits >= 8) {
      out[offset++] = (buffer >>> (bits - 8)) & 0xff
      bits -= 8
    }
  }
  return decodeUtf8(out.subarray(0, offset))
}

// ---------------------------------------------------------------------------
// base16 / hex
// ---------------------------------------------------------------------------

/**
 * 十六进制解码成文本（复用 util 的 hexToBytes，错误信息转中文）。
 * @param {unknown} input
 */
export function decodeBase16(input) {
  try {
    return decodeUtf8(hexToBytes(String(input ?? '')))
  } catch (error) {
    throw new Error(hexErrorToChinese(error))
  }
}

/**
 * 文本编码成小写十六进制。
 * @param {unknown} input
 */
export function encodeBase16(input) {
  return bytesToHex(encodeUtf8(String(input ?? '')))
}

/** base16 就是 hex 的别名。 */
export const decodeHex = decodeBase16
/** base16 就是 hex 的别名。 */
export const encodeHex = encodeBase16

// ---------------------------------------------------------------------------
// ASCII85 / base85
// ---------------------------------------------------------------------------

/**
 * 编码成 ASCII85（不带 `<~ ~>` 包裹；全零 4 字节组压缩成 `z`）。
 * @param {unknown} input
 */
export function encodeAscii85(input) {
  const bytes = encodeUtf8(String(input ?? ''))
  let out = ''
  for (let index = 0; index < bytes.length; index += 4) {
    const chunk = [bytes[index], bytes[index + 1], bytes[index + 2], bytes[index + 3]]
    const length = chunk.filter((byte) => byte !== undefined).length
    let value = 0
    for (let slot = 0; slot < 4; slot += 1) value = value * 256 + (chunk[slot] ?? 0)
    if (length === 4 && value === 0) {
      out += 'z'
      continue
    }
    const digits = []
    for (let slot = 4; slot >= 0; slot -= 1) {
      digits[slot] = String.fromCharCode((value % 85) + 33)
      value = Math.floor(value / 85)
    }
    out += length === 4 ? digits.join('') : digits.slice(0, length + 1).join('')
  }
  return out
}

/**
 * 解码 ASCII85：容忍空白与可选的 `<~ ~>` 包裹，支持 `z` 全零缩写。
 * @param {unknown} input
 * @returns {string}
 */
export function decodeAscii85(input) {
  let text = String(input ?? '').replace(/\s+/g, '')
  if (text.startsWith('<~')) text = text.slice(2)
  if (text.endsWith('~>')) text = text.slice(0, -2)
  if (text.length === 0) throw new Error('ascii85 输入为空')
  const out = []
  let group = []
  const pushGroup = (values) => {
    const value = ((((values[0] * 85) + values[1]) * 85 + values[2]) * 85 + values[3]) * 85 + values[4]
    if (value > 0xffffffff) throw new Error('ascii85 分组数值溢出（不是合法的 ASCII85 数据）')
    out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff)
  }
  for (const char of text) {
    if (char === 'z') {
      if (group.length > 0) throw new Error('ascii85 的 z 只能出现在分组边界')
      out.push(0, 0, 0, 0)
      continue
    }
    const code = char.charCodeAt(0)
    if (code < 33 || code > 117) throw new Error(`ascii85 含非法字符 ${JSON.stringify(char)}（只允许 ! 到 u）`)
    group.push(code - 33)
    if (group.length === 5) {
      pushGroup(group)
      group = []
    }
  }
  if (group.length === 1) throw new Error('ascii85 末尾分组只剩 1 个字符，无法解析')
  if (group.length > 0) {
    const meaningful = group.length - 1
    while (group.length < 5) group.push(84)
    const before = out.length
    pushGroup(group)
    out.length = before + meaningful
  }
  return decodeUtf8(Uint8Array.from(out))
}

/** base85 按 ASCII85 处理。 */
export const decodeBase85 = decodeAscii85
/** base85 按 ASCII85 处理。 */
export const encodeBase85 = encodeAscii85

// ---------------------------------------------------------------------------
// binary / decimal / octal
// ---------------------------------------------------------------------------

/**
 * 二进制串解码成文本（复用 util 的 binaryToBytes，错误信息转中文）。
 * @param {unknown} input
 */
export function decodeBinary(input) {
  try {
    return decodeUtf8(binaryToBytes(String(input ?? '')))
  } catch (error) {
    throw new Error(binaryErrorToChinese(error))
  }
}

/**
 * 文本编码成二进制串（每字节 8 位，不留分隔符）。
 * @param {unknown} input
 */
export function encodeBinary(input) {
  return bytesToBinary(encodeUtf8(String(input ?? '')))
}

/**
 * 十进制码串解码成文本：全部片段 ≤255 时按字节解释，否则按 Unicode 码点解释
 * （中文常见 `20013 25991` 这种写法，两种都能还原）。
 * @param {unknown} input
 * @returns {string}
 */
export function decodeDecimal(input) {
  const parts = String(input ?? '').trim().split(/[\s,;:]+/).filter(Boolean)
  if (parts.length === 0) throw new Error('decimal 输入为空')
  const values = parts.map((part) => {
    if (!/^\d+$/.test(part)) throw new Error(`decimal 含非数字片段 ${JSON.stringify(part)}`)
    return Number.parseInt(part, 10)
  })
  if (values.some((value) => value > 0x10ffff)) throw new Error('decimal 码点超出 Unicode 范围')
  if (values.every((value) => value <= 255)) return decodeUtf8(Uint8Array.from(values))
  try {
    return String.fromCodePoint(...values)
  } catch {
    throw new Error('decimal 码点序列非法')
  }
}

/**
 * 文本编码成十进制字节串（空格分隔）。
 * @param {unknown} input
 */
export function encodeDecimal(input) {
  return [...encodeUtf8(String(input ?? ''))].join(' ')
}

/**
 * 八进制码串解码成文本：支持空格/逗号分隔，也支持 `\101\102` 这类转义写法。
 * @param {unknown} input
 * @returns {string}
 */
export function decodeOctal(input) {
  const raw = String(input ?? '')
  if (raw.trim().length === 0) throw new Error('octal 输入为空')
  const normalized = raw
    .replace(/\\[0-7]{1,3}/g, (match) => ` ${match.slice(1)} `)
    .replace(/0o/gi, ' ')
  const parts = normalized.trim().split(/[\s,;:]+/).filter(Boolean)
  if (parts.length === 0) throw new Error('octal 输入为空')
  const bytes = parts.map((part) => {
    if (!/^[0-7]{1,3}$/.test(part)) throw new Error(`octal 片段非法 ${JSON.stringify(part)}（只允许 0-7，最多 3 位）`)
    const value = Number.parseInt(part, 8)
    if (value > 255) throw new Error(`octal 字节越界：${part}（最大 377）`)
    return value
  })
  return decodeUtf8(Uint8Array.from(bytes))
}

/**
 * 文本编码成三位八进制字节串（空格分隔）。
 * @param {unknown} input
 */
export function encodeOctal(input) {
  return [...encodeUtf8(String(input ?? ''))]
    .map((byte) => byte.toString(8).padStart(3, '0'))
    .join(' ')
}

// ---------------------------------------------------------------------------
// URL / HTML
// ---------------------------------------------------------------------------

/**
 * URL 百分号解码：`+` 视为空格，非法转义抛中文错误。
 * @param {unknown} input
 */
export function decodeUrl(input) {
  const text = String(input ?? '')
  if (text.length === 0) throw new Error('url 输入为空')
  try {
    return decodeURIComponent(text.replace(/\+/g, ' '))
  } catch (error) {
    throw new Error(`URL 解码失败：${error?.message ?? '百分号转义不完整'}`)
  }
}

/**
 * URL 编码（`encodeURIComponent`）。
 * @param {unknown} input
 */
export function encodeUrl(input) {
  try {
    return encodeURIComponent(String(input ?? ''))
  } catch {
    throw new Error('URL 编码失败：输入含非法 UTF-16 代理项')
  }
}

/**
 * HTML 实体解码：支持命名实体与 `&#DDDD;` / `&#xHHHH;`，未知实体保持原样。
 * @param {unknown} input
 */
export function decodeHtml(input) {
  const text = String(input ?? '')
  if (text.length === 0) throw new Error('html 输入为空')
  return text.replace(/&#x([0-9a-f]+);|&#(\d+);|&([a-z][a-z0-9]*);/gi, (match, hex, decimal, name) => {
    if (hex !== undefined) {
      const code = Number.parseInt(hex, 16)
      return code <= 0x10ffff ? String.fromCodePoint(code) : match
    }
    if (decimal !== undefined) {
      const code = Number.parseInt(decimal, 10)
      return code <= 0x10ffff ? String.fromCodePoint(code) : match
    }
    const key = String(name).toLowerCase()
    return Object.hasOwn(HTML_ENTITIES, key) ? HTML_ENTITIES[key] : match
  })
}

/**
 * HTML 实体编码：转义 `& < > " '`。
 * @param {unknown} input
 */
export function encodeHtml(input) {
  return String(input ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// ---------------------------------------------------------------------------
// Morse / Bacon / ROT13
// ---------------------------------------------------------------------------

/**
 * 归一化莫尔斯输入：统一长/短与分隔符写法。
 * 支持 `. -`、`· −`、`长短` 以及 ` / `、`|` 作为词分隔。
 * @param {unknown} input
 */
function normalizeMorse(input) {
  return String(input ?? '')
    .replace(/[·•．。]/g, '.')
    .replace(/[−–—―]/g, '-')
    .replace(/长/g, '-')
    .replace(/短/g, '.')
}

/**
 * 莫尔斯码解码：字母用空格分隔，单词用 `/`（或 `|`）分隔，容忍多余空白。
 * @param {unknown} input
 * @returns {string} 大写文本
 */
export function decodeMorse(input) {
  const normalized = normalizeMorse(input).trim()
  if (normalized.length === 0) throw new Error('morse 输入为空')
  const words = normalized
    .split(/\s*\/\s*|\s*\|\s*|\r?\n+/)
    .map((word) => word.trim())
    .filter(Boolean)
  if (words.length === 0) throw new Error('morse 输入为空')
  const decodedWords = words.map((word) => {
    const letters = word.split(/\s+/).filter(Boolean).map((code) => {
      const char = MORSE_REVERSE.get(code)
      if (char === undefined) throw new Error(`莫尔斯码无法识别的码字 ${JSON.stringify(code)}`)
      return char
    })
    return letters.join('')
  })
  return decodedWords.join(' ')
}

/**
 * 莫尔斯码编码：字母之间空格，单词之间 ` / `。
 * @param {unknown} input
 */
export function encodeMorse(input) {
  const words = String(input ?? '').toUpperCase().split(/\s+/).filter(Boolean)
  if (words.length === 0) throw new Error('morse 编码输入为空')
  return words.map((word) => [...word].map((char) => {
    const code = MORSE_TABLE[char]
    if (code === undefined) throw new Error(`莫尔斯码不支持字符 ${JSON.stringify(char)}`)
    return code
  }).join(' ')).join(' / ')
}

/**
 * Bacon 解码：5 位一组，A/B 或 0/1 均可；默认 26 字母表，可切 24 字母表。
 * @param {unknown} input
 * @param {{variant?: 24 | 26}} [options]
 * @returns {string}
 */
export function decodeBacon(input, options = {}) {
  const variant = options.variant === 24 ? 24 : 26
  const alphabet = BACON_ALPHABETS[variant]
  let cleaned = String(input ?? '').replace(/\s+/g, '')
  if (cleaned.length === 0) throw new Error('bacon 输入为空')
  cleaned = cleaned.toUpperCase().replace(/0/g, 'A').replace(/1/g, 'B')
  const bad = [...cleaned].find((char) => char !== 'A' && char !== 'B')
  if (bad !== undefined) throw new Error(`bacon 输入只能包含 A/B 或 0/1，遇到 ${JSON.stringify(bad)}`)
  if (cleaned.length % 5 !== 0) throw new Error('bacon 输入长度不是 5 的倍数')
  let out = ''
  for (let index = 0; index < cleaned.length; index += 5) {
    let value = 0
    for (const char of cleaned.slice(index, index + 5)) value = value * 2 + (char === 'B' ? 1 : 0)
    const letter = alphabet[value]
    if (letter === undefined) throw new Error(`bacon 分组超出字母表范围（variant=${variant}）`)
    out += letter
  }
  return out
}

/**
 * Bacon 编码：字母按 26 字母表转 5 位，A 表示 0、B 表示 1；非字母字符会被跳过并报错。
 * @param {unknown} input
 * @param {{variant?: 24 | 26}} [options]
 */
export function encodeBacon(input, options = {}) {
  const variant = options.variant === 24 ? 24 : 26
  const alphabet = BACON_ALPHABETS[variant]
  const text = String(input ?? '').toUpperCase()
  if (text.length === 0) throw new Error('bacon 编码输入为空')
  let out = ''
  for (const char of text) {
    if (/\s/.test(char)) {
      out += ' '
      continue
    }
    const index = alphabet.indexOf(char)
    if (index < 0) throw new Error(`bacon 编码不支持字符 ${JSON.stringify(char)}（variant=${variant}）`)
    out += index.toString(2).padStart(5, '0').replace(/0/g, 'A').replace(/1/g, 'B')
  }
  return out
}

/**
 * ROT13：字母自反移位，编码与解码是同一个操作。
 * @param {unknown} input
 */
export function rot13(input) {
  return String(input ?? '').replace(/[a-z]/gi, (char) => {
    const base = char <= 'Z' ? 'A'.codePointAt(0) : 'a'.codePointAt(0)
    return String.fromCharCode(((char.codePointAt(0) - base + 13) % 26) + base)
  })
}

// ---------------------------------------------------------------------------
// quoted-printable
// ---------------------------------------------------------------------------

/**
 * quoted-printable 解码：去掉软换行 `=\n`，把 `=XX` 还原成字节后按 UTF-8 解出。
 * @param {unknown} input
 * @returns {string}
 */
export function decodeQuotedPrintable(input) {
  const text = String(input ?? '').replace(/=\r?\n/g, '')
  if (text.length === 0) throw new Error('quoted-printable 输入为空')
  const bytes = []
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]
    if (char !== '=') {
      const charBytes = encodeUtf8(char)
      for (const byte of charBytes) bytes.push(byte)
      continue
    }
    const hex = text.slice(index + 1, index + 3)
    if (!/^[0-9A-Fa-f]{2}$/.test(hex)) {
      throw new Error(`quoted-printable 转义不完整：${JSON.stringify(text.slice(index, index + 3))}`)
    }
    bytes.push(Number.parseInt(hex, 16))
    index += 2
  }
  return decodeUtf8(Uint8Array.from(bytes))
}

/**
 * quoted-printable 编码：可打印 ASCII 原样保留，其余字节转 `=XX`，按 76 列软换行。
 * @param {unknown} input
 */
export function encodeQuotedPrintable(input) {
  const tokens = []
  for (const byte of encodeUtf8(String(input ?? ''))) {
    if (byte >= 0x21 && byte <= 0x7e && byte !== 0x3d) {
      tokens.push(String.fromCharCode(byte))
    } else if (byte === 0x20 || byte === 0x09) {
      tokens.push(String.fromCharCode(byte))
    } else {
      tokens.push(`=${byte.toString(16).toUpperCase().padStart(2, '0')}`)
    }
  }
  const lines = []
  let line = ''
  for (const token of tokens) {
    if (line.length + token.length > 75) {
      lines.push(`${line}=`)
      line = ''
    }
    line += token
  }
  lines.push(line)
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// unicode 转义
// ---------------------------------------------------------------------------

/**
 * `\uXXXX` / `\u{...}` / `\xXX` / 常见控制转义 解码。
 * @param {unknown} input
 * @returns {string}
 */
export function decodeUnicodeEscape(input) {
  const text = String(input ?? '')
  if (text.length === 0) throw new Error('unicode-escape 输入为空')
  if (!text.includes('\\')) throw new Error('unicode-escape 输入里没有反斜杠转义')
  const simple = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', '0': '\0', '\\': '\\', "'": "'", '"': '"' }
  let out = ''
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]
    if (char !== '\\') {
      out += char
      continue
    }
    const next = text[index + 1]
    if (next === undefined) throw new Error('unicode-escape 输入以孤立的反斜杠结尾')
    if (next === 'u') {
      if (text[index + 2] === '{') {
        const close = text.indexOf('}', index + 3)
        if (close < 0) throw new Error('unicode-escape 的 \\u{...} 缺少右花括号')
        const hex = text.slice(index + 3, close)
        if (!/^[0-9A-Fa-f]{1,6}$/.test(hex)) throw new Error(`unicode-escape 的 \\u{...} 内含非法十六进制 ${JSON.stringify(hex)}`)
        out += String.fromCodePoint(Number.parseInt(hex, 16))
        index = close
      } else {
        const hex = text.slice(index + 2, index + 6)
        if (!/^[0-9A-Fa-f]{4}$/.test(hex)) throw new Error(`unicode-escape 的 \\u 转义需要 4 位十六进制，得到 ${JSON.stringify(hex)}`)
        out += String.fromCharCode(Number.parseInt(hex, 16))
        index += 5
      }
    } else if (next === 'x') {
      const hex = text.slice(index + 2, index + 4)
      if (!/^[0-9A-Fa-f]{2}$/.test(hex)) throw new Error(`unicode-escape 的 \\x 转义需要 2 位十六进制，得到 ${JSON.stringify(hex)}`)
      out += String.fromCharCode(Number.parseInt(hex, 16))
      index += 3
    } else if (Object.hasOwn(simple, next)) {
      out += simple[next]
      index += 1
    } else {
      throw new Error(`unicode-escape 无法识别的转义序列 ${JSON.stringify(`\\${next}`)}`)
    }
  }
  return out
}

/**
 * 把文本转成 `\uXXXX` 转义：可打印 ASCII 原样保留，反斜杠与控制字符转义。
 * @param {unknown} input
 */
export function encodeUnicodeEscape(input) {
  let out = ''
  for (const char of String(input ?? '')) {
    const code = char.codePointAt(0)
    if (char === '\\') out += '\\\\'
    else if (char === '\n') out += '\\n'
    else if (char === '\r') out += '\\r'
    else if (char === '\t') out += '\\t'
    else if (code >= 0x20 && code <= 0x7e) out += char
    else if (code <= 0xffff) out += `\\u${code.toString(16).padStart(4, '0')}`
    else out += `\\u{${code.toString(16)}}`
  }
  return out
}

// ---------------------------------------------------------------------------
// uuencode
// ---------------------------------------------------------------------------

/**
 * uuencode 解码：支持 `begin ... end` 包裹，也容忍只有数据行的裸输入。
 * @param {unknown} input
 * @returns {string}
 */
export function decodeUuencode(input) {
  const lines = String(input ?? '').replace(/\r\n?/g, '\n').split('\n')
  if (lines.length === 0) throw new Error('uuencode 输入为空')
  let beginIndex = -1
  for (let index = 0; index < lines.length; index += 1) {
    if (/^begin\s+\d{3}\s*\S*/.test(lines[index].trim())) {
      beginIndex = index
      break
    }
  }
  let endIndex = lines.length
  for (let index = beginIndex + 1; index < lines.length; index += 1) {
    if (/^end\s*$/.test(lines[index].trim())) {
      endIndex = index
      break
    }
  }
  const body = lines.slice(beginIndex + 1, endIndex)
  if (body.length === 0) throw new Error('uuencode 输入里没有数据行')
  const out = []
  for (const rawLine of body) {
    if (rawLine.length === 0) continue
    const first = rawLine.charCodeAt(0)
    if (first < 0x20 || first > 0x60) throw new Error('uuencode 数据行的长度字段非法')
    const count = (first - 0x20) & 0x3f
    if (count === 0) continue
    if (count > 45) throw new Error(`uuencode 数据行长度字段非法（${count} > 45）`)
    const encoded = rawLine.slice(1)
    if (encoded.length < Math.ceil(count / 3) * 4) throw new Error('uuencode 数据行长度不足')
    const produced = []
    for (let offset = 0; offset < encoded.length && produced.length < count; offset += 4) {
      const group = encoded.slice(offset, offset + 4)
      if (group.length < 4) throw new Error('uuencode 数据行末尾分组不完整')
      const values = []
      for (const char of group) {
        const code = char.charCodeAt(0)
        if (code < 0x20 || code > 0x60) throw new Error(`uuencode 数据含非法字符 ${JSON.stringify(char)}`)
        values.push((code - 0x20) & 0x3f)
      }
      const chunk = (values[0] << 18) | (values[1] << 12) | (values[2] << 6) | values[3]
      produced.push((chunk >> 16) & 0xff, (chunk >> 8) & 0xff, chunk & 0xff)
    }
    out.push(...produced.slice(0, count))
  }
  if (out.length === 0) throw new Error('uuencode 没有解出任何字节')
  return decodeUtf8(Uint8Array.from(out))
}

/**
 * uuencode 编码：输出标准 `begin 644 <name> ... end` 包裹的数据。
 * @param {unknown} input
 * @param {{name?: string}} [options]
 */
export function encodeUuencode(input, options = {}) {
  const name = options.name ?? 'ctf.txt'
  const bytes = encodeUtf8(String(input ?? ''))
  const lines = [`begin 644 ${name}`]
  for (let start = 0; start < bytes.length; start += 45) {
    const chunk = bytes.subarray(start, start + 45)
    const encoded = []
    for (let index = 0; index < chunk.length; index += 3) {
      const b0 = chunk[index]
      const b1 = chunk[index + 1] ?? 0
      const b2 = chunk[index + 2] ?? 0
      const value = (b0 << 16) | (b1 << 8) | b2
      for (const shift of [18, 12, 6, 0]) {
        const part = (value >> shift) & 0x3f
        encoded.push(part === 0 ? '`' : String.fromCharCode(part + 0x20))
      }
    }
    lines.push(String.fromCharCode((chunk.length & 0x3f) + 0x20) + encoded.join(''))
  }
  lines.push('`')
  lines.push('end')
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// 编解码注册表 + 自动爆破
// ---------------------------------------------------------------------------

/** 具体编码 → 解码函数。 */
const CODEC_DECODERS = Object.freeze({
  base64: decodeBase64,
  base64url: decodeBase64,
  base32: decodeBase32,
  base16: decodeBase16,
  base85: decodeAscii85,
  binary: decodeBinary,
  decimal: decodeDecimal,
  octal: decodeOctal,
  url: decodeUrl,
  html: decodeHtml,
  morse: decodeMorse,
  bacon: decodeBacon,
  rot13,
  'quoted-printable': decodeQuotedPrintable,
  'unicode-escape': decodeUnicodeEscape,
  uuencode: decodeUuencode,
})

/** 具体编码 → 编码函数。 */
const CODEC_ENCODERS = Object.freeze({
  base64: encodeBase64,
  base64url: encodeBase64Url,
  base32: encodeBase32,
  base16: encodeBase16,
  base85: encodeAscii85,
  binary: encodeBinary,
  decimal: encodeDecimal,
  octal: encodeOctal,
  url: encodeUrl,
  html: encodeHtml,
  morse: encodeMorse,
  bacon: encodeBacon,
  rot13,
  'quoted-printable': encodeQuotedPrintable,
  'unicode-escape': encodeUnicodeEscape,
  uuencode: encodeUuencode,
})

/** 自动爆破每层最多保留的候选数（beam search 宽度）。 */
const BEAM_WIDTH = 16
/** 记录为候选的最低可打印度。 */
const RECORD_PRINTABLE = 0.6
/** 允许继续往下解一层的最低可打印度。 */
const RECURSE_PRINTABLE = 0.85
/** 单次自动爆破的尝试次数上限，防止恶意输入拖死会话。 */
const MAX_ATTEMPTS = 8000
/** 超过这个长度的中间结果不再继续递归。 */
const MAX_RECURSE_LENGTH = 4096
/** 超过这个长度的结果直接丢弃，避免内存放大。 */
const MAX_RESULT_LENGTH = 40000

/**
 * 解码一层；不支持的编码抛中文错误。
 * @param {string} encoding `CODEC_ENCODINGS` 里的具体编码（不含 auto）
 * @param {unknown} text
 */
export function decodeOnce(encoding, text) {
  const decoder = CODEC_DECODERS[encoding]
  if (typeof decoder !== 'function') throw new Error(`不支持的编码 ${JSON.stringify(encoding)}（不支持 auto，需要具体编码）`)
  return decoder(String(text ?? ''))
}

/**
 * 编码一层；不支持的编码抛中文错误。
 * @param {string} encoding `CODEC_ENCODINGS` 里的具体编码（不含 auto）
 * @param {unknown} text
 */
export function encodeOnce(encoding, text) {
  const encoder = CODEC_ENCODERS[encoding]
  if (typeof encoder !== 'function') throw new Error(`不支持的编码 ${JSON.stringify(encoding)}（不支持 auto，需要具体编码）`)
  return encoder(String(text ?? ''))
}

/** 候选排序：疑似 flag 优先 → 无替换字符优先 → 分数高 → 结果短。 */
function compareCandidates(a, b) {
  if (a.flagLike !== b.flagLike) return a.flagLike ? -1 : 1
  if (a.readable !== b.readable) return a.readable ? -1 : 1
  if (b.score !== a.score) return b.score - a.score
  return a.result.length - b.result.length
}

/**
 * 自动解码爆破：对每一层尝试全部解码器，用可打印度剪枝，按深度优先扩展。
 *
 * 这是一个 beam search：每层保留分数最高的若干条中间结果继续往下解，
 * 每一层解出的结果都记录为候选，最后统一排序。它只做启发式排序，
 * 不承诺「第一条就是答案」，所以报告里会给出完整候选表与下一步建议。
 *
 * @param {unknown} input
 * @param {{maxDepth?: number, beamWidth?: number, limit?: number}} [options]
 * @returns {{attempts: number, maxDepth: number, candidates: Array<{path: string[], pathLabel: string, result: string, score: number, printable: number, flagLike: boolean, readable: boolean, depth: number}>}}
 */
export function autoDecode(input, options = {}) {
  const text = String(input ?? '')
  const maxDepth = clampInt(options.maxDepth, 1, 8, 4)
  const beamWidth = clampInt(options.beamWidth, 1, 64, BEAM_WIDTH)
  const limit = clampInt(options.limit, 1, 200, 40)
  let frontier = [{ path: [], text }]
  const seen = new Set([text])
  const candidates = []
  let attempts = 0
  for (let depth = 1; depth <= maxDepth && frontier.length > 0; depth += 1) {
    const next = []
    for (const node of frontier) {
      for (const encoding of CONCRETE_ENCODINGS) {
        if (attempts >= MAX_ATTEMPTS) break
        attempts += 1
        let result
        try {
          result = decodeOnce(encoding, node.text)
        } catch {
          continue
        }
        if (typeof result !== 'string' || result.length === 0 || result === node.text) continue
        if (result.length > MAX_RESULT_LENGTH) continue
        const path = [...node.path, encoding]
        const scored = printableScore(result)
        const candidate = {
          path,
          pathLabel: path.join(' → '),
          result,
          score: scored.score,
          printable: scored.printable,
          flagLike: scored.flagLike,
          readable: !result.includes('\uFFFD'),
          depth,
        }
        if (!seen.has(result)) {
          seen.add(result)
          candidates.push(candidate)
          if (next.length < beamWidth * 4) {
            next.push({ path, text: result, score: scored.score, printable: scored.printable, length: result.length })
          }
        }
      }
      if (attempts >= MAX_ATTEMPTS) break
    }
    // 只有「像文本」的中间结果才值得继续往下解，避免在乱码上指数扩散。
    frontier = next
      .filter((node) => node.printable >= RECURSE_PRINTABLE && node.length <= MAX_RECURSE_LENGTH)
      .sort((a, b) => b.score - a.score)
      .slice(0, beamWidth)
    if (attempts >= MAX_ATTEMPTS) break
  }
  candidates.sort(compareCandidates)
  return { attempts, maxDepth, candidates: candidates.slice(0, limit) }
}

/**
 * 对一次显式解码的结果做「还能不能再解一层」探测。
 * 只保留比当前结果更可信或命中 flag 的下一层。
 * @param {string} result
 * @param {number} currentScore
 */
function nextLayerHints(result, currentScore) {
  const hints = []
  for (const encoding of CONCRETE_ENCODINGS) {
    let nested
    try {
      nested = decodeOnce(encoding, result)
    } catch {
      continue
    }
    if (typeof nested !== 'string' || nested === result) continue
    const scored = printableScore(nested)
    if (scored.flagLike || scored.score > currentScore) {
      hints.push({ encoding, nested, scored })
    }
  }
  hints.sort((a, b) => b.scored.score - a.scored.score)
  return hints.slice(0, 3)
}

// ---------------------------------------------------------------------------
// 报告渲染
// ---------------------------------------------------------------------------

/**
 * 把失败原因渲染成统一的 Markdown 报告（execute 的兜底出口）。
 * @param {string} title
 * @param {unknown} error
 */
function errorReport(title, error) {
  const message = String(error?.message ?? error ?? '未知错误')
  return [
    `# ${title}`,
    '',
    '## 结论',
    `处理失败：${message}`,
    '',
    '## 下一步建议',
    '- 检查 `text` 是否为空、`encoding` 是否在枚举内（也接受 `auto`）。',
    '- 只想解一层时用 `action=decode` 并显式给 `encoding`；想穷举编码链时用 `action=auto`。',
  ].join('\n')
}

/**
 * 渲染自动爆破报告。
 * @param {string} text
 * @param {number} maxDepth
 * @param {ReturnType<typeof autoDecode>} result
 */
function buildAutoReport(text, maxDepth, result) {
  const { attempts, candidates } = result
  const inputScore = printableScore(text)
  const flagged = candidates.filter((candidate) => candidate.flagLike)
  const lines = ['# ctf_codec', '', `动作：auto 编码链爆破 · 输入：${text.length} 字符 · 最大深度：${maxDepth}`, '']
  lines.push('## 结论')
  if (candidates.length === 0) {
    lines.push(`尝试 ${attempts} 次解码，没有得到比输入更可信的结果。`)
    if (inputScore.printable >= 0.95) {
      lines.push('输入本身已经是高可打印文本：可能已是明文，或是需要密钥的古典密码/压缩数据；可改用 `ctf_cipher` 做密码爆破。')
    }
  } else {
    const best = candidates[0]
    lines.push(`尝试 ${attempts} 次解码，得到 ${candidates.length} 条候选${flagged.length > 0 ? `，其中 ${flagged.length} 条疑似答案` : ''}。`)
    lines.push(`最佳候选：${best.pathLabel} → ${oneLine(best.result, 120)}`)
    if (flagged.length > 0) {
      lines.push(`疑似答案路径：${flagged.slice(0, 3).map((candidate) => candidate.pathLabel).join('；')}`)
    } else if (inputScore.printable >= 0.95 && candidates.every((candidate) => !candidate.readable || candidate.score <= inputScore.score + 5)) {
      // rot13 之类的变形总会产生「可打印但没意义」的候选；输入本身已是干净文本时要明确说清楚。
      lines.push(`注意：输入本身已 ${percent(inputScore.printable)} 可打印，候选大多只是字符置换；若它看起来就是明文，优先考虑古典密码/取证工具。`)
    }
  }
  lines.push('')
  lines.push('## 候选')
  if (candidates.length === 0) {
    lines.push('（无候选）')
  } else {
    const rows = candidates.slice(0, 20).map((candidate) => [
      candidate.pathLabel,
      oneLine(candidate.result, 110),
      String(candidate.score),
      candidate.flagLike ? '★ 疑似flag' : (candidate.readable ? '' : '含替换字符'),
    ])
    lines.push(formatRows(rows, ['路径', '结果预览', '分数', '标记']))
    if (candidates.length > 20) lines.push(`（共 ${candidates.length} 条候选，此处只显示前 20 条）`)
  }
  lines.push('')
  lines.push('## 下一步建议')
  if (flagged.length > 0) {
    lines.push('- 先核对「疑似flag」行的内容是否满足题目要求（flag{...}/ctf{...}）；命中即可直接提交。')
    lines.push('- 需要复现某条链路时，按「路径」从左到右逐层用 `action=decode` + 对应 encoding 手工解一遍。')
  } else if (candidates.length > 0) {
    lines.push('- 候选可读度不高：把「路径」列最后一层换成 `action=decode` 手工验证；若结果杂乱，可能还需要 `ctf_cipher` 的古典密码爆破。')
  } else {
    lines.push('- 换一个提示词或直接指定 encoding 再试；如果怀疑是古典密码/压缩/加密数据，用 `ctf_cipher` 或文件取证工具。')
  }
  lines.push('- 只解一层时用 `action=decode`：比 auto 更快，也更容易核对中间结果。')
  return lines.join('\n')
}

/**
 * 渲染单次解码报告。
 * @param {string} text
 * @param {string} encoding
 * @param {string} result
 */
function buildDecodeReport(text, encoding, result) {
  const before = printableScore(text)
  const after = printableScore(result)
  const lines = ['# ctf_codec', '', `动作：decode · 编码：${encoding} · 输入：${text.length} 字符`, '']
  lines.push('## 结论')
  if (result === text) {
    lines.push(`解码后与输入完全相同：这串文本里没有可识别的 ${encoding} 内容。`)
  } else {
    lines.push(`${encoding} 解码成功：${text.length} 字符 → ${result.length} 字符，可打印度 ${percent(after.printable)}${after.flagLike ? '，命中疑似答案' : ''}。`)
    if (after.printable < 0.6) lines.push('结果可打印度偏低：可能解错了编码，或这本身就是二进制/加密数据。')
  }
  lines.push('')
  lines.push('## 结果')
  lines.push('```')
  lines.push(blockText(result))
  lines.push('```')
  lines.push('')
  const hints = result === text ? [] : nextLayerHints(result, after.score)
  lines.push('## 下一步建议')
  if (after.flagLike) {
    lines.push('- 结果里出现 flag/ctf 形态的片段，先核对格式；完整 flag 需要时可用 `preview` 之外的工具继续提字符。')
  }
  if (hints.length > 0) {
    for (const hint of hints) {
      lines.push(`- 看起来还能再解一层：\`encoding=${hint.encoding}\` → ${oneLine(hint.nested, 100)}（分数 ${hint.scored.score}）`)
    }
  }
  if (before.printable < 0.9 && result !== text) {
    lines.push('- 若结果仍像乱码，改用 `action=auto` 让工具枚举编码链。')
  }
  if (lines[lines.length - 1] === '## 下一步建议') {
    lines.push('- 没有发现可继续解码的下一层：结果可能就是最终明文，或需要古典密码/取证工具继续处理。')
  }
  return lines.join('\n')
}

/**
 * 渲染单次编码报告。
 * @param {string} text
 * @param {string} encoding
 * @param {string} result
 */
function buildEncodeReport(text, encoding, result) {
  const lines = ['# ctf_codec', '', `动作：encode · 编码：${encoding} · 输入：${text.length} 字符`, '']
  lines.push('## 结论')
  lines.push(`已用 ${encoding} 编码：${text.length} 字符 → ${result.length} 字符。`)
  lines.push('')
  lines.push('## 结果')
  lines.push('```')
  lines.push(blockText(result))
  lines.push('```')
  lines.push('')
  lines.push('## 下一步建议')
  lines.push(`- 把上面的结果贴回 \`text\` 字段并用 \`action=decode\` + \`encoding=${encoding}\` 可还原验证。`)
  lines.push('- 多条编码串联时（如 base64 → hex），逐层 encode 后把结果作为下一层的输入即可。')
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// 工具定义
// ---------------------------------------------------------------------------

/**
 * 构造 `ctf_codec` 工具定义。
 * @param {any} ctx registrant context
 */
export function createCodecTool(ctx) {
  void ctx
  return {
    name: 'ctf_codec',
    description:
      'Encode, decode, or auto-crack an encoding chain. Supports base64, base64url, base32, base16/hex, base85/ascii85, binary, decimal, octal, URL, HTML entities, Morse, Bacon, ROT13, UUencode, quoted-printable and unicode escapes. Auto mode tries decoders recursively and ranks candidates.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: {
          type: 'string',
          enum: ['decode', 'encode', 'auto'],
          description: 'decode (default): apply one named decoder; encode: apply one named encoder; auto: search encoding chains recursively.',
        },
        text: {
          type: 'string',
          description: 'The string to transform (required).',
        },
        encoding: {
          type: 'string',
          enum: [...CODEC_ENCODINGS],
          description: 'Encoding to use. auto (default) is only valid for decode/auto; encode requires an explicit encoding.',
        },
        maxDepth: {
          type: 'integer',
          minimum: 1,
          maximum: 8,
          description: 'Maximum encoding-chain depth for auto mode (1-8, default 4).',
        },
      },
      required: ['text'],
    },
    output: textOutput('Encoding chain report'),
    async execute(args) {
      try {
        const payload = args !== null && typeof args === 'object' && !Array.isArray(args) ? args : {}
        if (typeof payload.text !== 'string' || payload.text.length === 0) {
          throw new Error('ctf_codec 需要非空的 text 参数（要处理的字符串）')
        }
        const text = payload.text
        const action = normalizeEnum(payload.action, ['decode', 'encode', 'auto'], 'decode', 'action')
        const encoding = normalizeEnum(payload.encoding ?? 'auto', CODEC_ENCODINGS, 'auto', 'encoding')
        const maxDepth = clampInt(payload.maxDepth, 1, 8, 4)

        if (action === 'encode') {
          if (encoding === 'auto') {
            throw new Error('action=encode 时必须显式指定 encoding（auto 只用于解码爆破）')
          }
          return { text: buildEncodeReport(text, encoding, encodeOnce(encoding, text)) }
        }
        if (action === 'auto' || encoding === 'auto') {
          return { text: buildAutoReport(text, maxDepth, autoDecode(text, { maxDepth })) }
        }
        return { text: buildDecodeReport(text, encoding, decodeOnce(encoding, text)) }
      } catch (error) {
        return { text: errorReport('ctf_codec', error) }
      }
    },
  }
}
