/**
 * `ctf_pwn` — Pwn 辅助：hexdump、整数/端序换算、p32/p64 打包、de Bruijn cyclic
 * 生成与偏移查找、坏字符扫描。
 *
 * 设计取向：
 * - 全部是本地纯计算，不启动、不附加、不调试任何进程（不碰 ptrace）。
 * - 端序换算是 pwn 里最容易抄错的一步，因此打包结果同时给出「所选端序」和
 *   「反向端序对照」两种写法，复制 shellcode 前可以肉眼核对。
 * - cyclic 用与 pwntools 相同的 de Bruijn 生成算法（字母表
 *   lowercase + uppercase + digits，周期 4），所以偏移量与 `cyclic_find` 一致；
 *   生成器是惰性的，只有偏移查找才会顺序消费到命中位置。
 */
import {
  bytesToHex,
  clampInt,
  encodeUtf8,
  escapeNonPrintable,
  formatRows,
  hexToBytes,
  isPrintableAscii,
  textOutput,
} from './util.js'

/** 工具支持的 action。 */
const PWN_ACTIONS = ['hexdump', 'pack', 'unpack', 'int', 'cyclic', 'shellcode']
/** pack/unpack 的格式：定宽端序 + 三种自由格式。 */
const PACK_FORMATS = ['le16', 'le32', 'le64', 'be16', 'be32', 'be64', 'hex', 'c-escape', 'python']
/** format → 定宽端序说明；width 为 null 表示没有固定宽度，用最小大端字节表示。 */
const PACK_SPECS = Object.freeze({
  le16: { width: 2, endian: 'le' },
  le32: { width: 4, endian: 'le' },
  le64: { width: 8, endian: 'le' },
  be16: { width: 2, endian: 'be' },
  be32: { width: 4, endian: 'be' },
  be64: { width: 8, endian: 'be' },
  hex: { width: null, endian: 'be' },
  'c-escape': { width: null, endian: 'be' },
  python: { width: null, endian: 'be' },
})
/** pwntools cyclic 默认字母表：小写 + 大写 + 数字，共 62 个字符。 */
const CYCLIC_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
/** cyclic 默认 4 字节周期，对应经典 62^4 个唯一四字节窗口。 */
const CYCLIC_PERIOD = 4
/** de Bruijn(62, 4) 的总长度上限（循环序列展平后的长度）。 */
const CYCLIC_CAPACITY = 62 ** 4
/** cyclic 一次性生成的显示上限，避免把 14MB 字符串塞进模型输出。 */
const CYCLIC_DISPLAY_LIMIT = 1024 * 1024
/** 最经典的三个坏字符：字符串函数与行读取都会在这里截断。 */
const CLASSIC_BAD_CHARS = [0x00, 0x0a, 0x0d]
/** 其他常见的空白/分隔字节，是否算坏字符取决于目标函数的解析方式。 */
const WHITESPACE_BAD_CHARS = [0x09, 0x0b, 0x0c, 0x20]
/** 描述坏字符在真实场景里的后果。 */
const BAD_CHAR_NOTES = Object.freeze({
  0x00: 'NUL，C 字符串终止符：strcpy/strlen/scanf("%s") 会在此截断',
  0x09: 'TAB，部分 scanf/分词器当作空白',
  0x0a: 'LF，行读取（gets/fgets/readline）会在此截断',
  0x0b: 'VT，垂直制表符，部分解析器当作空白',
  0x0c: 'FF，换页符，部分解析器当作空白',
  0x0d: 'CR，行读取会在此截断',
  0x20: '空格，strtok/scanf 会把它当作分隔符',
})

/** 动作归一化：缺省 hexdump，非法值返回 null 由 execute 报错。 */
function normalizeAction(value) {
  if (value === undefined || value === null || value === '') return 'hexdump'
  return typeof value === 'string' && PWN_ACTIONS.includes(value) ? value : null
}

/** 输入解释方式归一化：只区分 hex 与 text，其他值按 hex。 */
function normalizeInputKind(value) {
  return value === 'text' ? 'text' : 'hex'
}

/** format 归一化：缺省 le64；非法值抛中文错误，由 execute 捕获成报告。 */
function normalizeFormat(value, fallback = 'le64') {
  if (value === undefined || value === null || value === '') return fallback
  if (typeof value === 'string' && PACK_FORMATS.includes(value)) return value
  throw new Error(`不支持的 format：${JSON.stringify(value)}（可选 ${PACK_FORMATS.join(', ')}）`)
}

// ---------------------------------------------------------------------------
// 基础换算
// ---------------------------------------------------------------------------

/** 大端/小端字节数组转 BigInt。 */
export function bytesToBigInt(bytes, endian = 'be') {
  let value = 0n
  if (endian === 'le') {
    for (let i = bytes.length - 1; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[i])
  } else {
    for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  }
  return value
}

/** BigInt 的有符号十六进制表示，例如 -0x10。 */
export function bigintHex(value) {
  if (typeof value !== 'bigint') throw new Error('bigintHex 需要 bigint')
  return value < 0n ? `-0x${(-value).toString(16)}` : `0x${value.toString(16)}`
}

/** 表示该值所需的最小字节数（负数按绝对值算，打包时用补码）。 */
function minimalByteWidth(value) {
  const absolute = value < 0n ? -value : value
  const bits = absolute === 0n ? 1 : absolute.toString(2).length
  return Math.max(1, Math.ceil(bits / 8))
}

/**
 * 把整数按指定宽度和端序写成字节；超出宽度时按补码/取模截断。
 * @param {bigint} value
 * @param {number} width 字节宽度
 * @param {'le' | 'be'} endian
 */
export function packBigIntToBytes(value, width, endian) {
  if (typeof value !== 'bigint') throw new Error('packBigIntToBytes 需要 bigint')
  if (!Number.isInteger(width) || width < 1 || width > 64) {
    throw new Error('字节宽度必须是 1..64 的整数')
  }
  if (endian !== 'le' && endian !== 'be') throw new Error("endian 只能是 'le' 或 'be'")
  const modulus = 1n << BigInt(width * 8)
  let unsigned = value % modulus
  if (unsigned < 0n) unsigned += modulus
  const truncated = value < 0n || value >= modulus
  const bytes = new Uint8Array(width)
  for (let i = 0; i < width; i += 1) {
    const shift = BigInt(8 * (endian === 'le' ? i : width - 1 - i))
    bytes[i] = Number((unsigned >> shift) & 0xffn)
  }
  return { bytes, hex: bytesToHex(bytes), unsigned, truncated, width, endian }
}

/**
 * 解析 `pack` / `int` 的主输入：
 * - `0x...` → 十六进制整数
 * - 纯数字 → 十进制整数
 * - 含 `\xNN` 的串 → 字节串，按大端拼成整数
 * - 空格/逗号分隔的十六进制字节 → 字节串，按大端拼成整数
 * - 其余 → UTF-8 文本，其字节按大端拼成整数（于是 'AAAA' 就是 0x41414141）
 * @param {unknown} input
 * @returns {{ value: bigint, kind: string, bytes?: Uint8Array, note: string }}
 */
export function parseIntegerInput(input) {
  if (typeof input === 'bigint') {
    return { value: input, kind: 'integer', note: '按整数解读' }
  }
  if (typeof input === 'number' && Number.isFinite(input)) {
    const value = BigInt(Math.trunc(input))
    return { value, kind: 'decimal', note: '按数字解读' }
  }
  if (typeof input !== 'string') {
    throw new Error('data 必须是字符串（或数字）：pack/int 需要 0x 十六进制、十进制，或字节串（如 "AAAA"）')
  }
  const raw = input.trim()
  if (raw.length === 0) {
    throw new Error('data 为空：pack/int 需要 0x 十六进制、十进制，或字节串（如 "AAAA"）')
  }
  // 1) 显式的 \xNN / 0xNN 字节转义串，例如 \x41\x42 或 0x41 0x42
  if (/\\x/i.test(raw)) {
    const bytes = hexToBytes(raw)
    if (bytes.length === 0) throw new Error('data 解析后没有字节')
    return { value: bytesToBigInt(bytes, 'be'), kind: 'bytes', bytes, note: `按 ${bytes.length} 字节大端拼成整数` }
  }
  const sign = raw.startsWith('-') ? -1n : 1n
  const body = raw.replace(/^[+-]/, '').replace(/_/g, '')
  if (body.length === 0) throw new Error('data 只有正负号，没有数值')
  if (/^0x[0-9a-f]+$/i.test(body)) {
    return { value: sign * BigInt(`0x${body.slice(2)}`), kind: 'hex', note: '按十六进制整数解读' }
  }
  if (/^\d+$/.test(body)) {
    return { value: sign * BigInt(body), kind: 'decimal', note: '按十进制整数解读' }
  }
  // 2) 分隔的十六进制字节串，例如 "41 42 43" / "de,ad,be,ef"
  if (/^(?:[0-9a-f]{2})(?:[\s,_-]+[0-9a-f]{2})+$/i.test(body)) {
    const bytes = hexToBytes(body)
    return { value: sign * bytesToBigInt(bytes, 'be'), kind: 'bytes', bytes, note: `按 ${bytes.length} 字节大端拼成整数` }
  }
  // 3) 兜底：当作 UTF-8 文本，字节按大端拼成整数
  const bytes = encodeUtf8(raw)
  if (bytes.length === 0) throw new Error('data 解析后没有字节')
  return { value: bytesToBigInt(bytes, 'be'), kind: 'text', bytes, note: `按 UTF-8 文本 ${JSON.stringify(raw)} 的 ${bytes.length} 字节大端拼成整数` }
}

/** 完整的 `\xNN` 转义（可打印字节也转义，适合直接复制进 C/Python 源码）。 */
export function escapeAllBytes(bytes) {
  let out = ''
  for (const byte of bytes) out += `\\x${byte.toString(16).padStart(2, '0')}`
  return out
}

/** Python bytes 字面量内容（字符串内的转义，不含外层 b''）。 */
export function escapePythonBytes(bytes) {
  let out = ''
  for (const byte of bytes) {
    if (byte === 0x5c) out += '\\\\'
    else if (byte === 0x27) out += "\\'"
    else if (byte === 0x0a) out += '\\n'
    else if (byte === 0x0d) out += '\\r'
    else if (byte === 0x09) out += '\\t'
    else if (isPrintableAscii(byte)) out += String.fromCharCode(byte)
    else out += `\\x${byte.toString(16).padStart(2, '0')}`
  }
  return out
}

/**
 * 按 format 决定宽度/端序，把整数打包成字节。
 * @param {bigint} value
 * @param {string} format
 */
export function packIntegerValue(value, format = 'le64') {
  if (typeof value !== 'bigint') throw new Error('packIntegerValue 需要 bigint')
  const spec = PACK_SPECS[format]
  if (spec === undefined) throw new Error(`不支持的 format：${format}（可选 ${PACK_FORMATS.join(', ')}）`)
  const width = spec.width === null ? minimalByteWidth(value) : spec.width
  return packBigIntToBytes(value, width, spec.endian)
}

/** pwntools 打包表达式。 */
function pwntoolsPackExpression(packed, format, hex) {
  const valueHex = bigintHex(packed.unsigned)
  switch (format) {
    case 'le16': return `p16(${valueHex})`
    case 'le32': return `p32(${valueHex})`
    case 'le64': return `p64(${valueHex})`
    case 'be16': return `struct.pack('>H', ${valueHex})`
    case 'be32': return `struct.pack('>I', ${valueHex})`
    case 'be64': return `struct.pack('>Q', ${valueHex})`
    default: return `bytes.fromhex('${hex}')`
  }
}

/**
 * `pack` 的纯函数核心：解析输入、打包，并给出所有可复制形态。
 * @param {unknown} input
 * @param {string} format
 */
export function renderPacked(input, format = 'le64') {
  const parsed = parseIntegerInput(input)
  const packed = packIntegerValue(parsed.value, format)
  const hex = bytesToHex(packed.bytes)
  const readable = escapeNonPrintable(packed.bytes)
  const spec = PACK_SPECS[format]
  let reversed = null
  if (spec.width !== null) {
    const reversedBytes = Uint8Array.from([...packed.bytes].reverse())
    reversed = {
      bytes: reversedBytes,
      hex: bytesToHex(reversedBytes),
      hexGrouped: bytesToHex(reversedBytes, { group: reversedBytes.length }),
      escapes: escapeAllBytes(reversedBytes),
      readable: escapeNonPrintable(reversedBytes),
    }
  }
  return {
    parsed,
    packed,
    format,
    hex,
    hexGrouped: bytesToHex(packed.bytes, { group: packed.bytes.length }),
    escapes: escapeAllBytes(packed.bytes),
    readable,
    reversed,
    valueHex: bigintHex(parsed.value),
    unsignedHex: bigintHex(packed.unsigned),
    pythonLiteral: `b'${escapePythonBytes(packed.bytes)}'`,
    pythonCode: `shellcode = b'${escapePythonBytes(packed.bytes)}'`,
    cLiteral: `"${escapeAllBytes(packed.bytes)}"`,
    cDeclaration: `unsigned char buf[${packed.bytes.length}] = "${escapeAllBytes(packed.bytes)}";`,
    pwntools: pwntoolsPackExpression(packed, format, hex),
  }
}

/**
 * `unpack` 的纯函数核心：把十六进制字节串按 format 的宽度与端序读成整数，
 * 同时给出无符号/有符号两种解读。format 为自由格式时按字节数自动选宽度。
 * @param {string | Uint8Array} input hex 串或字节数组
 * @param {string} format
 */
export function unpackInteger(input, format = 'le64') {
  const spec = PACK_SPECS[format]
  if (spec === undefined) throw new Error(`不支持的 format：${format}（可选 ${PACK_FORMATS.join(', ')}）`)
  let bytes
  if (typeof input === 'string') bytes = hexToBytes(input)
  else if (input instanceof Uint8Array) bytes = input
  else throw new Error('unpack 需要十六进制字节串或 Uint8Array')
  if (bytes.length === 0) {
    throw new Error('data 为空：unpack 需要十六进制字节串，例如 41424344')
  }
  let width = spec.width
  let autoWidth = false
  if (width === null) {
    autoWidth = true
    width = [1, 2, 4, 8].includes(bytes.length) ? bytes.length : Math.min(bytes.length, 8)
  }
  if (bytes.length < width) {
    throw new Error(`data 只有 ${bytes.length} 字节，format=${format} 需要 ${width} 字节`)
  }
  const used = bytes.subarray(0, width)
  const unsigned = bytesToBigInt(used, spec.endian)
  const totalBits = BigInt(width * 8)
  const signed = unsigned >= (1n << (totalBits - 1n)) ? unsigned - (1n << totalBits) : unsigned
  const order = spec.endian === 'le' ? 'little' : 'big'
  const hex = bytesToHex(used)
  const unsignedPwntools = spec.endian === 'le' && [2, 4, 8].includes(width)
    ? `u${width * 8}(bytes.fromhex('${hex}'))`
    : `int.from_bytes(bytes.fromhex('${hex}'), '${order}')`
  return {
    bytes: used,
    hex,
    width,
    endian: spec.endian,
    autoWidth,
    format,
    unsigned,
    signed,
    extraBytes: bytes.length - width,
    pwntools: unsignedPwntools,
    pwntoolsSigned: `int.from_bytes(bytes.fromhex('${hex}'), '${order}', signed=True)`,
  }
}

// ---------------------------------------------------------------------------
// hexdump
// ---------------------------------------------------------------------------

/**
 * 生成经典 16 列 hexdump：`0000  xx xx ..  ascii`。
 * offset/length 是相对原始字节数组的窗口，行首显示绝对偏移。
 * @param {Uint8Array} bytes
 * @param {{offset?: number, length?: number}} [options]
 */
export function formatHexdump(bytes, options = {}) {
  if (!(bytes instanceof Uint8Array)) throw new Error('formatHexdump 需要 Uint8Array')
  const rawOffset = Number.isInteger(options.offset) ? options.offset : 0
  const offset = Math.min(Math.max(0, rawOffset), bytes.length)
  const rawLength = Number.isInteger(options.length) ? options.length : bytes.length - offset
  const length = Math.max(0, rawLength)
  const window = bytes.subarray(offset, Math.min(bytes.length, offset + length))
  const lines = []
  for (let i = 0; i < window.length; i += 16) {
    const chunk = window.subarray(i, i + 16)
    const hexParts = []
    const asciiParts = []
    for (let j = 0; j < 16; j += 1) {
      const byte = chunk[j]
      if (byte === undefined) {
        hexParts.push('  ')
        asciiParts.push(' ')
      } else {
        hexParts.push(byte.toString(16).padStart(2, '0'))
        asciiParts.push(isPrintableAscii(byte) ? String.fromCharCode(byte) : '.')
      }
    }
    const hexText = `${hexParts.slice(0, 8).join(' ')}  ${hexParts.slice(8).join(' ')}`
    lines.push(`${(offset + i).toString(16).padStart(4, '0')}  ${hexText}  |${asciiParts.join('')}|`)
  }
  return {
    lines,
    window,
    offset,
    length,
    total: bytes.length,
    beforeWindow: offset,
    afterWindow: bytes.length - (offset + window.length),
  }
}

// ---------------------------------------------------------------------------
// cyclic（de Bruijn）
// ---------------------------------------------------------------------------

/**
 * 惰性 de Bruijn 序列生成器：与 pwntools `cyclic` 的字母表/周期约定一致，
 * 逐个字符 yield，因此查找偏移时不必先构造 14MB 的全序列。
 * @param {string} [alphabet]
 * @param {number} [period]
 */
export function* deBruijnSequence(alphabet = CYCLIC_ALPHABET, period = CYCLIC_PERIOD) {
  if (typeof alphabet !== 'string' || alphabet.length < 2) {
    throw new Error('de Bruijn 字母表至少需要 2 个字符')
  }
  if (!Number.isInteger(period) || period < 1 || period > 8) {
    throw new Error('de Bruijn 周期必须是 1..8 的整数')
  }
  const k = alphabet.length
  const a = new Array(k * period).fill(0)
  function* db(t, p) {
    if (t > period) {
      if (period % p === 0) {
        for (let j = 1; j <= p; j += 1) yield alphabet[a[j]]
      }
    } else {
      a[t] = a[t - p]
      yield* db(t + 1, p)
      for (let j = a[t - p] + 1; j < k; j += 1) {
        a[t] = j
        yield* db(t + 1, t)
      }
    }
  }
  yield* db(1, 1)
}

/**
 * 生成前 `length` 个 cyclic 字符。
 * @param {number} length
 * @param {{alphabet?: string, period?: number}} [options]
 */
export function cyclicPattern(length, options = {}) {
  const total = Number.isInteger(length) ? length : Number.parseInt(String(length ?? ''), 10)
  if (!Number.isFinite(total) || total < 0) throw new Error('cyclic 长度必须是非负整数')
  if (total > CYCLIC_CAPACITY) {
    throw new Error(`cyclic 长度最多 ${CYCLIC_CAPACITY} 字节（62^4：4 字节周期 alnum 的 de Bruijn 上限）`)
  }
  const alphabet = typeof options.alphabet === 'string' && options.alphabet.length >= 2
    ? options.alphabet
    : CYCLIC_ALPHABET
  const period = Number.isInteger(options.period) ? options.period : CYCLIC_PERIOD
  if (total === 0) return ''
  const out = []
  let count = 0
  for (const char of deBruijnSequence(alphabet, period)) {
    out.push(char)
    count += 1
    if (count >= total) break
  }
  return out.join('')
}

/** 把查找模式规范化成「按字节比较」的字符串（支持 \xNN 转义写法）。 */
function normalizeCyclicNeedle(pattern) {
  const raw = typeof pattern === 'string' ? pattern : ''
  if (raw.length === 0) return ''
  if (/\\x/i.test(raw)) {
    const bytes = hexToBytes(raw)
    let out = ''
    for (const byte of bytes) out += String.fromCharCode(byte)
    return out
  }
  return raw
}

/**
 * 在 cyclic 序列里查找模式第一次出现的偏移；找不到返回 -1。
 * 顺序消费生成器，最多消费 `limit` 个字符（默认整个 62^4 空间）。
 * @param {string} pattern
 * @param {{limit?: number, alphabet?: string, period?: number}} [options]
 */
export function cyclicFind(pattern, options = {}) {
  const needle = normalizeCyclicNeedle(pattern)
  if (needle.length === 0) return -1
  const limit = clampInt(options.limit, 1, CYCLIC_CAPACITY, CYCLIC_CAPACITY)
  const alphabet = typeof options.alphabet === 'string' && options.alphabet.length >= 2
    ? options.alphabet
    : CYCLIC_ALPHABET
  const period = Number.isInteger(options.period) ? options.period : CYCLIC_PERIOD
  const overlap = Math.max(0, needle.length - 1)
  const chunk = []
  let tail = ''
  let generated = 0
  const search = (haystack) => haystack.indexOf(needle)
  for (const char of deBruijnSequence(alphabet, period)) {
    chunk.push(char)
    generated += 1
    if (chunk.length >= 65536 || generated >= limit) {
      const haystack = tail + chunk.join('')
      const index = search(haystack)
      if (index >= 0) return generated - haystack.length + index
      tail = overlap > 0 ? haystack.slice(-overlap) : ''
      chunk.length = 0
      if (generated >= limit) break
    }
  }
  if (chunk.length > 0) {
    const haystack = tail + chunk.join('')
    const index = search(haystack)
    if (index >= 0) return generated - haystack.length + index
  }
  return -1
}

// ---------------------------------------------------------------------------
// shellcode
// ---------------------------------------------------------------------------

/**
 * 把 `\xNN` 转义串或十六进制串规范化成字节。
 * @param {string} input
 * @returns {Uint8Array}
 */
export function parseShellcodeInput(input) {
  const raw = typeof input === 'string' ? input.trim() : ''
  if (raw.length === 0) {
    throw new Error('data 为空：shellcode 需要 \\xNN 转义串或十六进制串，例如 "\\x48\\x31\\xc0" 或 "4831c0"')
  }
  try {
    const bytes = hexToBytes(raw)
    if (bytes.length === 0) throw new Error('解析后没有字节')
    return bytes
  } catch (error) {
    throw new Error(`无法把 data 解析成字节：${error.message}；示例："\\x48\\x31\\xc0" 或 "4831c0"`)
  }
}

/**
 * 扫描 shellcode 里各字节出现次数，并显式标出常见坏字符。
 * @param {Uint8Array} bytes
 */
export function scanShellcode(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error('scanShellcode 需要 Uint8Array')
  const frequency = new Map()
  for (const byte of bytes) frequency.set(byte, (frequency.get(byte) ?? 0) + 1)
  const present = [...frequency.keys()].sort((a, b) => a - b)
  const classicBadChars = CLASSIC_BAD_CHARS
    .filter((byte) => frequency.has(byte))
    .map((byte) => ({ byte, count: frequency.get(byte), note: BAD_CHAR_NOTES[byte] }))
  const whitespaceBadChars = WHITESPACE_BAD_CHARS
    .filter((byte) => frequency.has(byte))
    .map((byte) => ({ byte, count: frequency.get(byte), note: BAD_CHAR_NOTES[byte] }))
  return { frequency, present, classicBadChars, whitespaceBadChars }
}

// ---------------------------------------------------------------------------
// 报告
// ---------------------------------------------------------------------------

/** 统一错误报告：保证 execute 永远返回文本。 */
function pwnErrorReport(message) {
  return [
    '# ctf_pwn · 出错',
    '',
    '## 原因',
    '',
    message,
    '',
    '## 下一步',
    '',
    '- `hexdump`：`data` 配 `as="hex"`（默认）或 `as="text"`；`offset`/`length` 控制窗口。',
    '- `pack` / `int`：`data` 用 `0x...`、十进制数字，或 `"AAAA"` 这样的字节串。',
    '- `unpack`：`data` 是十六进制字节串，`format` 决定宽度与端序（默认 `le64`）。',
    '- `cyclic`：`data` 给长度（如 `"64"`），`pattern` 给要查的子串（可用 `\\xNN` 转义）。',
    '- `shellcode`：`data` 用 `\\xNN` 转义串或十六进制串。',
  ].join('\n')
}

/** `hexdump` 报告。 */
function renderHexdumpReport(input) {
  const kind = normalizeInputKind(input.as)
  const data = typeof input.data === 'string' ? input.data : ''
  if (data.length === 0) {
    throw new Error("data 为空：hexdump 需要 hex 串（as='hex'）或文本（as='text'）")
  }
  let bytes
  if (kind === 'text') {
    bytes = encodeUtf8(data)
  } else {
    try {
      bytes = hexToBytes(data)
    } catch (error) {
      throw new Error(`data 不是合法十六进制（若想按文本解读请设 as="text"）：${error.message}`)
    }
  }
  if (bytes.length === 0) {
    throw new Error('data 解析后没有字节：hexdump 需要非空的十六进制串或文本')
  }
  const offset = clampInt(input.offset, 0, bytes.length, 0)
  const length = clampInt(input.length, 0, CYCLIC_DISPLAY_LIMIT, 256)
  const dump = formatHexdump(bytes, { offset, length })
  const lines = []
  lines.push('# ctf_pwn · hexdump')
  lines.push('')
  lines.push('## 摘要')
  lines.push(formatRows([
    ['输入解释', kind === 'text' ? 'UTF-8 文本' : '十六进制串'],
    ['输入字节数', `${bytes.length}`],
    ['窗口起点', `0x${offset.toString(16)}（${offset}）`],
    ['窗口长度', `${length}`],
    ['实际显示', `${dump.window.length} 字节`],
  ], ['项目', '值']))
  if (dump.beforeWindow > 0 || dump.afterWindow > 0) {
    lines.push('')
    lines.push(`- 窗口外：前 ${dump.beforeWindow} 字节、后 ${dump.afterWindow} 字节未显示；调整 offset/length 可继续看。`)
  }
  lines.push('')
  lines.push('## 十六进制转储')
  lines.push('```text')
  if (dump.lines.length === 0) lines.push('（空窗口：offset 超出数据范围或 length=0）')
  else lines.push(...dump.lines)
  lines.push('```')
  lines.push('')
  lines.push('## 说明')
  lines.push('- 行首是绝对偏移（十六进制），中间 16 列十六进制字节，最后是 ASCII 列（不可打印字节显示为 `.`）。')
  lines.push('- 复制字节时建议用 `\\xNN` 转义形式，避免不可见字符在终端/编辑器中丢失。')
  return lines.join('\n')
}

/** `pack` 报告。 */
function renderPackReport(input) {
  const format = normalizeFormat(input.format, 'le64')
  const data = typeof input.data === 'number' ? String(input.data) : input.data
  if (typeof data !== 'string' || data.trim().length === 0) {
    throw new Error("data 为空：pack 需要整数（0x.. / 十进制）或字节串（如 'AAAA'）")
  }
  const rendered = renderPacked(data, format)
  const { parsed, packed } = rendered
  const lines = []
  lines.push('# ctf_pwn · pack')
  lines.push('')
  lines.push('## 摘要')
  lines.push(formatRows([
    ['输入解释', parsed.note],
    ['输入值', rendered.valueHex],
    ['format', format],
    ['字节宽度', `${packed.width} 字节`],
    ['端序', packed.endian === 'le' ? 'little-endian（低字节在前）' : 'big-endian（高字节在前）'],
    ['截断', packed.truncated ? '是：超出宽度，按补码/取模截断' : '否'],
  ], ['项目', '值']))
  lines.push('')
  lines.push('## 字节（hex，空格分隔）')
  lines.push('```text')
  lines.push(rendered.hexGrouped)
  lines.push('```')
  lines.push('')
  lines.push('## 字节（\\xNN 转义，可直接复制）')
  lines.push('```text')
  lines.push(rendered.escapes)
  lines.push('```')
  lines.push('')
  lines.push('## 各种写法')
  lines.push(formatRows([
    ['连续 hex', rendered.hex],
    ['可读转义', rendered.readable],
    ['Python bytes', rendered.pythonLiteral],
    ['C 数组', `${rendered.cDeclaration}`],
    ['pwntools', rendered.pwntools],
  ], ['形式', '值']))
  if (rendered.reversed !== null) {
    lines.push('')
    lines.push('## 反向端序对照')
    lines.push(`- 所选端序是 ${packed.endian === 'le' ? '小端' : '大端'}；把字节倒过来就是${packed.endian === 'le' ? '大端' : '小端'}写法，用于核对是否抄错。`)
    lines.push(formatRows([
      ['反向 hex', rendered.reversed.hex],
      ['反向可读', rendered.reversed.readable],
    ], ['形式', '值']))
  }
  lines.push('')
  lines.push('## 用法示例')
  lines.push('```python')
  lines.push('from pwn import *')
  lines.push(`payload = b'A' * offset + ${rendered.pwntools}`)
  lines.push('```')
  lines.push('')
  lines.push('## 提示')
  lines.push('- `p32`/`p64` 是小端；大端场景用 `struct.pack(\'>I\', ...)` 或 `p64(...)[::-1]`。')
  if (packed.truncated) lines.push('- 输入值超出所选宽度已被截断：确认目标架构是 32 位还是 64 位，再选 `p32`/`p64`。')
  return lines.join('\n')
}

/** `unpack` 报告。 */
function renderUnpackReport(input) {
  const format = normalizeFormat(input.format, 'le64')
  const data = typeof input.data === 'string' ? input.data.trim() : ''
  if (data.length === 0) {
    throw new Error('data 为空：unpack 需要十六进制字节串，例如 41424344')
  }
  const unpacked = unpackInteger(data, format)
  const lines = []
  lines.push('# ctf_pwn · unpack')
  lines.push('')
  lines.push('## 摘要')
  lines.push(formatRows([
    ['输入 hex', unpacked.hex],
    ['format', format],
    ['实际宽度', `${unpacked.width} 字节${unpacked.autoWidth ? '（自由格式，按输入长度自动选择）' : ''}`],
    ['端序', unpacked.endian === 'le' ? 'little-endian' : 'big-endian'],
    ['剩余字节', `${unpacked.extraBytes}`],
  ], ['项目', '值']))
  if (unpacked.extraBytes > 0) {
    lines.push('')
    lines.push(`- 只读取了前 ${unpacked.width} 字节；后 ${unpacked.extraBytes} 字节被忽略（如需全部读取请选更大的 format/自由格式）。`)
  }
  lines.push('')
  lines.push('## 数值解读')
  lines.push(formatRows([
    ['无符号 hex', bigintHex(unpacked.unsigned)],
    ['无符号 dec', unpacked.unsigned.toString(10)],
    ['有符号 dec', unpacked.signed.toString(10)],
    ['二进制', unpacked.unsigned.toString(2)],
  ], ['项目', '值']))
  lines.push('')
  lines.push('## pwntools 写法')
  lines.push('```python')
  lines.push(unpacked.pwntools)
  lines.push(unpacked.pwntoolsSigned)
  lines.push('```')
  lines.push('')
  lines.push('## 用法示例')
  lines.push('```bash')
  lines.push(`# 假设泄漏出来的字节是 ${unpacked.hex}`)
  lines.push(`python3 -c "${unpacked.pwntools}"`)
  lines.push('```')
  return lines.join('\n')
}

/** `int` 报告。 */
function renderIntReport(input) {
  const parsed = parseIntegerInput(input.data)
  const value = parsed.value
  const minimalWidth = minimalByteWidth(value)
  const widths = [...new Set([minimalWidth, 2, 4, 8])].sort((a, b) => a - b)
  const lines = []
  lines.push('# ctf_pwn · 整数换算')
  lines.push('')
  lines.push('## 数值')
  const binary = value < 0n ? `-${(-value).toString(2)}` : value.toString(2)
  const binaryText = binary.length > 128 ? `${binary.slice(0, 128)}…（共 ${binary.length} 字符）` : binary
  lines.push(formatRows([
    ['输入解释', parsed.note],
    ['hex', bigintHex(value)],
    ['dec', value.toString(10)],
    ['oct', value < 0n ? `-0o${(-value).toString(8)}` : `0o${value.toString(8)}`],
    ['bin', binaryText],
  ], ['项目', '值']))
  lines.push('')
  lines.push('## 端序字节序列')
  const rows = []
  for (const width of widths) {
    const caveat = width < minimalWidth ? '（截断）' : ''
    const le = packBigIntToBytes(value, width, 'le')
    const be = packBigIntToBytes(value, width, 'be')
    rows.push([`${width} 字节${caveat}`, 'LE', bytesToHex(le.bytes), escapeNonPrintable(le.bytes)])
    rows.push([`${width} 字节${caveat}`, 'BE', bytesToHex(be.bytes), escapeNonPrintable(be.bytes)])
  }
  lines.push(formatRows(rows, ['宽度', '端序', 'hex', '可读转义']))
  lines.push('')
  lines.push('## 提示')
  lines.push('- 32 位程序常用 `p32`（LE），64 位程序常用 `p64`（LE）；栈上写入地址时端序反了会导致跳转失败。')
  if (minimalWidth > 8) lines.push(`- 输入值需要 ${minimalWidth} 字节才能完整表示，超过 64 位；按 2/4/8 字节展示时会被截断。`)
  lines.push('- 负数的字节序列是补码：例如 `-1` 在 4 字节下是 `ff ff ff ff`。')
  return lines.join('\n')
}

/** `cyclic` 报告。 */
function renderCyclicReport(input) {
  const dataText = typeof input.data === 'string' ? input.data.trim() : ''
  const patternText = typeof input.pattern === 'string' ? input.pattern : ''
  let length = clampInt(input.length, 1, CYCLIC_DISPLAY_LIMIT, 256)
  let needle = patternText
  if (dataText.length > 0) {
    if (/^\d+$/.test(dataText)) length = clampInt(dataText, 1, CYCLIC_DISPLAY_LIMIT, 256)
    else if (needle.length === 0) needle = dataText
  }
  const pattern = cyclicPattern(length)
  const shown = pattern.length <= 4096 ? pattern : `${pattern.slice(0, 4096)}…`
  const lines = []
  lines.push('# ctf_pwn · cyclic')
  lines.push('')
  lines.push('## 摘要')
  lines.push(formatRows([
    ['生成长度', `${pattern.length} 字节`],
    ['周期', `${CYCLIC_PERIOD} 字节（62^4 = ${CYCLIC_CAPACITY} 个唯一窗口）`],
    ['字母表', CYCLIC_ALPHABET],
    ['pwntools 等价', `cyclic(${pattern.length})`],
  ], ['项目', '值']))
  lines.push('')
  lines.push('## 模式')
  lines.push('```text')
  lines.push(shown || '（长度 0）')
  if (pattern.length > shown.length) lines.push(`…（完整长度 ${pattern.length} 字节，此处只显示前 ${shown.length}）`)
  lines.push('```')
  lines.push('')
  lines.push('## 偏移查找')
  if (needle.length === 0) {
    lines.push('- 未提供 `pattern`，跳过查找；把崩溃时看到的 4 字节（如 `baaa`）填进 `pattern` 即可反查偏移。')
  } else {
    const offset = cyclicFind(needle, { limit: CYCLIC_CAPACITY })
    if (offset >= 0) {
      lines.push(`- ✅ 命中：\`${needle}\` 在 cyclic 序列中的偏移是 **${offset}**（0 起）。`)
      lines.push(`- 若这个值来自崩溃时的栈/RIP，写入位置大致就是 offset ${offset}。`)
    } else {
      lines.push(`- ❌ 没有命中：\`${needle}\` 没有出现在前 ${CYCLIC_CAPACITY} 字节的 cyclic 序列里。`)
      lines.push('- 检查是否抄错字节、是否混入了不可打印字符（可用 `\\xNN` 写法传入），或目标程序用的是别的字母表。')
    }
  }
  lines.push('')
  lines.push('## 用法示例')
  lines.push('```python')
  lines.push('from pwn import *')
  lines.push('payload = cyclic(offset) + p64(target)')
  lines.push('```')
  lines.push('- 偏移查找也可以直接跑 `cyclic_find(0x61616162)`，本工具的 `pattern` 支持 ASCII 或 `\\xNN` 转义。')
  lines.push('- 找不到时先确认周期是 4 字节；有些题目用 `cyclic(n=8)`，需要换字母表/周期重算。')
  return lines.join('\n')
}

/** `shellcode` 报告。 */
function renderShellcodeReport(input) {
  const data = typeof input.data === 'string' ? input.data : ''
  if (data.trim().length === 0) {
    throw new Error('data 为空：shellcode 需要 \\xNN 转义串或十六进制串')
  }
  const bytes = parseShellcodeInput(data)
  const scan = scanShellcode(bytes)
  const lines = []
  lines.push('# ctf_pwn · shellcode')
  lines.push('')
  lines.push('## 摘要')
  lines.push(formatRows([
    ['字节数', `${bytes.length}`],
    ['hex', bytesToHex(bytes)],
    ['可读转义', escapeNonPrintable(bytes)],
  ], ['项目', '值']))
  lines.push('')
  lines.push('## C 数组')
  lines.push('```c')
  lines.push(`unsigned char shellcode[] = "${escapeAllBytes(bytes)}";`)
  lines.push(`// 长度：${bytes.length} 字节`)
  lines.push('```')
  lines.push('')
  lines.push('## Python bytes')
  lines.push('```python')
  lines.push(`shellcode = b'${escapePythonBytes(bytes)}'`)
  lines.push('```')
  lines.push('')
  lines.push('## 完整 \\xNN 转义')
  lines.push('```text')
  lines.push(escapeAllBytes(bytes))
  lines.push('```')
  lines.push('')
  lines.push('## 坏字符检查')
  if (scan.classicBadChars.length === 0) {
    lines.push('- ✅ 未发现经典坏字符 `0x00` / `0x0a` / `0x0d`（0x00 / LF / CR）。')
  } else {
    for (const item of scan.classicBadChars) {
      lines.push(`- ⚠️ 命中经典坏字符：\`0x${item.byte.toString(16).padStart(2, '0')}\`（出现 ${item.count} 次）—— ${item.note}`)
    }
  }
  if (scan.whitespaceBadChars.length > 0) {
    lines.push('')
    lines.push('### 其他空白/分隔字节（是否算坏字符取决于目标函数）')
    for (const item of scan.whitespaceBadChars) {
      lines.push(`- \`0x${item.byte.toString(16).padStart(2, '0')}\`（出现 ${item.count} 次）—— ${item.note}`)
    }
  }
  lines.push('')
  lines.push('## 字节出现统计')
  lines.push(formatRows(
    scan.present.map((byte) => [
      `0x${byte.toString(16).padStart(2, '0')}`,
      String(scan.frequency.get(byte)),
      isPrintableAscii(byte) ? String.fromCharCode(byte) : '.',
    ]),
    ['字节', '次数', 'ASCII'],
  ))
  lines.push('')
  lines.push('## 提示')
  lines.push('- 坏字符扫描只回答「这些字节出现了」；是否会被目标函数截断取决于它怎么读输入（`strcpy`、`gets`、`scanf` 各不相同）。')
  lines.push('- 编码器（如 XOR/加壳）去掉坏字符后，记得在 exploit 里先解码再跳转。')
  lines.push('- `0x00` 在 C 字符串里必然截断；很多 shellcode 已刻意避免它。')
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// 工具定义
// ---------------------------------------------------------------------------

const PWN_DESCRIPTION =
  'Pwn helpers: hexdump, integer and endianness conversion, p32/p64 packing to escaped shellcode, de Bruijn cyclic pattern generation and offset lookup, and bad-character scanning. Pure local computation; it does not run or attach to a process.'

/**
 * 构造 `ctf_pwn` 工具定义。
 * @param {any} ctx registrant context
 */
export function createPwnTool(ctx) {
  void ctx
  return {
    name: 'ctf_pwn',
    description: PWN_DESCRIPTION,
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: {
          type: 'string',
          enum: PWN_ACTIONS,
          description: 'hexdump (default) | pack | unpack | int | cyclic | shellcode.',
        },
        data: {
          type: 'string',
          description: 'Main input: hex string / text / integer / cyclic pattern / escaped shellcode, depending on action.',
        },
        as: {
          type: 'string',
          enum: ['hex', 'text'],
          description: 'How to interpret data for hexdump. hex (default) or text (UTF-8 bytes).',
        },
        format: {
          type: 'string',
          enum: PACK_FORMATS,
          description: 'Packing format: le16/le32/le64/be16/be32/be64 (default le64), or hex / c-escape / python for free-form byte strings.',
        },
        offset: {
          type: 'integer',
          description: 'Hexdump window start offset in bytes (default 0).',
        },
        length: {
          type: 'integer',
          description: 'Hexdump window length / cyclic generation length in bytes (default 256 for hexdump, 256 for cyclic).',
        },
        pattern: {
          type: 'string',
          description: 'Cyclic substring to locate (ASCII or \\xNN escaped). Required for offset lookup.',
        },
      },
    },
    output: textOutput('Pwn helpers'),
    async execute(args) {
      try {
        const input = args !== null && typeof args === 'object' ? args : {}
        const action = normalizeAction(input.action)
        if (action === null) {
          return { text: pwnErrorReport(`不支持的 action：${JSON.stringify(input.action)}；可选 ${PWN_ACTIONS.join(' / ')}。`) }
        }
        if (action === 'hexdump') return { text: renderHexdumpReport(input) }
        if (action === 'pack') return { text: renderPackReport(input) }
        if (action === 'unpack') return { text: renderUnpackReport(input) }
        if (action === 'int') return { text: renderIntReport(input) }
        if (action === 'cyclic') return { text: renderCyclicReport(input) }
        return { text: renderShellcodeReport(input) }
      } catch (error) {
        return { text: pwnErrorReport(`执行失败：${error?.message ?? String(error)}`) }
      }
    },
  }
}
