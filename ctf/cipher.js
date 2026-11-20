/**
 * `ctf_cipher` — 古典密码的施加与爆破。
 *
 * 覆盖 Caesar/ROT-N、ROT13、ROT47、Atbash、栅栏（rail fence）、Vigenère、
 * 列置换（columnar transposition）、Bacon、Morse 与键盘错位（keyboard shift）。
 * 爆破模式枚举出该密码的候选解，用共享的 `printableScore` 排序，并显式标出
 * 疑似 flag；Vigenère / 列置换依赖密钥、无法全量穷举，因此只试内置常见密钥字典，
 * 报告里会写明这一限制，避免把「没试到」当成「不存在」。
 *
 * 设计约束与 codec.js 一致：只用 Node 内置模块、`execute` 不抛原始异常、
 * 纯函数单独导出便于测试与 index.js 复用。
 */
import { clampInt, formatRows, preview, printableScore, textOutput } from './util.js'
import { autoDecode, decodeBacon, decodeMorse } from './codec.js'

/** `ctf_cipher` 的 cipher 枚举。 */
export const CIPHERS = Object.freeze([
  'caesar',
  'rot13',
  'rot47',
  'atbash',
  'railfence',
  'vigenere',
  'columnar',
  'bacon',
  'morse',
  'keyboard-shift',
])

/** Vigenère / 列置换爆破时尝试的常见密钥（CTF 出场率高的短词）。 */
const COMMON_KEYS = Object.freeze([
  'flag', 'ctf', 'key', 'secret', 'password', 'admin', 'love', 'crypto', 'vigenere', 'caesar', 'test', 'abc',
])

/** 每种密码附带的说明，既用于报告，也提醒模型「看到候选后该做什么」。 */
const CIPHER_NOTES = Object.freeze({
  caesar: ['Caesar 只移位字母、保留数字与符号；26 个反向移位已全部枚举。'],
  rot13: ['ROT13 是自反的：同一个操作既是加密也是解密。'],
  rot47: ['ROT47 作用于可见 ASCII（33-126），默认枚举 1..maxShift 个移位。'],
  atbash: ['Atbash 是字母表镜像替换，只有唯一一种映射。'],
  railfence: ['栅栏密码默认枚举 2..12 条栅栏；短文本的可读度区分度有限。'],
  vigenere: ['Vigenère 无法在无密钥时穷举，这里只试常见密钥字典；已知 key 时用 apply 模式直接解。'],
  columnar: ['列置换依赖密钥，这里只试常见词典与 3/4 位数字置换；已知 key 时用 apply 模式。'],
  bacon: ['Bacon 只接受 A/B 或 0/1 串，24 与 26 字母表都会尝试。'],
  morse: ['Morse 用空格分隔字母、`/` 或 `|` 分隔单词，长短符号与中文「长/短」都支持。'],
  'keyboard-shift': ['键盘错位同时枚举「全键盘整体左右移 1..N 位」（手位偏移）与「单行左右移」（单行错位）两种常见情况。'],
})

/** 键盘四行：plain 与 shifted 一一对应（同一行内左右移位、大小写形态保持不变）。 */
const KEYBOARD_ROWS = Object.freeze([
  { plain: '1234567890-=', shifted: '!@#$%^&*()_+' },
  { plain: 'qwertyuiop[]\\', shifted: 'QWERTYUIOP{}|' },
  { plain: "asdfghjkl;'", shifted: 'ASDFGHJKL:"' },
  { plain: 'zxcvbnm,./', shifted: 'ZXCVBNM<>?' },
])

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/** 百分比显示。 */
function percent(ratio) {
  return `${Math.round((Number(ratio) || 0) * 100)}%`
}

/** 把结果压成单行表格单元格：转义换行/控制字符与 Markdown 的 `|`。 */
function oneLine(value, limit = 110) {
  const text = String(value ?? '')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\t/g, '\\t')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, (char) => `\\x${char.codePointAt(0).toString(16).padStart(2, '0')}`)
    .replace(/\|/g, '\\|')
  return preview(text, limit)
}

/** 把结果放进 Markdown 代码块。 */
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

/**
 * 读取整数参数，未提供时回退默认值，非法时抛中文错误。
 * @param {unknown} value
 * @param {number} fallback
 * @param {string} label
 */
function readInt(value, fallback, label) {
  if (value === undefined || value === null || value === '') return fallback
  const parsed = Number.parseInt(String(value), 10)
  if (!Number.isFinite(parsed)) throw new Error(`${label} 必须是整数`)
  return parsed
}

/** 候选排序：疑似 flag 优先 → 分数高 → 结果短。 */
function compareCandidates(a, b) {
  if (a.flagLike !== b.flagLike) return a.flagLike ? -1 : 1
  if (b.score !== a.score) return b.score - a.score
  return a.result.length - b.result.length
}

/**
 * 给候选打分：返回排好序的候选数组。
 * @param {Array<{label: string, result: string}>} candidates
 * @returns {Array<{label: string, result: string, score: number, printable: number, flagLike: boolean}>}
 */
export function rankCandidates(candidates) {
  return candidates
    .map((candidate) => {
      const scored = printableScore(candidate.result)
      return {
        label: candidate.label,
        result: candidate.result,
        score: scored.score,
        printable: scored.printable,
        flagLike: scored.flagLike,
      }
    })
    .sort(compareCandidates)
}

// ---------------------------------------------------------------------------
// Caesar / ROT13 / ROT47 / Atbash
// ---------------------------------------------------------------------------

/**
 * Caesar 移位：只移位 ASCII 字母，保留大小写；shift 可为负。
 * @param {unknown} input
 * @param {number} shift 超过 26 会自动取模
 */
export function caesar(input, shift) {
  const amount = readInt(shift, 0, 'caesar 的 shift')
  const normalized = ((amount % 26) + 26) % 26
  if (normalized === 0) return String(input ?? '')
  return String(input ?? '').replace(/[a-z]/gi, (char) => {
    const base = char <= 'Z' ? 0x41 : 0x61
    return String.fromCharCode(((char.charCodeAt(0) - base + normalized) % 26) + base)
  })
}

/**
 * ROT13：字母移位 13 位（自反）。
 * @param {unknown} input
 */
export function rot13(input) {
  return caesar(input, 13)
}

/**
 * ROT47：可见 ASCII（33-126）移位；shift 默认 47，自反。
 * @param {unknown} input
 * @param {number} [shift]
 */
export function rot47(input, shift = 47) {
  const amount = readInt(shift, 47, 'rot47 的 shift')
  const normalized = ((amount % 94) + 94) % 94
  if (normalized === 0) return String(input ?? '')
  return String(input ?? '').replace(/[!-~]/g, (char) => (
    String.fromCharCode(((char.charCodeAt(0) - 0x21 + normalized) % 94) + 0x21)
  ))
}

/**
 * Atbash：字母表镜像（A↔Z，a↔z），数字与符号不变。
 * @param {unknown} input
 */
export function atbash(input) {
  return String(input ?? '').replace(/[a-z]/gi, (char) => {
    const base = char <= 'Z' ? 0x41 : 0x61
    return String.fromCharCode(base + (25 - (char.charCodeAt(0) - base)))
  })
}

// ---------------------------------------------------------------------------
// 栅栏密码
// ---------------------------------------------------------------------------

/**
 * 校验栅栏条数。
 * @param {unknown} value
 * @param {number} fallback
 */
function normalizeRails(value, fallback) {
  const rails = readInt(value, fallback, 'rails')
  if (rails < 2 || rails > 20) throw new Error('rails 必须在 2..20 之间')
  return rails
}

/**
 * 计算栅栏模式下每个字符所在的栏号。
 * @param {number} length
 * @param {number} rails
 * @returns {number[]}
 */
function railPattern(length, rails) {
  const pattern = new Array(length)
  let rail = 0
  let direction = 1
  for (let index = 0; index < length; index += 1) {
    pattern[index] = rail
    rail += direction
    if (rail === 0 || rail === rails - 1) direction = -direction
  }
  return pattern
}

/**
 * 栅栏加密（W 型写法）。
 * @param {unknown} input
 * @param {number} rails
 */
export function railFenceEncode(input, rails) {
  const count = normalizeRails(rails, 2)
  const chars = [...String(input ?? '')]
  if (chars.length === 0) return ''
  if (count === 1) return chars.join('')
  const pattern = railPattern(chars.length, count)
  let out = ''
  for (let rail = 0; rail < count; rail += 1) {
    for (let index = 0; index < chars.length; index += 1) {
      if (pattern[index] === rail) out += chars[index]
    }
  }
  return out
}

/**
 * 栅栏解密：按 W 型模式把密文切回各栏再按列序读回。
 * @param {unknown} input
 * @param {number} rails
 */
export function railFenceDecode(input, rails) {
  const count = normalizeRails(rails, 2)
  const chars = [...String(input ?? '')]
  if (chars.length === 0) return ''
  if (count === 1) return chars.join('')
  const pattern = railPattern(chars.length, count)
  const counts = new Array(count).fill(0)
  for (const rail of pattern) counts[rail] += 1
  const railTexts = []
  let offset = 0
  for (let rail = 0; rail < count; rail += 1) {
    railTexts.push(chars.slice(offset, offset + counts[rail]))
    offset += counts[rail]
  }
  const cursors = new Array(count).fill(0)
  return pattern.map((rail) => railTexts[rail][cursors[rail]++]).join('')
}

// ---------------------------------------------------------------------------
// Vigenère
// ---------------------------------------------------------------------------

/**
 * 把密钥解析成字母移位序列；非法密钥抛中文错误。
 * @param {unknown} key
 * @returns {number[]}
 */
function vigenereShifts(key) {
  const letters = String(key ?? '').trim().toUpperCase()
  if (letters.length === 0) throw new Error('Vigenère 需要 key 参数（仅字母）')
  if (!/^[A-Z]+$/.test(letters)) throw new Error('Vigenère 的 key 只能包含字母 A-Z')
  return [...letters].map((char) => char.charCodeAt(0) - 0x41)
}

/**
 * Vigenère 加密：只移位字母，非字母字符保留原样且不消耗密钥位。
 * @param {unknown} input
 * @param {unknown} key
 */
export function vigenereEncode(input, key) {
  const shifts = vigenereShifts(key)
  let keyIndex = 0
  return String(input ?? '').replace(/[a-z]/gi, (char) => {
    const base = char <= 'Z' ? 0x41 : 0x61
    const shift = shifts[keyIndex % shifts.length]
    keyIndex += 1
    return String.fromCharCode(((char.charCodeAt(0) - base + shift) % 26) + base)
  })
}

/**
 * Vigenère 解密（加密的逆运算）。
 * @param {unknown} input
 * @param {unknown} key
 */
export function vigenereDecode(input, key) {
  const shifts = vigenereShifts(key)
  let keyIndex = 0
  return String(input ?? '').replace(/[a-z]/gi, (char) => {
    const base = char <= 'Z' ? 0x41 : 0x61
    const shift = shifts[keyIndex % shifts.length]
    keyIndex += 1
    return String.fromCharCode(((char.charCodeAt(0) - base - shift + 26) % 26) + base)
  })
}

// ---------------------------------------------------------------------------
// 列置换（columnar transposition）
// ---------------------------------------------------------------------------

/**
 * 规范化列置换密钥：去空白，空密钥抛中文错误。
 * @param {unknown} key
 * @returns {string}
 */
function normalizeColumnarKey(key) {
  const value = String(key ?? '').trim()
  if (value.length === 0) throw new Error('列置换需要 key 参数（列标题字符串，例如 ZEBRA 或 3124）')
  if (/\s/.test(value)) throw new Error('列置换的 key 不能包含空白字符')
  return value
}

/**
 * 由列标题算出读取顺序：按键名字典序稳定排序后返回列下标。
 * @param {string} key
 * @returns {number[]}
 */
function columnOrder(key) {
  return [...key]
    .map((char, index) => ({ char, index }))
    .sort((a, b) => (a.char === b.char ? a.index - b.index : (a.char < b.char ? -1 : 1)))
    .map((item) => item.index)
}

/**
 * 列置换加密：按行填入网格，再按列标题顺序逐列读出（末尾不补齐，空位跳过）。
 * @param {unknown} input
 * @param {unknown} key
 */
export function columnarEncode(input, key) {
  const columnKey = normalizeColumnarKey(key)
  const chars = [...String(input ?? '')]
  const width = columnKey.length
  if (chars.length === 0) return ''
  if (width === 1) return chars.join('')
  const rows = Math.ceil(chars.length / width)
  const grid = Array.from({ length: rows }, () => new Array(width).fill(''))
  for (let index = 0; index < chars.length; index += 1) {
    grid[Math.floor(index / width)][index % width] = chars[index]
  }
  let out = ''
  for (const column of columnOrder(columnKey)) {
    for (let row = 0; row < rows; row += 1) {
      if (grid[row][column] !== '') out += grid[row][column]
    }
  }
  return out
}

/**
 * 列置换解密：先按列标题顺序把密文切回各列，再按行读回。
 * @param {unknown} input
 * @param {unknown} key
 */
export function columnarDecode(input, key) {
  const columnKey = normalizeColumnarKey(key)
  const chars = [...String(input ?? '')]
  const width = columnKey.length
  if (chars.length === 0) return ''
  if (width === 1) return chars.join('')
  const rows = Math.ceil(chars.length / width)
  const columnLengths = new Array(width).fill(0)
  for (let index = 0; index < chars.length; index += 1) columnLengths[index % width] += 1
  const grid = Array.from({ length: rows }, () => new Array(width).fill(''))
  let offset = 0
  for (const column of columnOrder(columnKey)) {
    for (let row = 0; row < columnLengths[column]; row += 1) {
      grid[row][column] = chars[offset]
      offset += 1
    }
  }
  let out = ''
  for (let row = 0; row < rows; row += 1) {
    for (let column = 0; column < width; column += 1) {
      if (grid[row][column] !== '') out += grid[row][column]
    }
  }
  return out
}

// ---------------------------------------------------------------------------
// 键盘错位
// ---------------------------------------------------------------------------

/**
 * 键盘行内左右移位：对命中键盘行的字符替换为同行偏移 `delta` 位后的键，
 * 大小写形态（plain/shifted）保持不变；未命中任何键盘行的字符原样保留。
 * @param {unknown} input
 * @param {number} delta 正数向右、负数向左
 * @param {number | null} [rowIndex] 只处理指定行（0..3），null 表示全部行
 */
export function keyboardShift(input, delta, rowIndex = null) {
  const offset = readInt(delta, 0, 'keyboard-shift 的 shift')
  const source = String(input ?? '')
  if (offset === 0) return source
  let out = ''
  for (const char of source) {
    let mapped = char
    for (let row = 0; row < KEYBOARD_ROWS.length; row += 1) {
      if (rowIndex !== null && row !== rowIndex) continue
      const { plain, shifted } = KEYBOARD_ROWS[row]
      let index = plain.indexOf(char)
      let useShifted = false
      if (index < 0) {
        index = shifted.indexOf(char)
        useShifted = true
      }
      if (index < 0) continue
      const length = plain.length
      const nextIndex = (((index + offset) % length) + length) % length
      mapped = useShifted ? shifted[nextIndex] : plain[nextIndex]
      break
    }
    out += mapped
  }
  return out
}

// ---------------------------------------------------------------------------
// 爆破（枚举候选）
// ---------------------------------------------------------------------------

/**
 * Caesar 爆破：枚举 1..26 个「反向移位」。
 * @param {unknown} input
 * @returns {Array<{label: string, result: string}>}
 */
export function bruteforceCaesar(input) {
  const candidates = []
  for (let shift = 1; shift <= 26; shift += 1) {
    candidates.push({ label: `shift=${shift}`, result: caesar(input, -shift) })
  }
  return candidates
}

/**
 * ROT47 爆破：枚举 1..maxShift 个移位。
 * @param {unknown} input
 * @param {number} [maxShift]
 * @returns {Array<{label: string, result: string}>}
 */
export function bruteforceRot47(input, maxShift = 94) {
  const limit = clampInt(maxShift, 1, 94, 94)
  const candidates = []
  for (let shift = 1; shift <= limit; shift += 1) {
    candidates.push({ label: `shift=${shift}`, result: rot47(input, -shift) })
  }
  return candidates
}

/**
 * 栅栏爆破：枚举 2..maxRails 条栅栏。
 * @param {unknown} input
 * @param {number} [maxRails] 默认 12
 * @returns {Array<{label: string, result: string}>}
 */
export function bruteforceRailFence(input, maxRails = 12) {
  const limit = clampInt(maxRails, 2, 20, 12)
  const candidates = []
  for (let rails = 2; rails <= limit; rails += 1) {
    candidates.push({ label: `rails=${rails}`, result: railFenceDecode(input, rails) })
  }
  return candidates
}

/**
 * 键盘错位爆破：既枚举「全键盘整体左右移」（整只手错位），也枚举「单行左右移」
 * （只有一行打歪），两种都按结果去重。
 * @param {unknown} input
 * @returns {Array<{label: string, result: string}>}
 */
export function bruteforceKeyboardShift(input) {
  const source = String(input ?? '')
  const candidates = []
  const seen = new Set([source])
  const push = (label, result) => {
    if (seen.has(result)) return
    seen.add(result)
    candidates.push({ label, result })
  }
  const maxOffset = Math.max(...KEYBOARD_ROWS.map((row) => row.plain.length)) - 1
  for (let offset = 1; offset <= maxOffset; offset += 1) {
    for (const delta of [offset, -offset]) {
      push(`全键盘 ${delta > 0 ? '右移' : '左移'} ${Math.abs(delta)} 位`, keyboardShift(source, delta))
    }
  }
  for (let row = 0; row < KEYBOARD_ROWS.length; row += 1) {
    const length = KEYBOARD_ROWS[row].plain.length
    for (let offset = 1; offset < length; offset += 1) {
      for (const delta of [offset, -offset]) {
        push(`第${row + 1}行 ${delta > 0 ? '右移' : '左移'} ${Math.abs(offset)} 位`, keyboardShift(source, delta, row))
      }
    }
  }
  if (candidates.length === 0) throw new Error('keyboard-shift 没有找到可移位的字符（输入不含键盘行内字符？）')
  return candidates
}

/**
 * Bacon 爆破：24 与 26 字母表各解一次。
 * @param {unknown} input
 * @returns {Array<{label: string, result: string}>}
 */
export function bruteforceBacon(input) {
  const candidates = []
  for (const variant of [26, 24]) {
    try {
      candidates.push({ label: `bacon ${variant} 字母表`, result: decodeBacon(input, { variant }) })
    } catch {
      // 该字母表解不了就跳过，两个都失败时由 runBruteforce 报空候选。
    }
  }
  return candidates
}

/**
 * Vigenère 爆破：无法全量穷举，只试调用方给的 key 与内置常见密钥字典。
 * @param {unknown} input
 * @param {unknown} [userKey]
 * @returns {Array<{label: string, result: string}>}
 */
export function bruteforceVigenere(input, userKey) {
  const keys = []
  const provided = typeof userKey === 'string' ? userKey.trim() : ''
  if (provided.length > 0) keys.push(provided)
  for (const key of COMMON_KEYS) {
    if (!keys.includes(key)) keys.push(key)
  }
  const candidates = []
  for (const key of keys) {
    try {
      candidates.push({ label: `key=${key}`, result: vigenereDecode(input, key) })
    } catch {
      // 非法 key（含非字母）直接跳过。
    }
  }
  return candidates
}

/**
 * 生成 1..n 的全部排列，用于列置换的数字密钥穷举。
 * @param {number} n
 * @returns {string[]}
 */
function permutations(n) {
  const digits = Array.from({ length: n }, (_, index) => String(index + 1))
  const result = []
  const walk = (prefix, rest) => {
    if (rest.length === 0) {
      result.push(prefix)
      return
    }
    for (let index = 0; index < rest.length; index += 1) {
      walk(prefix + rest[index], rest.slice(0, index).concat(rest.slice(index + 1)))
    }
  }
  walk('', digits)
  return result
}

/**
 * 列置换爆破：调用方 key → 常见词典 → 3/4 位数字全排列。
 * 报告里会说明这只是字典尝试，不是全量穷举。
 * @param {unknown} input
 * @param {unknown} [userKey]
 * @returns {Array<{label: string, result: string}>}
 */
export function bruteforceColumnar(input, userKey) {
  const keys = []
  const provided = typeof userKey === 'string' ? userKey.trim() : ''
  if (provided.length > 0) keys.push(provided)
  for (const key of COMMON_KEYS) {
    if (!keys.includes(key)) keys.push(key)
  }
  for (const key of permutations(3)) {
    if (!keys.includes(key)) keys.push(key)
  }
  for (const key of permutations(4)) {
    if (!keys.includes(key)) keys.push(key)
  }
  const candidates = []
  for (const key of keys) {
    try {
      candidates.push({ label: `key=${key}`, result: columnarDecode(input, key) })
    } catch {
      // 非法 key 跳过。
    }
  }
  return candidates
}

/**
 * 按密码类型跑爆破，返回未打分的候选列表。
 * @param {string} cipher
 * @param {unknown} input
 * @param {{key?: string, rails?: number, maxShift?: number}} [options]
 * @returns {Array<{label: string, result: string}>}
 */
export function runBruteforce(cipher, input, options = {}) {
  switch (cipher) {
    case 'caesar':
      return bruteforceCaesar(input)
    case 'rot13':
      return [{ label: 'rot13', result: rot13(input) }]
    case 'rot47':
      return bruteforceRot47(input, options.maxShift)
    case 'atbash':
      return [{ label: 'atbash', result: atbash(input) }]
    case 'railfence':
      return bruteforceRailFence(input, options.rails ?? 12)
    case 'vigenere':
      return bruteforceVigenere(input, options.key)
    case 'columnar':
      return bruteforceColumnar(input, options.key)
    case 'bacon':
      return bruteforceBacon(input)
    case 'morse':
      return [{ label: 'morse', result: decodeMorse(input) }]
    case 'keyboard-shift':
      return bruteforceKeyboardShift(input)
    default:
      throw new Error(`不支持的密码 ${JSON.stringify(cipher)}`)
  }
}

// ---------------------------------------------------------------------------
// 施加（apply 模式）
// ---------------------------------------------------------------------------

/**
 * 按密码类型解一次。
 * @param {string} cipher
 * @param {unknown} input
 * @param {{key?: string, shift?: number, rails?: number}} [options]
 * @returns {{label: string, result: string, defaults: string[]}}
 */
export function applyCipher(cipher, input, options = {}) {
  const defaults = []
  switch (cipher) {
    case 'caesar': {
      const hasShift = options.shift !== undefined && options.shift !== null && options.shift !== ''
      const shift = readInt(options.shift, 3, 'shift')
      if (!hasShift) defaults.push('未提供 shift，按默认 3 反向移位')
      return { label: `caesar shift=${shift}`, result: caesar(input, -shift), defaults }
    }
    case 'rot13':
      return { label: 'rot13', result: rot13(input), defaults }
    case 'rot47': {
      const hasShift = options.shift !== undefined && options.shift !== null && options.shift !== ''
      const shift = readInt(options.shift, 47, 'shift')
      if (!hasShift) defaults.push('未提供 shift，按默认 47')
      return { label: `rot47 shift=${shift}`, result: rot47(input, -shift), defaults }
    }
    case 'atbash':
      return { label: 'atbash', result: atbash(input), defaults }
    case 'railfence': {
      const hasRails = options.rails !== undefined && options.rails !== null && options.rails !== ''
      const rails = normalizeRails(options.rails, 3)
      if (!hasRails) defaults.push('未提供 rails，按默认 3 条栅栏')
      return { label: `railfence rails=${rails}`, result: railFenceDecode(input, rails), defaults }
    }
    case 'vigenere':
      return { label: `vigenere key=${String(options.key).trim()}`, result: vigenereDecode(input, options.key), defaults }
    case 'columnar':
      return { label: `columnar key=${String(options.key).trim()}`, result: columnarDecode(input, options.key), defaults }
    case 'bacon':
      return { label: 'bacon 26 字母表', result: decodeBacon(input, { variant: 26 }), defaults }
    case 'morse':
      return { label: 'morse', result: decodeMorse(input), defaults }
    case 'keyboard-shift': {
      const hasShift = options.shift !== undefined && options.shift !== null && options.shift !== ''
      const shift = readInt(options.shift, 1, 'shift')
      if (!hasShift) defaults.push('未提供 shift，按默认 1 位回移')
      return { label: `keyboard-shift offset=${shift}`, result: keyboardShift(input, -shift), defaults }
    }
    default:
      throw new Error(`不支持的密码 ${JSON.stringify(cipher)}`)
  }
}

// ---------------------------------------------------------------------------
// 报告渲染
// ---------------------------------------------------------------------------

/**
 * 把失败原因渲染成统一 Markdown 报告。
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
    '- 检查 `text` 是否为空、`cipher` 是否在枚举内。',
    '- `action=apply` 时，Vigenère / 列置换必须提供 `key`；Caesar/ROT47 建议显式给 `shift`，栅栏建议给 `rails`。',
    '- 不确定密码类型时先用 `action=bruteforce` 按 `printableScore` 找最像答案的候选。',
  ].join('\n')
}

/**
 * 渲染爆破报告。
 * @param {string} cipher
 * @param {string} text
 * @param {Array<{label: string, result: string, score: number, printable: number, flagLike: boolean}>} ranked
 * @param {string | undefined} notice 爆破方自身的失败原因
 */
function buildBruteforceReport(cipher, text, ranked, notice) {
  const flagged = ranked.filter((candidate) => candidate.flagLike)
  const lines = ['# ctf_cipher', '', `动作：bruteforce · 密码：${cipher} · 输入：${text.length} 字符`, '']
  lines.push('## 结论')
  if (notice !== undefined) {
    lines.push(`爆破未产出候选：${notice}`)
  } else if (ranked.length === 0) {
    lines.push('没有产出候选：输入格式与所选密码不匹配。')
  } else {
    lines.push(`枚举 ${ranked.length} 个候选，按可打印度排序${flagged.length > 0 ? `，命中 ${flagged.length} 条疑似答案` : '，没有命中 flag 形态'}。`)
    lines.push(`最佳候选（${ranked[0].label}）：${oneLine(ranked[0].result, 120)}`)
  }
  lines.push('')
  lines.push('## 候选')
  if (ranked.length === 0) {
    lines.push('（无候选）')
  } else {
    const rows = ranked.slice(0, 20).map((candidate) => [
      candidate.label,
      oneLine(candidate.result, 110),
      String(candidate.score),
      candidate.flagLike ? '★ 疑似flag' : '',
    ])
    lines.push(formatRows(rows, ['参数', '结果预览', '分数', '标记']))
    if (ranked.length > 20) lines.push(`（共 ${ranked.length} 个候选，此处只显示前 20 个）`)
  }
  lines.push('')
  lines.push('## 下一步建议')
  for (const note of CIPHER_NOTES[cipher] ?? []) lines.push(`- ${note}`)
  if (flagged.length > 0) {
    lines.push('- 先核对「疑似flag」行的内容；命中题目格式即可直接提交，需要完整链路时再用 `action=apply` 指定参数复现。')
  } else if (ranked.length > 0) {
    lines.push('- 没有命中 flag：最佳候选可读度可能仍不高，试试换 cipher（如 caesar 不行就试 railfence/atbash），或把结果交给 `ctf_codec` 的 auto 模式再解一层。')
  } else {
    lines.push('- 确认密文字母/符号与所选密码匹配；Bacon 需要 A/B 或 0/1 串，Morse 需要点划与分隔符。')
  }
  lines.push('- 确认密码后，用 `action=apply` 指定 shift/key/rails 复现单个解，比爆破更快也更好核对。')
  return lines.join('\n')
}

/**
 * 渲染施加报告（含「结果还能不能再解一层」的交叉提示）。
 * @param {string} cipher
 * @param {string} text
 * @param {{label: string, result: string, defaults: string[]}} applied
 */
function buildApplyReport(cipher, text, applied) {
  const scored = printableScore(applied.result)
  const lines = ['# ctf_cipher', '', `动作：apply · 密码：${cipher} · 输入：${text.length} 字符`, '']
  lines.push('## 结论')
  lines.push(`${applied.label} 解密完成：${text.length} 字符 → ${applied.result.length} 字符，可打印度 ${percent(scored.printable)}${scored.flagLike ? '，命中疑似答案' : ''}。`)
  for (const note of applied.defaults) lines.push(`- ${note}`)
  lines.push('')
  lines.push('## 结果')
  lines.push('```')
  lines.push(blockText(applied.result))
  lines.push('```')
  lines.push('')
  lines.push('## 下一步建议')
  if (scored.flagLike) {
    lines.push('- 结果里出现 flag/ctf 形态的片段，先核对格式；命中即可提交。')
  }
  const hints = autoDecode(applied.result, { maxDepth: 1, limit: 6 }).candidates
    .filter((candidate) => candidate.score > scored.score || candidate.flagLike)
    .slice(0, 2)
  for (const hint of hints) {
    lines.push(`- 结果看起来还能再解一层：\`ctf_codec\` 的 \`encoding=${hint.path[hint.path.length - 1]}\` → ${oneLine(hint.result, 100)}（分数 ${hint.score}）`)
  }
  if (scored.printable < 0.7) {
    lines.push('- 结果可打印度偏低：参数（shift/key/rails）可能不对，先回 `action=bruteforce` 看排序后的候选。')
  } else if (hints.length === 0 && !scored.flagLike) {
    lines.push('- 结果已像正常文本但没有 flag：可能题目答案不是该形态，或还需要编码/取证工具继续处理。')
  }
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// 工具定义
// ---------------------------------------------------------------------------

/**
 * 构造 `ctf_cipher` 工具定义。
 * @param {any} ctx registrant context
 */
export function createCipherTool(ctx) {
  void ctx
  return {
    name: 'ctf_cipher',
    description:
      'Apply or brute-force classical ciphers: Caesar/ROT-N, ROT13, ROT47, Atbash, rail fence, Vigenere, columnar transposition, Bacon, Morse and keyboard shift. Brute-force mode ranks every candidate by printable score.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: {
          type: 'string',
          enum: ['bruteforce', 'apply'],
          description: 'bruteforce (default): enumerate candidates and rank them; apply: decrypt once with the given shift/key/rails.',
        },
        cipher: {
          type: 'string',
          enum: [...CIPHERS],
          description: 'Classical cipher to use. Defaults to caesar.',
        },
        text: {
          type: 'string',
          description: 'The cipher text to attack (required).',
        },
        key: {
          type: 'string',
          description: 'Key for Vigenere (letters only) or columnar transposition (column labels such as ZEBRA or 3124).',
        },
        shift: {
          type: 'integer',
          description: 'Shift for caesar/rot47 apply (positive = undo that many positions); keyboard-shift offset. Defaults per cipher.',
        },
        rails: {
          type: 'integer',
          minimum: 2,
          maximum: 20,
          description: 'Rail-fence rail count (2-20). Defaults to 3 for apply and enumerates up to 12 in bruteforce.',
        },
        maxShift: {
          type: 'integer',
          minimum: 1,
          maximum: 94,
          description: 'Upper bound of shifts enumerated by rot47 bruteforce (1-94, default 94).',
        },
      },
      required: ['text'],
    },
    output: textOutput('Classical cipher report'),
    async execute(args) {
      try {
        const payload = args !== null && typeof args === 'object' && !Array.isArray(args) ? args : {}
        if (typeof payload.text !== 'string' || payload.text.length === 0) {
          throw new Error('ctf_cipher 需要非空的 text 参数（要处理的密文）')
        }
        const text = payload.text
        const action = normalizeEnum(payload.action, ['bruteforce', 'apply'], 'bruteforce', 'action')
        const cipher = normalizeEnum(payload.cipher, CIPHERS, 'caesar', 'cipher')
        const options = {
          key: typeof payload.key === 'string' ? payload.key : undefined,
          shift: payload.shift,
          rails: payload.rails === undefined || payload.rails === null || payload.rails === ''
            ? undefined
            : clampInt(payload.rails, 2, 20, 3),
          maxShift: clampInt(payload.maxShift, 1, 94, 94),
        }
        if (action === 'apply') {
          return { text: buildApplyReport(cipher, text, applyCipher(cipher, text, options)) }
        }
        let candidates = []
        let notice
        try {
          candidates = runBruteforce(cipher, text, options)
        } catch (error) {
          notice = String(error?.message ?? error ?? '未知错误')
        }
        return { text: buildBruteforceReport(cipher, text, rankCandidates(candidates), notice) }
      } catch (error) {
        return { text: errorReport('ctf_cipher', error) }
      }
    },
  }
}
