/**
 * `ctf_file` — 一次调用完成二进制文件取证：文件指纹、内嵌对象、尾部附加数据、
 * flag 形状命中、strings 摘要与 Base64 长块。
 *
 * 设计目标是把「拿到一个可疑文件先看什么」固定成一条可复现的流水线：
 *   1. magic 指纹和扩展名交叉校验（扩展名骗人是最常见的考点）；
 *   2. 在整个字节流里扫内嵌对象的 magic（PNG 套 ZIP、PDF 里塞 ELF 之类）；
 *   3. 容器尾部标记（PNG IEND / JPEG FFD9 / ZIP EOCD / gzip 流尾）之后的附加字节；
 *   4. flag 形状、strings、Base64 长块这些「答案可能藏在明处」的线索。
 *
 * 只读：唯一会写盘的路径是 `extractEmbedded=true` 时落到输入文件同目录的
 * `<basename>_extracted/`。依赖仅 Node 内置模块。
 */
import { createHash } from 'node:crypto'
import { mkdir, open, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'
import zlib from 'node:zlib'
import {
  bytesToHex,
  clampInt,
  escapeNonPrintable,
  extractStrings,
  formatBytes,
  formatRows,
  preview,
  readBytesSafe,
  resolveSessionCwd,
  resolveUserPath,
  textOutput,
} from './util.js'

/** 超过这个大小就不整文件读入：只采样头尾并在报告里明确降级。 */
const MAX_FULL_READ = 128 * 1024 * 1024
/** 降级模式下头/尾各采样多少字节。 */
const SAMPLE_BYTES = 2 * 1024 * 1024

const bytesOf = (...values) => Uint8Array.from(values)
const asciiOf = (text) => Uint8Array.from([...text].map((char) => char.charCodeAt(0)))

/** Uint8Array → Buffer（零拷贝视图，便于 indexOf / toString）。 */
function toBuffer(bytes) {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
}

function readU16LE(bytes, at) {
  return bytes[at] | (bytes[at + 1] << 8)
}
function readU32LE(bytes, at) {
  return (bytes[at] | (bytes[at + 1] << 8) | (bytes[at + 2] << 16) | (bytes[at + 3] << 24)) >>> 0
}

/** ZIP 家族共享的扩展名：同一份 magic 可能叫 .docx/.jar/.apk。 */
const ZIP_EXTS = [
  'zip', 'jar', 'war', 'ear', 'apk', 'aar', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm',
  'epub', 'odt', 'ods', 'odp', 'whl', 'xpi', 'ipa', 'kra', 'sketch', 'cbz',
]

/**
 * 文件头 magic 表。`at` 表示 magic 在文件内的绝对偏移（默认 0），
 * `exts` 是该类型常见的真实扩展名，用于和用户文件名交叉校验。
 */
export const MAGIC_TABLE = [
  { type: 'PNG', label: 'PNG 图像', magics: [bytesOf(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)], exts: ['png', 'apng'] },
  { type: 'JPEG', label: 'JPEG 图像', magics: [bytesOf(0xff, 0xd8, 0xff)], exts: ['jpg', 'jpeg', 'jpe', 'jfif', 'mpo'] },
  { type: 'GIF', label: 'GIF 图像', magics: [asciiOf('GIF87a'), asciiOf('GIF89a')], exts: ['gif'] },
  { type: 'PDF', label: 'PDF 文档', magics: [asciiOf('%PDF-')], exts: ['pdf'] },
  { type: 'ZIP', label: 'ZIP 家族（zip/jar/apk/Office/EPUB 等）', magics: [bytesOf(0x50, 0x4b, 0x03, 0x04), bytesOf(0x50, 0x4b, 0x05, 0x06), bytesOf(0x50, 0x4b, 0x07, 0x08)], exts: ZIP_EXTS },
  { type: 'GZIP', label: 'gzip 压缩流', magics: [bytesOf(0x1f, 0x8b, 0x08)], exts: ['gz', 'tgz'] },
  { type: 'BZIP2', label: 'bzip2 压缩流', magics: [asciiOf('BZh')], exts: ['bz2', 'tbz2'] },
  { type: 'XZ', label: 'XZ 压缩流', magics: [bytesOf(0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)], exts: ['xz', 'txz'] },
  { type: 'ZSTD', label: 'Zstandard 压缩流', magics: [bytesOf(0x28, 0xb5, 0x2f, 0xfd)], exts: ['zst'] },
  { type: '7ZIP', label: '7-Zip 压缩包', magics: [bytesOf(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c)], exts: ['7z'] },
  { type: 'RAR', label: 'RAR 压缩包', magics: [bytesOf(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07)], exts: ['rar'] },
  { type: 'ELF', label: 'ELF 可执行文件', magics: [bytesOf(0x7f, 0x45, 0x4c, 0x46)], exts: ['elf', 'so', 'o', 'ko', 'bin', 'out'] },
  { type: 'PE', label: 'PE / MZ 可执行文件', magics: [asciiOf('MZ')], exts: ['exe', 'dll', 'sys', 'scr', 'ocx', 'com', 'efi'] },
  { type: 'SQLITE', label: 'SQLite 数据库', magics: [asciiOf('SQLite format 3\u0000')], exts: ['sqlite', 'sqlite3', 'db'] },
  { type: 'WASM', label: 'WebAssembly 模块', magics: [bytesOf(0x00, 0x61, 0x73, 0x6d)], exts: ['wasm'] },
  { type: 'BMP', label: 'BMP 位图', magics: [asciiOf('BM')], exts: ['bmp', 'dib'] },
  { type: 'PCAP', label: 'PCAP 抓包', magics: [bytesOf(0xd4, 0xc3, 0xb2, 0xa1), bytesOf(0xa1, 0xb2, 0xc3, 0xd4), bytesOf(0x4d, 0x3c, 0xb2, 0xa1), bytesOf(0xa1, 0xb2, 0x3c, 0x4d)], exts: ['pcap', 'cap'] },
  { type: 'PCAPNG', label: 'PCAPNG 抓包', magics: [bytesOf(0x0a, 0x0d, 0x0d, 0x0a)], exts: ['pcapng'] },
  { type: 'JAVA_CLASS', label: 'Java class（与 Mach-O fat 头冲突）', magics: [bytesOf(0xca, 0xfe, 0xba, 0xbe)], exts: ['class'] },
  { type: 'OLE', label: 'OLE2 复合文档（doc/xls/ppt/msi）', magics: [bytesOf(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1)], exts: ['doc', 'xls', 'ppt', 'msi', 'msg', 'vsd', 'pub'] },
  { type: 'MP4', label: 'MP4 / ISO BMFF（`ftyp` 在偏移 4）', at: 4, magics: [asciiOf('ftyp')], exts: ['mp4', 'm4a', 'm4v', 'mov', '3gp', 'heic', 'heif', 'avif'] },
  { type: 'RIFF', label: 'RIFF 容器（WAV/AVI/WebP）', magics: [asciiOf('RIFF')], exts: ['wav', 'avi', 'webp'] },
  { type: 'TIFF', label: 'TIFF 图像', magics: [bytesOf(0x49, 0x49, 0x2a, 0x00), bytesOf(0x4d, 0x4d, 0x00, 0x2a)], exts: ['tif', 'tiff'] },
  { type: 'ICO', label: 'ICO / CUR 图标', magics: [bytesOf(0x00, 0x00, 0x01, 0x00)], exts: ['ico', 'cur'] },
  { type: 'FLAC', label: 'FLAC 无损音频', magics: [asciiOf('fLaC')], exts: ['flac'] },
  { type: 'OGG', label: 'Ogg 容器', magics: [asciiOf('OggS')], exts: ['ogg', 'oga', 'ogv'] },
  { type: 'TAR', label: 'TAR 归档（`ustar` 在偏移 257）', at: 257, magics: [asciiOf('ustar')], exts: ['tar'] },
  { type: 'RTF', label: 'RTF 文档', magics: [asciiOf('{\\rtf')], exts: ['rtf'] },
]

/**
 * 内嵌对象扫描用的签名。这里刻意不用 2 字节的 `BM`/`MZ`/`PK`：
 * 在随机二进制里它们误报太多，只保留长度 >= 3 的强签名。
 */
const EMBEDDED_SIGNATURES = [
  { type: 'ZIP', label: 'ZIP 家族（zip/jar/apk/docx...）', needle: bytesOf(0x50, 0x4b, 0x03, 0x04), ext: 'zip' },
  { type: 'PNG', label: 'PNG 图像', needle: bytesOf(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a), ext: 'png' },
  // JPEG 只认「SOI + 常见首 marker」：单独的 FF D8 FF 三字节在任意二进制里误报太多。
  { type: 'JPEG', label: 'JPEG 图像', needle: bytesOf(0xff, 0xd8, 0xff, 0xe0), ext: 'jpg' },
  { type: 'JPEG', label: 'JPEG 图像', needle: bytesOf(0xff, 0xd8, 0xff, 0xe1), ext: 'jpg' },
  { type: 'JPEG', label: 'JPEG 图像', needle: bytesOf(0xff, 0xd8, 0xff, 0xdb), ext: 'jpg' },
  { type: 'JPEG', label: 'JPEG 图像', needle: bytesOf(0xff, 0xd8, 0xff, 0xee), ext: 'jpg' },
  { type: 'JPEG', label: 'JPEG 图像', needle: bytesOf(0xff, 0xd8, 0xff, 0xc0), ext: 'jpg' },
  { type: 'JPEG', label: 'JPEG 图像', needle: bytesOf(0xff, 0xd8, 0xff, 0xc2), ext: 'jpg' },
  { type: 'GIF', label: 'GIF 图像', needle: asciiOf('GIF89a'), ext: 'gif' },
  { type: 'GIF', label: 'GIF 图像', needle: asciiOf('GIF87a'), ext: 'gif' },
  { type: 'PDF', label: 'PDF 文档', needle: asciiOf('%PDF-'), ext: 'pdf' },
  { type: '7ZIP', label: '7-Zip 压缩包', needle: bytesOf(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c), ext: '7z' },
  { type: 'RAR', label: 'RAR 压缩包', needle: bytesOf(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07), ext: 'rar' },
  { type: 'ELF', label: 'ELF 可执行文件', needle: bytesOf(0x7f, 0x45, 0x4c, 0x46), ext: 'elf' },
  { type: 'GZIP', label: 'gzip 压缩流', needle: bytesOf(0x1f, 0x8b, 0x08), ext: 'gz' },
  { type: 'SQLITE', label: 'SQLite 数据库', needle: asciiOf('SQLite format 3'), ext: 'sqlite' },
  { type: 'WASM', label: 'WebAssembly 模块', needle: bytesOf(0x00, 0x61, 0x73, 0x6d), ext: 'wasm' },
  { type: 'PCAPNG', label: 'PCAPNG 抓包', needle: bytesOf(0x0a, 0x0d, 0x0d, 0x0a), ext: 'pcapng' },
  { type: 'PCAP', label: 'PCAP 抓包', needle: bytesOf(0xd4, 0xc3, 0xb2, 0xa1), ext: 'pcap' },
  { type: 'JAVA_CLASS', label: 'Java class / Mach-O fat', needle: bytesOf(0xca, 0xfe, 0xba, 0xbe), ext: 'class' },
  { type: 'OLE', label: 'OLE2 复合文档', needle: bytesOf(0xd0, 0xcf, 0x11, 0xe0), ext: 'doc' },
]

/** flag 形状：`flag{...}` / `CTF{...}` / `KEY{...}` 等，兼容数字下划线前缀。 */
const FLAG_PATTERN = /[A-Za-z0-9_]{2,20}\{[^}\n]{1,120}\}/g

/**
 * 读取文件：小文件整读；超过 128MiB 时只采样头尾并标记降级。
 * @param {string} target 绝对路径
 */
async function readForAnalysis(target) {
  let stats
  try {
    stats = await stat(target)
  } catch (error) {
    return { ok: false, error: `${error?.code ?? 'UNKNOWN'}: ${error?.message ?? String(error)}` }
  }
  if (stats.isDirectory()) return { ok: false, error: '目标是一个目录，ctf_file 只接受单个文件。' }
  if (stats.size === 0) {
    return { ok: true, size: 0, degraded: false, regions: [{ bytes: new Uint8Array(0), base: 0 }] }
  }
  if (stats.size <= MAX_FULL_READ) {
    const read = await readBytesSafe(target)
    if (!read.ok) return { ok: false, error: read.error }
    return { ok: true, size: stats.size, degraded: false, regions: [{ bytes: read.bytes, base: 0 }] }
  }
  // 大文件：只读头尾，避免把进程内存打爆；报告里明确说明降级。
  const handle = await open(target, 'r')
  try {
    const headLength = Math.min(SAMPLE_BYTES, stats.size)
    const tailLength = Math.min(SAMPLE_BYTES, stats.size - headLength)
    const head = Buffer.alloc(headLength)
    const tail = Buffer.alloc(tailLength)
    if (headLength > 0) await handle.read(head, 0, headLength, 0)
    if (tailLength > 0) await handle.read(tail, 0, tailLength, stats.size - tailLength)
    return {
      ok: true,
      size: stats.size,
      degraded: true,
      regions: [
        { bytes: new Uint8Array(head), base: 0 },
        { bytes: new Uint8Array(tail), base: stats.size - tailLength },
      ],
    }
  } finally {
    await handle.close()
  }
}

/**
 * 用 magic 表识别文件真实类型。
 * @param {Uint8Array} bytes
 * @returns {undefined | {type: string, label: string, exts: string[], at: number}}
 */
export function detectMagic(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return undefined
  for (const entry of MAGIC_TABLE) {
    const at = entry.at ?? 0
    for (const magic of entry.magics) {
      if (at + magic.length > bytes.length) continue
      let match = true
      for (let i = 0; i < magic.length; i += 1) {
        if (bytes[at + i] !== magic[i]) {
          match = false
          break
        }
      }
      if (match) return { type: entry.type, label: entry.label, exts: entry.exts, at }
    }
  }
  return undefined
}

/** 取文件扩展名（小写、不含点）。 */
function extensionOf(target) {
  return path.extname(target).toLowerCase().replace(/^\./, '')
}

/**
 * 扫描内嵌对象的 magic 偏移。
 * @param {Uint8Array} bytes 单个区域字节
 * @param {{perTypeLimit?: number, totalLimit?: number, base?: number}} [options]
 */
function scanEmbeddedObjects(bytes, options = {}) {
  const perTypeLimit = options.perTypeLimit ?? 24
  const totalLimit = options.totalLimit ?? 160
  const base = options.base ?? 0
  const buffer = toBuffer(bytes)
  /** @type {Array<{type: string, label: string, ext: string, offset: number, base: number}>} */
  const hits = []
  for (const signature of EMBEDDED_SIGNATURES) {
    const needle = Buffer.from(signature.needle)
    let from = 0
    let count = 0
    while (count < perTypeLimit && hits.length < totalLimit) {
      const index = buffer.indexOf(needle, from)
      if (index < 0) break
      hits.push({ type: signature.type, label: signature.label, ext: signature.ext, offset: index, base })
      count += 1
      from = index + 1
    }
  }
  // MP4 的 `ftyp` 在偏移 4，单独处理。
  const ftyp = Buffer.from(asciiOf('ftyp'))
  let ftypFrom = 0
  let ftypCount = 0
  while (ftypCount < perTypeLimit && hits.length < totalLimit) {
    const index = buffer.indexOf(ftyp, ftypFrom)
    if (index < 0) break
    if (index >= 4) hits.push({ type: 'MP4', label: 'MP4 / ISO BMFF（`ftyp`）', ext: 'mp4', offset: index - 4, base })
    ftypFrom = index + 1
    ftypCount += 1
  }
  return hits
}

/** 尝试定位 gzip 成员结束位置（用于尾部附加数据与大小估计）。 */
function findGzipEnd(bytes, offset) {
  const tail = bytes.subarray(offset)
  try {
    zlib.gunzipSync(toBuffer(tail))
    return { end: bytes.length, exact: false, note: '整段可解压；若尾部有被 zlib 忽略的填充字节，这里无法精确切分。' }
  } catch {
    // 继续用回退试解压定位。
  }
  if (tail.length > 2 * 1024 * 1024) {
    return { end: undefined, exact: false, note: 'gzip 样本过大，未做逐字节回退定位。' }
  }
  const maxTrim = Math.min(tail.length - 18, tail.length > 1024 * 1024 ? 64 : 2048)
  for (let trim = 1; trim <= maxTrim; trim += 1) {
    const end = tail.length - trim
    if (end < 18) break
    try {
      zlib.gunzipSync(toBuffer(tail.subarray(0, end)))
      return { end: offset + end, exact: true, note: '通过逐字节回退试解压定位到 gzip 流结尾。' }
    } catch {
      // 继续回退。
    }
  }
  return { end: undefined, exact: false, note: 'gzip 流尾定位失败，无法精确切分附加数据。' }
}

/**
 * 估计一个内嵌对象的长度。
 * @param {Uint8Array} bytes 该对象所在的区域字节
 * @param {number} offset 区域内的相对偏移
 * @param {string} type 对象类型
 * @param {number} [nextOffset] 区域内下一个对象的偏移（用于回退估计）
 */
export function estimateEmbeddedSize(bytes, offset, type, nextOffset) {
  const buffer = toBuffer(bytes)
  const remaining = bytes.length - offset
  const fallback = (note) => {
    const end = nextOffset !== undefined && nextOffset > offset ? Math.min(nextOffset, bytes.length) : bytes.length
    return { size: Math.max(0, end - offset), exact: false, note }
  }
  switch (type) {
    case 'ZIP': {
      const eocd = buffer.indexOf(Buffer.from(bytesOf(0x50, 0x4b, 0x05, 0x06)), offset)
      if (eocd >= 0 && eocd + 22 <= bytes.length) {
        const commentLength = readU16LE(bytes, eocd + 20)
        const end = eocd + 22 + commentLength
        if (end <= bytes.length) return { size: end - offset, exact: true, note: '按 EOCD 计算。' }
      }
      return fallback('未找到 ZIP EOCD，按到下一个对象/文件尾估计。')
    }
    case 'PNG': {
      const iend = buffer.indexOf(Buffer.from(asciiOf('IEND')), offset + 8)
      if (iend >= 0 && iend + 8 <= bytes.length) return { size: iend + 8 - offset, exact: true, note: '按 IEND 计算。' }
      return fallback('未找到 PNG IEND，按到下一个对象/文件尾估计。')
    }
    case 'JPEG': {
      // 主容器从 0 开始时用「最后一个 EOI」：EXIF 缩略图会让第一个 FFD9 提前出现。
      const eoi = offset === 0
        ? buffer.lastIndexOf(Buffer.from(bytesOf(0xff, 0xd9)))
        : buffer.indexOf(Buffer.from(bytesOf(0xff, 0xd9)), offset + 2)
      if (eoi >= 0 && eoi >= offset) return { size: eoi + 2 - offset, exact: offset === 0, note: offset === 0 ? '按最后一个 FFD9 计算（容器可能内嵌缩略图）。' : '按第一个 FFD9 计算。' }
      return fallback('未找到 JPEG FFD9，按到下一个对象/文件尾估计。')
    }
    case 'GIF': {
      const trailer = buffer.indexOf(Buffer.from(bytesOf(0x3b)), offset + 6)
      if (trailer >= 0) return { size: trailer + 1 - offset, exact: false, note: '按 GIF trailer 0x3B 估计（可能被图像数据里的同值字节误判）。' }
      return fallback('未找到 GIF trailer，按到下一个对象/文件尾估计。')
    }
    case 'PDF': {
      const eof = buffer.indexOf(Buffer.from(asciiOf('%%EOF')), offset)
      if (eof >= 0) return { size: eof + 5 - offset, exact: true, note: '按 %%EOF 计算。' }
      return fallback('未找到 %%EOF，按到下一个对象/文件尾估计。')
    }
    case 'BMP': {
      if (offset + 6 <= bytes.length) {
        const declared = readU32LE(bytes, offset + 2)
        if (declared >= 14 && declared <= remaining) return { size: declared, exact: true, note: '按 BMP 头部声明长度计算。' }
      }
      return fallback('BMP 头部声明长度不可用，按到下一个对象/文件尾估计。')
    }
    case 'GZIP': {
      const gzip = findGzipEnd(bytes, offset)
      if (gzip.end !== undefined) return { size: gzip.end - offset, exact: gzip.exact, note: gzip.note }
      return fallback(gzip.note)
    }
    case 'RAR':
    case '7ZIP':
    case 'ELF':
    case 'WASM':
    case 'SQLITE':
    case 'JAVA_CLASS':
    case 'OLE':
      return fallback('该格式没有可靠的流内结束标记，按到下一个对象/文件尾估计。')
    default:
      return fallback('按到下一个对象/文件尾估计。')
  }
}

/**
 * 找出容器尾部标记之后的附加数据。
 * @param {Uint8Array} bytes 区域字节（通常是文件最后一段）
 * @param {string | undefined} detectedType 主容器的 magic 类型
 * @param {number} [base] 该区域在文件内的起始偏移
 */
export function findTrailingData(bytes, detectedType, base = 0) {
  const results = []
  if (bytes.length === 0) return results
  const buffer = toBuffer(bytes)
  const add = (format, endPosition, marker) => {
    if (endPosition === undefined || endPosition < 0 || endPosition > bytes.length) return
    if (endPosition === bytes.length) return
    results.push({ format, offset: base + endPosition, length: bytes.length - endPosition, marker })
  }
  if (detectedType === 'PNG') {
    const iend = buffer.lastIndexOf(Buffer.from(asciiOf('IEND')))
    if (iend >= 0) add('PNG（IEND 之后）', iend + 8, 'IEND')
  } else if (detectedType === 'JPEG') {
    const eoi = buffer.lastIndexOf(Buffer.from(bytesOf(0xff, 0xd9)))
    if (eoi >= 0) add('JPEG（FFD9 之后）', eoi + 2, 'FFD9')
  } else if (detectedType === 'ZIP') {
    const eocd = buffer.lastIndexOf(Buffer.from(bytesOf(0x50, 0x4b, 0x05, 0x06)))
    if (eocd >= 0 && eocd + 22 <= bytes.length) {
      const commentLength = readU16LE(bytes, eocd + 20)
      add('ZIP（EOCD 之后）', eocd + 22 + commentLength, 'EOCD')
    }
  } else if (detectedType === 'GZIP') {
    const gzip = findGzipEnd(bytes, 0)
    if (gzip.end !== undefined) add('gzip（压缩流之后）', gzip.end, 'gzip EOF')
  } else if (detectedType === 'PDF') {
    const eof = buffer.lastIndexOf(Buffer.from(asciiOf('%%EOF')))
    if (eof >= 0) add('PDF（%%EOF 之后）', eof + 5, '%%EOF')
  } else {
    // 容器类型未识别时，仍检查是否存在「尾部藏了一张 PNG」这种常见套路。
    const iend = buffer.lastIndexOf(Buffer.from(asciiOf('IEND')))
    if (iend >= 0) add('PNG（IEND 之后，容器类型非 PNG）', iend + 8, 'IEND')
  }
  return results
}

/**
 * 判断一个 flag 形状命中的大括号内容是否「像真的」：随机二进制里 `{` 很常见，
 * 不加过滤会把压缩/图像数据里的噪声当成 flag。这里要求大括号内 >=80% 可打印 ASCII。
 */
function plausibleFlagValue(matchText) {
  const brace = matchText.indexOf('{')
  if (brace < 0) return false
  const inner = matchText.slice(brace + 1, -1)
  if (inner.length === 0) return false
  let printable = 0
  for (const char of inner) {
    const code = char.codePointAt(0) ?? 0
    if (code >= 0x20 && code <= 0x7e) printable += 1
  }
  return printable / inner.length >= 0.8
}

/**
 * 扫描 flag 形状的字符串。
 * @param {Uint8Array} bytes 区域字节
 * @param {number} [limit] 最多返回条数
 * @param {number} [base] 区域在文件内的起始偏移
 */
export function findFlags(bytes, limit = 50, base = 0) {
  const text = toBuffer(bytes).toString('latin1')
  const found = []
  const pattern = new RegExp(FLAG_PATTERN.source, 'g')
  let match
  while ((match = pattern.exec(text)) !== null && found.length < limit) {
    const start = match.index
    const value = match[0]
    if (!plausibleFlagValue(value)) continue
    // 要求前缀是最大匹配：前面若还是字母数字，说明是从噪声中间截出来的。
    if (start > 0 && /[A-Za-z0-9_]/.test(text[start - 1])) continue
    const end = start + value.length
    const contextStart = Math.max(0, start - 16)
    const contextEnd = Math.min(bytes.length, end + 16)
    found.push({
      offset: base + start,
      value,
      context: escapeNonPrintable(bytes.subarray(contextStart, contextEnd), 200),
      priority: /^(flag|ctf|key)/i.test(value) ? 1 : 0,
    })
  }
  // flag{/CTF{ 开头的优先，其次按偏移；噪声里偶然命中的随机前缀排后面。
  found.sort((left, right) => right.priority - left.priority || left.offset - right.offset)
  return found
}

/** 可打印占比（0~1），用于判断解码结果是不是人话。 */
function printableRatio(bytes) {
  if (bytes.length === 0) return 0
  let printable = 0
  for (const byte of bytes) {
    if (byte === 0x09 || byte === 0x0a || byte === 0x0d || (byte >= 0x20 && byte <= 0x7e)) printable += 1
  }
  return printable / bytes.length
}

/**
 * 找高置信 Base64 长块并解码预览。
 * @param {Uint8Array} bytes 区域字节
 * @param {number} [limit]
 * @param {number} [base]
 */
export function findBase64Blocks(bytes, limit = 12, base = 0) {
  const text = toBuffer(bytes).toString('latin1')
  const pattern = /[A-Za-z0-9+/]{40,}={0,2}/g
  const found = []
  let match
  while ((match = pattern.exec(text)) !== null && found.length < limit) {
    const encoded = match[0]
    let decoded
    try {
      decoded = new Uint8Array(Buffer.from(encoded, 'base64'))
    } catch {
      continue
    }
    if (decoded.length < 16) continue
    const ratio = printableRatio(decoded)
    if (ratio < 0.85) continue
    found.push({
      offset: base + match.index,
      encodedLength: encoded.length,
      decodedLength: decoded.length,
      decodedPreview: escapeNonPrintable(decoded, 240),
      printable: ratio,
    })
  }
  return found
}

/** 计算文件的 MD5/SHA1/SHA256。 */
export function hashesOf(bytes) {
  const buffer = toBuffer(bytes)
  const out = {}
  for (const algorithm of ['md5', 'sha1', 'sha256']) out[algorithm] = createHash(algorithm).update(buffer).digest('hex')
  return out
}

/** 渲染「基本信息」一节。 */
function renderBasicInfo(target, read, hashes) {
  const lines = []
  const infoRows = [
    ['路径', target],
    ['大小', `${read.size} 字节（${formatBytes(read.size)}）`],
    ['MD5', hashes.md5],
    ['SHA1', hashes.sha1],
    ['SHA256', hashes.sha256],
  ]
  if (read.degraded === true) {
    infoRows.push(['读取方式', `降级：文件 > ${formatBytes(MAX_FULL_READ)}，仅分析头/尾各 ${formatBytes(SAMPLE_BYTES)}；上面的哈希是采样哈希。`])
  }
  lines.push('## 基本信息')
  lines.push(formatRows(infoRows, ['项目', '值']))
  return lines
}

/** 渲染「文件指纹」一节。 */
function renderFingerprint(target, primary, headBytes) {
  const lines = []
  const extension = extensionOf(target)
  lines.push('## 文件指纹')
  if (primary === undefined) {
    lines.push('头部 magic 未命中任何已知格式；可能是纯文本、自定义格式或被刻意去掉了文件头。')
    if (headBytes.length > 0) lines.push(`头部 ${Math.min(16, headBytes.length)} 字节：\`${bytesToHex(headBytes.subarray(0, 16))}\``)
    if (extension.length > 0) lines.push(`文件名扩展名：\`.${extension}\`（无法交叉校验）。`)
    return lines
  }
  const extensionMatches = extension.length > 0 && primary.exts.includes(extension)
  const rows = [
    ['真实类型', `${primary.label}（${primary.type}）`],
    ['magic 偏移', String(primary.at)],
    ['期望扩展名', primary.exts.slice(0, 8).join(' / ') + (primary.exts.length > 8 ? ' ...' : '')],
    ['文件名扩展名', extension.length > 0 ? `.${extension}` : '（无扩展名）'],
    ['交叉校验', extensionMatches ? '一致' : extension.length === 0 ? '无扩展名，无法校验' : '不一致'],
  ]
  lines.push(formatRows(rows, ['项目', '值']))
  if (extension.length > 0 && !extensionMatches) {
    lines.push('')
    lines.push(`**扩展名与真实类型不一致**：文件实际是 ${primary.label}，但扩展名是 \`.${extension}\`。`)
  }
  if (primary.type === 'JAVA_CLASS') lines.push('\n注意：`cafebabe` 同时是 Mach-O universal 文件头，需要结合上下文判断。')
  return lines
}

/** 渲染「内嵌对象」一节。 */
function renderEmbedded(embedded) {
  const lines = []
  lines.push('## 内嵌对象')
  if (embedded.length === 0) {
    lines.push('未在字节流中发现已知 magic 的内嵌对象（ZIP/PNG/JPEG/GIF/PDF/7z/RAR/ELF/gzip/SQLite/WASM/PCAP/OLE/MP4）。')
    return lines
  }
  const rows = embedded.map((item, index) => [
    String(index + 1),
    item.label,
    `0x${item.offset.toString(16)}（${item.offset}）`,
    item.size === undefined ? '?' : `${item.size} B${item.exact === false ? '（估计）' : ''}`,
    item.offset === 0 ? '文件起点（即主容器）' : item.note ?? '',
  ])
  lines.push(formatRows(rows, ['#', '类型', '偏移', '大小估计', '备注']))
  return lines
}

/** 渲染「尾部附加数据」一节。 */
function renderTrailing(trailing) {
  const lines = []
  lines.push('## 尾部附加数据')
  if (trailing.length === 0) {
    lines.push('未发现 PNG IEND / JPEG FFD9 / ZIP EOCD / gzip 流尾之后的附加字节（或容器类型无法定位尾部）。')
    return lines
  }
  for (const item of trailing) {
    lines.push(`- **${item.format}**：结束标记偏移 0x${(item.offset).toString(16)}，附加 **${item.length}** 字节。`)
  }
  return lines
}

/** 渲染「flag 形状命中」一节。 */
function renderFlags(flags) {
  const lines = []
  lines.push('## flag 形状命中')
  if (flags.length === 0) {
    lines.push('正则 `[A-Za-z0-9_]{2,20}\\{[^}\\n]{1,120}\\}` 未命中；flag 可能被编码/加密，或藏在图像像素里（试试 `ctf_stego`）。')
    return lines
  }
  const rows = flags.map((flag, index) => [String(index + 1), `0x${flag.offset.toString(16)}`, flag.value, flag.context])
  lines.push(formatRows(rows, ['#', '偏移', '内容', '上下文']))
  return lines
}

/** 渲染 strings 一节。 */
function renderStrings(target, regions, minStringLength, includeStrings) {
  const lines = []
  lines.push('## strings 摘要')
  if (!includeStrings) {
    lines.push('已按 `includeStrings=false` 跳过。')
    return lines
  }
  const rows = []
  let total = 0
  for (const region of regions) {
    const strings = extractStrings(region.bytes, { minLength: minStringLength, limit: 60 })
    for (const item of strings) {
      if (total >= 60) break
      rows.push([`0x${(region.base + item.offset).toString(16)}`, preview(item.text, 100)])
      total += 1
    }
    if (total >= 60) break
  }
  if (rows.length === 0) {
    lines.push(`没有长度 >= ${minStringLength} 的可打印 ASCII 串；可能是加密/压缩数据。`)
    return lines
  }
  lines.push(formatRows(rows, ['偏移', '字符串']))
  if (total >= 60) lines.push('\n只显示前 60 条；需要完整提取时用 `grep -a` 或专用 strings 工具。')
  return lines
}

/** 渲染 Base64 长块一节。 */
function renderBase64(blocks) {
  const lines = []
  lines.push('## Base64 长块')
  if (blocks.length === 0) {
    lines.push('未发现「长度 >= 40 字符且解码后可打印」的 Base64 长块。')
    return lines
  }
  const rows = blocks.map((block, index) => [
    String(index + 1),
    `0x${block.offset.toString(16)}`,
    String(block.encodedLength),
    String(block.decodedLength),
    `${Math.round(block.printable * 100)}%`,
    block.decodedPreview,
  ])
  lines.push(formatRows(rows, ['#', '偏移', '编码长度', '解码长度', '可打印占比', '解码预览']))
  return lines
}

/** 渲染「落盘结果」一节。 */
function renderExtracted(written) {
  const lines = []
  lines.push('## 落盘结果')
  if (written.length === 0) {
    lines.push('没有可落盘的内嵌对象（或扫描结果为空）。')
    return lines
  }
  lines.push(formatRows(written.map((item) => [item.path, `${item.size} B`, item.note ?? '']), ['文件', '大小', '备注']))
  lines.push('')
  lines.push(`仅写入输入文件同目录下的 \`${path.basename(path.dirname(written[0].path))}/\`，没有修改原文件。`)
  return lines
}

/**
 * 把内嵌对象写到 `<basename>_extracted/`。
 * 这是本工具唯一的写盘路径，且目录固定在输入文件旁边。
 */
async function extractEmbeddedObjects(target, embedded, limit) {
  const directory = path.join(path.dirname(target), `${path.basename(target)}_extracted`)
  await mkdir(directory, { recursive: true })
  const written = []
  for (let index = 0; index < embedded.length && written.length < limit; index += 1) {
    const item = embedded[index]
    const region = item.region
    if (region === undefined) continue
    const relativeOffset = item.offset - region.base
    if (relativeOffset < 0 || relativeOffset >= region.bytes.length) continue
    let size = item.size ?? region.bytes.length - relativeOffset
    let note = item.exact === false ? '大小估计' : ''
    if (relativeOffset + size > region.bytes.length) {
      size = region.bytes.length - relativeOffset
      note = '对象跨出采样区，仅落盘可读部分'
    }
    const safeType = String(item.type).toLowerCase().replace(/[^a-z0-9]+/g, '-')
    const name = `${String(written.length + 1).padStart(4, '0')}-${safeType}.${item.ext ?? 'bin'}`
    const outputPath = path.join(directory, name)
    await writeFile(outputPath, Buffer.from(region.bytes.subarray(relativeOffset, relativeOffset + size)))
    written.push({ path: outputPath, size, note })
  }
  return written
}

/**
 * 把分析结果渲染成 Markdown。结论先行，随后按取证流程分节。
 * @param {{target: string, read: any, includeStrings: boolean, minStringLength: number, extract: boolean, maxEmbedded: number}} params
 */
async function analyzeFile(params) {
  const { target, read, includeStrings, minStringLength, extract, maxEmbedded } = params
  const regions = read.regions
  const head = regions[0]
  const tail = regions[regions.length - 1]
  const primary = detectMagic(head.bytes)

  // 主哈希：小文件对全文件；降级模式对头+尾采样，并在基本信息里说明。
  const sample = read.degraded === true
    ? new Uint8Array(Buffer.concat([toBuffer(head.bytes), toBuffer(tail.bytes)]))
    : head.bytes
  const hashes = hashesOf(sample)

  // 内嵌扫描：按区域分段扫描，再统一换算成绝对偏移、合并排序。
  const embeddedHits = []
  for (const region of regions) {
    for (const hit of scanEmbeddedObjects(region.bytes, { base: region.base })) embeddedHits.push({ ...hit, region })
  }
  embeddedHits.sort((a, b) => a.offset - b.offset)

  // 大小估计需要「下一个对象偏移」作为回退边界。
  const embedded = embeddedHits.map((hit, index) => {
    const next = embeddedHits[index + 1]
    const nextRelative = next === undefined || next.region !== hit.region ? undefined : next.offset - hit.region.base
    const estimate = estimateEmbeddedSize(hit.region.bytes, hit.offset - hit.region.base, hit.type, nextRelative)
    return { ...hit, ...estimate, exact: estimate.exact, note: estimate.note }
  })

  const trailing = findTrailingData(tail.bytes, primary?.type, tail.base)
  const flags = []
  for (const region of regions) flags.push(...findFlags(region.bytes, 50, region.base))
  let base64Blocks = []
  for (const region of regions) base64Blocks.push(...findBase64Blocks(region.bytes, 12, region.base))

  const lines = []
  lines.push('## 结论')
  lines.push(`- 真实类型：${primary === undefined ? '未识别（头部 magic 未命中）' : `${primary.label}（${primary.type}）`}`)
  const extension = extensionOf(target)
  if (primary !== undefined && extension.length > 0) {
    const consistent = primary.exts.includes(extension)
    lines.push(`- 扩展名交叉校验：\`.${extension}\` ${consistent ? '与真实类型一致' : '与真实类型**不一致**'}。`)
  }
  lines.push(`- 文件大小：${read.size} 字节（${formatBytes(read.size)}）。`)
  lines.push(`- 尾部附加数据：${trailing.length > 0 ? `发现 ${trailing.reduce((sum, item) => sum + item.length, 0)} 字节（${trailing.map((item) => item.format).join('、')}）` : '未发现'}。`)
  lines.push(`- 内嵌对象：${embedded.length > 0 ? `发现 ${embedded.length} 个 magic 命中` : '未发现'}。`)
  lines.push(`- flag 形状命中：${flags.length > 0 ? `${flags.length} 处` : '0 处'}；Base64 长块：${base64Blocks.length > 0 ? `${base64Blocks.length} 处` : '0 处'}。`)
  if (read.degraded === true) lines.push('- **读取降级**：文件超过 128MiB，只分析了头/尾采样，结论可能不完整（尤其内嵌对象与尾部判断）。')
  if (flags.length > 0) {
    lines.push('')
    lines.push(`最值得先看：\`${flags[0].value}\``)
  }
  lines.push('')

  lines.push(...renderBasicInfo(target, read, hashes))
  lines.push('')
  lines.push(...renderFingerprint(target, primary, head.bytes))
  lines.push('')
  lines.push(...renderEmbedded(embedded))
  lines.push('')
  lines.push(...renderTrailing(trailing))
  if (trailing.length > 0) {
    const lastTrailing = trailing[trailing.length - 1]
    const relativeOffset = lastTrailing.offset - tail.base
    const previewBytes = tail.bytes.subarray(relativeOffset, relativeOffset + 96)
    lines.push('')
    lines.push(`附加数据预览：\`${escapeNonPrintable(previewBytes, 200)}\``)
  }
  lines.push('')
  lines.push(...renderFlags(flags))
  lines.push('')
  lines.push(...renderStrings(target, regions, minStringLength, includeStrings))
  lines.push('')
  lines.push(...renderBase64(base64Blocks))

  if (extract) {
    lines.push('')
    try {
      const written = await extractEmbeddedObjects(target, embedded.map((item) => ({
        ...item,
        region: item.region,
      })), maxEmbedded)
      lines.push(...renderExtracted(written))
    } catch (error) {
      lines.push('## 落盘结果')
      lines.push(`写入失败：${error?.code ?? 'UNKNOWN'}: ${error?.message ?? String(error)}`)
    }
  }

  lines.push('')
  lines.push('## 下一步建议')
  if (primary?.type === 'PNG' || primary?.type === 'JPEG' || primary?.type === 'GIF' || primary?.type === 'BMP') {
    lines.push('- 图像类文件优先用 `ctf_stego` 查 PNG chunk / LSB 隐写。')
  }
  if (primary?.type === 'ZIP') lines.push('- ZIP 先用 `unzip -l` 看目录；有密码时把文件名/注释当线索。')
  if (trailing.length > 0) lines.push('- 尾部附加数据可用 `dd if=<file> bs=1 skip=<offset> of=tail.bin` 切出来再跑 `ctf_file`。')
  lines.push('- 需要看完整字节时用 `xxd <file> | less`；本工具只给摘要，不替代十六进制编辑器。')

  return lines.join('\n')
}

/**
 * 构造 `ctf_file` 工具定义。
 * @param {any} ctx 注册上下文（用于解析会话工作目录）
 */
export function createFileTool(ctx) {
  return {
    name: 'ctf_file',
    description:
      'Forensic triage for one binary file in a single call: detect the real type from magic bytes and cross-check the extension, scan the whole byte stream for embedded objects (ZIP/PNG/JPEG/PDF/7z/RAR/ELF/gzip/SQLite/WASM/PCAP/OLE/MP4), report trailing data after container end markers (PNG IEND, JPEG FFD9, ZIP EOCD, gzip EOF), find flag-shaped strings, summarize printable strings with offsets, and decode long Base64 blocks. Optionally extracts embedded objects into <basename>_extracted/ next to the input. Read-only except that explicit extraction; files above 128 MiB are sampled from head and tail and the report says so.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: {
          type: 'string',
          description: 'Required. File to inspect; relative paths resolve against the session working directory, `~` is expanded.',
        },
        includeStrings: {
          type: 'boolean',
          description: 'Include the printable-strings summary with offsets. Default true.',
        },
        extractEmbedded: {
          type: 'boolean',
          description: 'Write detected embedded objects into <basename>_extracted/ next to the input. Default false (read-only).',
        },
        maxEmbedded: {
          type: 'integer',
          description: 'Maximum number of embedded objects to extract (1-64, default 16).',
        },
        minStringLength: {
          type: 'integer',
          description: 'Minimum printable string length for the strings summary (3-32, default 4).',
        },
      },
      required: ['path'],
    },
    output: textOutput('CTF file forensics'),
    async execute(args, exec) {
      const cwd = resolveSessionCwd(ctx, exec)
      const rawPath = typeof args?.path === 'string' ? args.path : ''
      if (rawPath.trim().length === 0) {
        return { text: '## 结论\n缺少 `path`：请给出要分析的文件路径（相对路径基于会话工作目录）。' }
      }
      const target = resolveUserPath(rawPath, cwd)
      const read = await readForAnalysis(target)
      if (!read.ok) {
        return { text: `## 结论\n无法读取文件 \`${target}\`\n\n原因：${read.error}\n\n请确认路径正确、文件存在且有读权限。` }
      }
      if (read.size === 0) {
        return { text: `## 结论\n文件 \`${target}\` 是空文件（0 字节），没有可分析的内容。` }
      }
      const includeStrings = args?.includeStrings !== false
      const extract = args?.extractEmbedded === true
      const maxEmbedded = clampInt(args?.maxEmbedded, 1, 64, 16)
      const minStringLength = clampInt(args?.minStringLength, 3, 32, 4)
      try {
        const text = await analyzeFile({ target, read, includeStrings, minStringLength, extract, maxEmbedded })
        return { text }
      } catch (error) {
        return {
          text: `## 结论\n分析 \`${target}\` 时失败，但文件已成功读取。\n\n异常：${error?.code ?? 'UNKNOWN'}: ${error?.message ?? String(error)}\n\n这通常是本工具的解析缺陷；可以先用 \`xxd\` 查看头部字节。`,
        }
      }
    },
  }
}
