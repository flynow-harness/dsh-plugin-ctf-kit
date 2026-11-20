/**
 * `ctf_stego` — PNG 结构分析（chunk / IHDR / 文本块 / 尾随字节）与 PNG LSB 隐写提取。
 *
 * PNG 的 LSB 提取有两个必须自己做的步骤，不能只靠 inflate：
 *   1. IDAT 解压出来的是「带过滤器的扫描线」，每行开头有一个 filter 字节，
 *      必须按 PNG 规范逐行反过滤（0 None / 1 Sub / 2 Up / 3 Average / 4 Paeth）；
 *   2. bpp（每像素字节数）决定 Sub/Average/Paeth 取「左邻」的步长；灰度/RGB/带 Alpha
 *      的 bpp 分别是 1/2/3/4，算错一步整张图就成噪声，LSB 自然也就读不出来。
 *
 * 支持范围明确：仅 8-bit、非隔行、colorType 0/2/4/6（灰度 / RGB / 灰度+Alpha / RGBA）。
 * 索引色、16-bit、Adam7 隔行会返回可读的「不支持 + 原因」，而不是抛异常。
 * 依赖仅 Node 内置 `node:zlib`。
 */
import zlib from 'node:zlib'
import {
  bytesToHex,
  clampInt,
  decodeUtf8,
  escapeNonPrintable,
  formatRows,
  preview,
  readBytesSafe,
  resolveSessionCwd,
  resolveUserPath,
  textOutput,
} from './util.js'

/** PNG 文件签名（8 字节）。 */
export const PNG_SIGNATURE = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])

/** colorType → 每像素通道数。 */
const CHANNEL_COUNT = { 0: 1, 2: 3, 4: 2, 6: 4 }

/** colorType 的文字说明。 */
const COLOR_TYPE_LABELS = {
  0: '灰度（grayscale）',
  2: '真彩色 RGB',
  3: '索引色（palette，本工具不支持 LSB）',
  4: '灰度 + Alpha',
  6: 'RGBA（真彩 + Alpha）',
}

/** 关键 chunk 的用途说明。 */
const CHUNK_LABELS = {
  IHDR: '图像头（宽高/位深/色型）',
  PLTE: '调色板',
  IDAT: '图像数据（zlib 压缩后的扫描线）',
  IEND: '图像结束',
  tEXt: '未压缩文本',
  zTXt: '压缩文本',
  iTXt: '国际化文本（可压缩）',
  tRNS: '透明色 / Alpha 表',
  gAMA: 'Gamma',
  cHRM: '色度坐标',
  sRGB: 'sRGB 颜色空间',
  iCCP: 'ICC 配置文件',
  pHYs: '物理像素尺寸',
  bKGD: '背景色',
  tIME: '最后修改时间',
  sBIT: '有效位深',
  hIST: '调色板直方图',
  eXIf: 'EXIF 元数据',
}

/** CRC-32（PNG 使用标准反射多项式 0xEDB88320）。 */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n += 1) {
    let value = n
    for (let k = 0; k < 8; k += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
    table[n] = value >>> 0
  }
  return table
})()

/**
 * 计算 CRC-32（PNG chunk 校验用）。
 * @param {Uint8Array} bytes
 * @returns {number} 无符号 32 位整数
 */
export function crc32(bytes) {
  let crc = 0xffffffff
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

function readU32(bytes, at) {
  return ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0
}

function latin1(bytes) {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('latin1')
}

/**
 * 解析 PNG 的 chunk 序列（不 inflate，纯结构层）。
 * 结构损坏时返回 `{ ok: false, error }`，不抛异常。
 * @param {Uint8Array} bytes
 */
export function parsePngChunks(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 8) {
    return { ok: false, error: '文件不足 8 字节，不可能是 PNG。' }
  }
  for (let i = 0; i < 8; i += 1) {
    if (bytes[i] !== PNG_SIGNATURE[i]) {
      return { ok: false, error: 'PNG 签名不匹配：这不是 PNG 文件（或文件头已损坏）。' }
    }
  }
  const chunks = []
  let ihdr
  let offset = 8
  let iendEnd
  while (offset + 8 <= bytes.length) {
    const length = readU32(bytes, offset)
    const type = latin1(bytes.subarray(offset + 4, offset + 8))
    const dataStart = offset + 8
    const dataEnd = dataStart + length
    const crcEnd = dataEnd + 4
    if (crcEnd > bytes.length) {
      return {
        ok: false,
        chunks,
        ihdr,
        error: `chunk \`${type}\` 声明长度 ${length} 超出文件末尾（文件被截断）。`,
      }
    }
    const data = bytes.subarray(dataStart, dataEnd)
    const storedCrc = readU32(bytes, dataEnd)
    const computedCrc = crc32(bytes.subarray(offset + 4, dataEnd))
    chunks.push({ offset, length, type, data, storedCrc, computedCrc, crcOk: storedCrc === computedCrc })
    if (type === 'IHDR' && ihdr === undefined && data.length >= 13) {
      ihdr = {
        width: readU32(data, 0),
        height: readU32(data, 4),
        bitDepth: data[8],
        colorType: data[9],
        compression: data[10],
        filter: data[11],
        interlace: data[12],
      }
    }
    offset = crcEnd
    if (type === 'IEND') {
      iendEnd = crcEnd
      break
    }
  }
  return { ok: true, chunks, ihdr, iendEnd, truncated: iendEnd === undefined }
}

/** PNG Paeth 预测器。 */
function paethPredictor(left, up, upLeft) {
  const estimate = left + up - upLeft
  const distLeft = Math.abs(estimate - left)
  const distUp = Math.abs(estimate - up)
  const distUpLeft = Math.abs(estimate - upLeft)
  if (distLeft <= distUp && distLeft <= distUpLeft) return left
  if (distUp <= distUpLeft) return up
  return upLeft
}

/**
 * 解压 IDAT 并按 PNG 过滤器(0-4)逐行反过滤，得到原始像素字节。
 * `pixels` 是去掉 filter 字节后的连续像素数据，长度 = 宽 × 高 × bpp。
 * @param {Uint8Array} bytes PNG 文件字节
 */
export function decodePngPixels(bytes) {
  const parsed = parsePngChunks(bytes)
  if (!parsed.ok) return { ok: false, error: parsed.error }
  const ihdr = parsed.ihdr
  if (ihdr === undefined) return { ok: false, error: 'PNG 缺少 IHDR，无法解码像素。' }
  if (ihdr.bitDepth !== 8) {
    return { ok: false, error: `仅支持 8-bit PNG；当前 bitDepth=${ihdr.bitDepth}（1/2/4/16-bit 需要按位/采样解包，暂不支持）。` }
  }
  if (ihdr.interlace !== 0) {
    return { ok: false, error: '仅支持非隔行 PNG；当前 interlace=1（Adam7），需要先解隔行，暂不支持。' }
  }
  if (ihdr.colorType === 3) {
    return { ok: false, error: '索引色（palette，colorType=3）PNG 暂不支持：像素是调色板索引而非颜色值。' }
  }
  const channels = CHANNEL_COUNT[ihdr.colorType]
  if (channels === undefined) return { ok: false, error: `未知 PNG colorType=${ihdr.colorType}。` }
  if (!Number.isSafeInteger(ihdr.width) || !Number.isSafeInteger(ihdr.height) || ihdr.width <= 0 || ihdr.height <= 0) {
    return { ok: false, error: `IHDR 尺寸非法：${ihdr.width} × ${ihdr.height}。` }
  }
  const idatChunks = parsed.chunks.filter((chunk) => chunk.type === 'IDAT')
  if (idatChunks.length === 0) return { ok: false, error: 'PNG 没有 IDAT 数据块，无法解码像素。' }
  const idat = Buffer.concat(idatChunks.map((chunk) => Buffer.from(chunk.data)))

  const rowBytes = ihdr.width * channels
  const stride = rowBytes + 1
  const expected = ihdr.height * stride
  if (!Number.isSafeInteger(expected) || expected > 512 * 1024 * 1024) {
    return { ok: false, error: `解压后数据量过大（${ihdr.width} × ${ihdr.height} × ${channels} 通道），拒绝处理。` }
  }

  let raw
  try {
    raw = new Uint8Array(zlib.inflateSync(idat, { maxOutputLength: expected }))
  } catch (error) {
    return { ok: false, error: `IDAT 解压失败：${error?.code ?? ''} ${error?.message ?? String(error)}` }
  }
  if (raw.length < expected) {
    return { ok: false, error: `IDAT 解压数据不足：期望 ${expected} 字节，实际 ${raw.length} 字节（文件可能被截断）。` }
  }

  const pixels = new Uint8Array(rowBytes * ihdr.height)
  let previous = null
  let rawOffset = 0
  for (let row = 0; row < ihdr.height; row += 1) {
    const filterType = raw[rawOffset]
    rawOffset += 1
    if (filterType > 4) {
      return { ok: false, error: `第 ${row} 行的 PNG 过滤器值非法：${filterType}（合法值 0-4）。` }
    }
    const rowStart = rawOffset
    rawOffset += rowBytes
    const current = new Uint8Array(rowBytes)
    for (let i = 0; i < rowBytes; i += 1) {
      const filtered = raw[rowStart + i]
      const left = i >= channels ? current[i - channels] : 0
      const up = previous === null ? 0 : previous[i]
      const upLeft = previous !== null && i >= channels ? previous[i - channels] : 0
      let value
      switch (filterType) {
        case 0:
          value = filtered
          break
        case 1:
          value = filtered + left
          break
        case 2:
          value = filtered + up
          break
        case 3:
          value = filtered + ((left + up) >> 1)
          break
        default:
          value = filtered + paethPredictor(left, up, upLeft)
          break
      }
      current[i] = value & 0xff
    }
    pixels.set(current, row * rowBytes)
    previous = current
  }
  return { ok: true, ihdr, width: ihdr.width, height: ihdr.height, channels, bpp: channels, pixels, parsed }
}

/**
 * 把 `channel` 选项换算成「每像素参与 LSB 的通道下标」。
 * 语义（贯穿提取与测试用的写入函数）：
 *   - rgb/rgba/all：按 R→G→B→A 顺序，取图像实际存在的通道；
 *   - r/g/b：取对应颜色通道；灰度图没有独立 R/G/B，统一映射到灰度通道；
 *   - a：仅灰度+Alpha / RGBA 图像有，返回错误说明。
 * @param {number} colorType PNG colorType
 * @param {'rgba'|'rgb'|'r'|'g'|'b'|'a'|'all'} channel
 */
export function channelIndexesFor(colorType, channel) {
  const isGray = colorType === 0 || colorType === 4
  const hasAlpha = colorType === 4 || colorType === 6
  const key = ['rgba', 'rgb', 'r', 'g', 'b', 'a', 'all'].includes(channel) ? channel : 'rgba'
  let indexes
  switch (key) {
    case 'rgba':
    case 'all':
      indexes = colorType === 0 ? [0] : colorType === 2 ? [0, 1, 2] : colorType === 4 ? [0, 1] : [0, 1, 2, 3]
      break
    case 'rgb':
      indexes = colorType === 6 ? [0, 1, 2] : colorType === 4 ? [0] : [0, 1, 2]
      break
    case 'r':
      indexes = [0]
      break
    case 'g':
      indexes = isGray ? [0] : [1]
      break
    case 'b':
      indexes = isGray ? [0] : [2]
      break
    default: // a
      if (!hasAlpha) {
        return { error: `该 PNG colorType=${colorType} 没有 Alpha 通道，无法使用 channel=a；可选 rgba/rgb/all/r。` }
      }
      indexes = [colorType === 4 ? 1 : 3]
      break
  }
  const label = key === 'all' ? 'all（等同 rgba：取全部通道）' : key
  return { indexes, label }
}

/**
 * 从像素字节中按位提取 LSB，按 MSB-first 组装成字节。
 * @param {Uint8Array} pixels 解码后的像素字节
 * @param {number} bpp 每像素字节数
 * @param {number[]} channelIndexes 参与提取的通道下标
 * @param {number} bit 取第几位（0=最低位）
 * @param {number} maxBytes 最多提取多少字节
 */
export function extractLsbBytes(pixels, bpp, channelIndexes, bit, maxBytes) {
  const pixelCount = Math.floor(pixels.length / bpp)
  const capacity = pixelCount * channelIndexes.length
  const maxOut = Math.min(maxBytes, Math.floor(capacity / 8))
  if (maxOut <= 0) return new Uint8Array(0)
  const out = new Uint8Array(maxOut)
  let bitCount = 0
  let current = 0
  let outIndex = 0
  outer: for (let pixel = 0; pixel < pixels.length; pixel += bpp) {
    for (const channel of channelIndexes) {
      current = (current << 1) | ((pixels[pixel + channel] >> bit) & 1)
      bitCount += 1
      if (bitCount === 8) {
        out[outIndex] = current
        outIndex += 1
        bitCount = 0
        current = 0
        if (outIndex >= maxOut) break outer
      }
    }
  }
  return out
}

/**
 * 把载荷按同一套语义写进 LSB（测试与被解题脚本复用）。
 * 不修改入参，返回写入后的像素副本。
 * @param {Uint8Array} pixels
 * @param {number} bpp
 * @param {number[]} channelIndexes
 * @param {number} bit
 * @param {Uint8Array | readonly number[]} payload
 */
export function embedLsbBytes(pixels, bpp, channelIndexes, bit, payload) {
  const out = Uint8Array.from(pixels)
  const bytes = payload instanceof Uint8Array ? payload : Uint8Array.from(payload)
  const mask = ~(1 << bit) & 0xff
  let bitPosition = 0
  outer: for (let pixel = 0; pixel < out.length; pixel += bpp) {
    for (const channel of channelIndexes) {
      const byteIndex = bitPosition >> 3
      if (byteIndex >= bytes.length) break outer
      const payloadBit = (bytes[byteIndex] >> (7 - (bitPosition & 7))) & 1
      out[pixel + channel] = (out[pixel + channel] & mask) | (payloadBit << bit)
      bitPosition += 1
    }
  }
  return out
}

/** 可打印占比（0~1）。 */
function printableRatio(bytes) {
  if (bytes.length === 0) return 0
  let printable = 0
  for (const byte of bytes) {
    if (byte === 0x09 || byte === 0x0a || byte === 0x0d || (byte >= 0x20 && byte <= 0x7e)) printable += 1
  }
  return printable / bytes.length
}

/**
 * 常见的隐写载荷头识别。
 * @param {Uint8Array} bytes 提取出的字节
 * @returns {undefined | {kind: string, label: string}}
 */
export function detectPayload(bytes) {
  const head = bytes.subarray(0, Math.min(bytes.length, 64))
  const buffer = Buffer.from(head.buffer, head.byteOffset, head.byteLength)
  const hasPrefix = (prefix) => buffer.length >= prefix.length && buffer.subarray(0, prefix.length).equals(Buffer.from(prefix))
  if (hasPrefix([0x50, 0x4b, 0x03, 0x04])) return { kind: 'zip', label: 'ZIP 压缩包（`PK\\x03\\x04`）' }
  if (hasPrefix([0x1f, 0x8b])) return { kind: 'gzip', label: 'gzip 压缩流（`\\x1f\\x8b`）' }
  if (hasPrefix([0x89, 0x50, 0x4e, 0x47])) return { kind: 'png', label: 'PNG 图片（`\\x89PNG`）' }
  if (hasPrefix([0x25, 0x50, 0x44, 0x46])) return { kind: 'pdf', label: 'PDF 文档（`%PDF`）' }
  if (hasPrefix([0x52, 0x61, 0x72, 0x21])) return { kind: 'rar', label: 'RAR 压缩包（`Rar!`）' }
  const text = buffer.toString('latin1')
  if (/(?:flag|ctf|key)\s*\{/i.test(text)) return { kind: 'flag', label: 'flag 文本（形如 `flag{...}`）' }
  if (/^\s*[[{]/.test(text) && printableRatio(head) > 0.9) return { kind: 'json', label: 'JSON / 结构化文本' }
  return undefined
}

/** 逐个检查常见载荷签名，供报告展示「查过什么」。 */
function payloadSignatures(bytes) {
  const head = bytes.subarray(0, Math.min(bytes.length, 64))
  const buffer = Buffer.from(head.buffer, head.byteOffset, head.byteLength)
  const hasPrefix = (prefix) => buffer.length >= prefix.length && buffer.subarray(0, prefix.length).equals(Buffer.from(prefix))
  const text = buffer.toString('latin1')
  return [
    ['ZIP 头 `PK\\x03\\x04`', hasPrefix([0x50, 0x4b, 0x03, 0x04])],
    ['gzip 头 `1F 8B`', hasPrefix([0x1f, 0x8b])],
    ['PNG 签名 `89 50 4E 47`', hasPrefix([0x89, 0x50, 0x4e, 0x47])],
    ['PDF 头 `%PDF`', hasPrefix([0x25, 0x50, 0x44, 0x46])],
    ['RAR 头 `Rar!`', hasPrefix([0x52, 0x61, 0x72, 0x21])],
    ['7-Zip 头 `37 7A BC AF`', hasPrefix([0x37, 0x7a, 0xbc, 0xaf])],
    ['flag 文本 `flag{...}`', /(?:flag|ctf|key)\s*\{/i.test(text)],
  ]
}

/** 解析 tEXt / zTXt / iTXt 的内容。 */
function parseTextChunk(chunk) {
  const buffer = Buffer.from(chunk.data.buffer, chunk.data.byteOffset, chunk.data.byteLength)
  const zero = buffer.indexOf(0)
  if (zero < 0) return { keyword: '', text: '（格式异常：缺少关键字分隔符）' }
  const keyword = buffer.subarray(0, zero).toString('latin1')
  try {
    if (chunk.type === 'tEXt') {
      return { keyword, text: buffer.subarray(zero + 1).toString('latin1') }
    }
    if (chunk.type === 'zTXt') {
      const compressed = buffer.subarray(zero + 2) // 跳过 keyword\0 + compressionMethod(1)
      const inflated = zlib.inflateSync(compressed)
      return { keyword, text: inflated.toString('utf8') }
    }
    // iTXt: keyword\0 compFlag(1) compMethod(1) languageTag\0 translatedKeyword\0 text
    let cursor = zero + 1
    const compressedFlag = buffer[cursor]
    cursor += 2 // compFlag + compMethod
    const languageEnd = buffer.indexOf(0, cursor)
    if (languageEnd < 0) return { keyword, text: '（格式异常：缺少 language tag）' }
    cursor = languageEnd + 1
    const translatedEnd = buffer.indexOf(0, cursor)
    if (translatedEnd < 0) return { keyword, text: '（格式异常：缺少 translated keyword）' }
    cursor = translatedEnd + 1
    const raw = buffer.subarray(cursor)
    const text = compressedFlag === 1 ? zlib.inflateSync(raw).toString('utf8') : raw.toString('utf8')
    return { keyword, text }
  } catch (error) {
    return { keyword, text: `（解压失败：${error?.message ?? String(error)}）` }
  }
}

/** 渲染 PNG 结构分析（action=info）。 */
function renderInfo(bytes, target) {
  const parsed = parsePngChunks(bytes)
  if (!parsed.ok) {
    const lines = [
      '## 结论',
      `无法解析为 PNG：${parsed.error}`,
      '',
      '## 说明',
      '- `ctf_stego` 的 `info`/`lsb` 只处理 PNG；其他格式请先用 `ctf_file` 确认真实类型。',
      `- 文件路径：\`${target}\`，共 ${bytes.length} 字节。`,
    ]
    return lines.join('\n')
  }
  const ihdr = parsed.ihdr
  const supportReason = (() => {
    if (ihdr === undefined) return '缺少 IHDR，无法判断。'
    if (ihdr.bitDepth !== 8) return `bitDepth=${ihdr.bitDepth}，仅支持 8-bit。`
    if (ihdr.interlace !== 0) return 'Adam7 隔行，暂不支持。'
    if (ihdr.colorType === 3) return '索引色（palette），暂不支持。'
    if (CHANNEL_COUNT[ihdr.colorType] === undefined) return `未知 colorType=${ihdr.colorType}。`
    return undefined
  })()

  const lines = []
  lines.push('## 结论')
  if (ihdr === undefined) {
    lines.push('PNG 签名有效，但缺少 IHDR，文件结构不完整。')
  } else {
    lines.push(`PNG 签名有效；图像 ${ihdr.width} × ${ihdr.height}，${COLOR_TYPE_LABELS[ihdr.colorType] ?? `colorType=${ihdr.colorType}`}，bitDepth=${ihdr.bitDepth}，${ihdr.interlace === 0 ? '非隔行' : 'Adam7 隔行'}。`)
    lines.push(supportReason === undefined ? '当前图像满足 LSB 提取条件（8-bit、非隔行、直接色型），可以直接 `action=lsb`。' : `LSB 提取受限：${supportReason}`)
  }
  const badCrc = parsed.chunks.filter((chunk) => !chunk.crcOk)
  lines.push(`共 ${parsed.chunks.length} 个 chunk，CRC ${badCrc.length === 0 ? '全部合法' : `有 ${badCrc.length} 个不匹配`}${parsed.truncated ? '，且未找到 IEND（文件可能被截断）' : ''}。`)
  lines.push('')

  lines.push('## PNG 签名')
  lines.push(`文件头 8 字节：\`${bytesToHex(bytes.subarray(0, 8), { upper: true, group: 8 })}\`（PNG 签名，校验通过）。`)
  lines.push('')

  lines.push('## Chunk 表')
  const chunkRows = parsed.chunks.map((chunk, index) => [
    String(index + 1),
    `0x${chunk.offset.toString(16)}`,
    chunk.type,
    String(chunk.length),
    chunk.crcOk ? '合法' : '不匹配',
    CHUNK_LABELS[chunk.type] ?? '',
  ])
  lines.push(formatRows(chunkRows, ['#', '偏移', '类型', '长度', 'CRC', '说明']))
  if (parsed.chunks.length > 40) lines.push(`\n（共 ${parsed.chunks.length} 个 chunk，上表已完整列出。）`)
  lines.push('')

  lines.push('## IHDR 拆解')
  if (ihdr === undefined) {
    lines.push('缺少 IHDR。')
  } else {
    const rows = [
      ['宽 × 高', `${ihdr.width} × ${ihdr.height}`],
      ['bitDepth', String(ihdr.bitDepth)],
      ['colorType', `${ihdr.colorType} — ${COLOR_TYPE_LABELS[ihdr.colorType] ?? '未知'}`],
      ['compression', String(ihdr.compression)],
      ['filter', String(ihdr.filter)],
      ['interlace', ihdr.interlace === 0 ? '0 — 非隔行' : `${ihdr.interlace} — Adam7 隔行`],
      ['每像素通道数（bpp）', String(CHANNEL_COUNT[ihdr.colorType] ?? '?')],
      ['LSB 支持性', supportReason === undefined ? '支持' : `不支持：${supportReason}`],
    ]
    lines.push(formatRows(rows, ['字段', '值']))
  }
  lines.push('')

  lines.push('## 文本 Chunk（tEXt / zTXt / iTXt）')
  const textChunks = parsed.chunks.filter((chunk) => ['tEXt', 'zTXt', 'iTXt'].includes(chunk.type))
  if (textChunks.length === 0) {
    lines.push('没有 tEXt / zTXt / iTXt 文本块（flag 可能不在这里）。')
  } else {
    for (const chunk of textChunks) {
      const parsedText = parseTextChunk(chunk)
      lines.push(`- \`${chunk.type}\` 关键字 \`${parsedText.keyword || '(空)'}\`：${preview(parsedText.text, 240)}`)
    }
  }
  lines.push('')

  lines.push('## 其他关键 Chunk')
  const interesting = parsed.chunks.filter((chunk) => ['PLTE', 'tRNS', 'gAMA', 'cHRM', 'sRGB', 'iCCP', 'pHYs', 'bKGD', 'tIME', 'sBIT', 'hIST', 'eXIf'].includes(chunk.type))
  if (interesting.length === 0) {
    lines.push('没有 PLTE / tRNS / tIME / eXIf 等附加信息块。')
  } else {
    lines.push(formatRows(interesting.map((chunk) => [chunk.type, String(chunk.length), CHUNK_LABELS[chunk.type] ?? '']), ['类型', '长度', '说明']))
  }
  lines.push('')

  lines.push('## IEND 之后的尾随字节')
  if (parsed.iendEnd === undefined) {
    lines.push('未找到 IEND，无法定位尾随字节（文件可能被截断）。')
  } else if (parsed.iendEnd >= bytes.length) {
    lines.push('IEND 之后没有尾随字节。')
  } else {
    const trailing = bytes.subarray(parsed.iendEnd)
    lines.push(`发现 **${trailing.length}** 字节尾随数据（IEND 结束于偏移 0x${parsed.iendEnd.toString(16)}）：`)
    lines.push('')
    lines.push(`\`${escapeNonPrintable(trailing.subarray(0, 256), 400)}\``)
  }
  lines.push('')

  lines.push('## LSB 预览（默认 rgba / bit 0 / text，前 128 字节）')
  const decoded = decodePngPixels(bytes)
  if (!decoded.ok) {
    lines.push(`跳过：${decoded.error}`)
  } else {
    const channel = channelIndexesFor(decoded.ihdr.colorType, 'rgba')
    const payload = extractLsbBytes(decoded.pixels, decoded.bpp, channel.indexes, 0, 128)
    const ratio = printableRatio(payload)
    lines.push(`提取 ${payload.length} 字节，可打印占比 ${Math.round(ratio * 100)}%。`)
    lines.push('')
    lines.push(`\`${escapeNonPrintable(payload.subarray(0, 128), 256)}\``)
    if (ratio < 0.2) lines.push('\n可打印占比很低：可能图像是干净的，或隐写使用了其他通道/位（用 `action=lsb` 换参数再试）。')
  }
  lines.push('')
  lines.push('## 下一步')
  lines.push('- 逐通道/逐位扫一遍：`action=lsb` 配合 `channel=all|rgb|r|g|b|a` 与 `bit=0..7`。')
  lines.push('- 看到像压缩包的载荷时，先把提取结果按 `format=hex` 拿到 hex，再落盘交给 `ctf_file`。')
  return lines.join('\n')
}

/** 渲染 LSB 提取（action=lsb）。 */
function renderLsb(bytes, target, options) {
  const { channel, bit, format, maxBytes } = options
  const decoded = decodePngPixels(bytes)
  if (!decoded.ok) {
    return [
      '## 结论',
      `无法执行 LSB 提取：${decoded.error}`,
      '',
      '## 说明',
      '- LSB 提取只支持 8-bit、非隔行、colorType 0/2/4/6（灰度 / RGB / 灰度+Alpha / RGBA）的 PNG。',
      '- 索引色（palette，colorType=3）需要先转成真彩色：`ffmpeg -i in.png -pix_fmt rgba out.png` 或 Python PIL `convert("RGBA")`。',
      '- 先用 `action=info` 看 chunk 表和 IHDR，确认文件本身没被截断。',
      `- 文件路径：\`${target}\`。`,
    ].join('\n')
  }
  const channelSelection = channelIndexesFor(decoded.ihdr.colorType, channel)
  if (channelSelection.error !== undefined) {
    return `## 结论\n通道选择无效：${channelSelection.error}\n\n请改 \`channel=all\` 或 \`channel=rgb\`。`
  }
  const payload = extractLsbBytes(decoded.pixels, decoded.bpp, channelSelection.indexes, bit, maxBytes)
  const ratio = printableRatio(payload)
  const signature = detectPayload(payload)
  const colorLabel = COLOR_TYPE_LABELS[decoded.ihdr.colorType] ?? `colorType=${decoded.ihdr.colorType}`

  const lines = []
  lines.push('## 结论')
  if (payload.length === 0) {
    lines.push('提取到 0 字节：图像像素不足以容纳请求的字节数（或参数组合不匹配）。')
  } else {
    lines.push(`从 \`${target}\`（${decoded.width} × ${decoded.height}，${colorLabel}，8-bit 非隔行）按 \`channel=${channelSelection.label}\` / \`bit=${bit}\` 提取到 **${payload.length}** 字节。`)
    lines.push(`可打印占比 ${Math.round(ratio * 100)}%。`)
    if (signature !== undefined) lines.push(`\n**疑似内嵌 ${signature.label}** — 强烈建议把载荷落盘后用 \`ctf_file\` 继续分析。`)
  }
  lines.push('')

  lines.push('## 提取结果')
  let trailingZeros = 0
  let trimmed = payload
  while (trimmed.length > 0 && trimmed[trimmed.length - 1] === 0) {
    trailingZeros += 1
    trimmed = trimmed.subarray(0, trimmed.length - 1)
  }
  if (format === 'hex') {
    const displayCap = 8192
    const shown = payload.subarray(0, Math.min(payload.length, displayCap))
    lines.push('```hex')
    lines.push(bytesToHex(shown, { group: 16 }))
    lines.push('```')
    if (payload.length > displayCap) lines.push(`\n（只显示前 ${displayCap} 字节，共 ${payload.length} 字节；需要完整载荷请用 \`format=hex\` 分段提取或直接落盘。）`)
  } else if (payload.length === 0) {
    lines.push('（空）')
  } else {
    const text = ratio >= 0.85 ? decodeUtf8(trimmed) : escapeNonPrintable(trimmed, 8192)
    lines.push('```text')
    lines.push(text)
    lines.push('```')
    if (ratio < 0.85) lines.push('\n可打印占比不高，上面把不可打印字节转成了 `\\xNN`；换通道/位组合再试，或用 `format=hex` 看原始字节。')
  }
  lines.push('')

  lines.push('## 字节概览')
  const overview = [
    ['提取长度', `${payload.length} 字节`],
    ['请求上限 maxBytes', String(maxBytes)],
    ['通道', channelSelection.label],
    ['bit（0=LSB）', String(bit)],
    ['可打印占比', `${Math.round(ratio * 100)}%`],
    ['首 32 字节 hex', payload.length > 0 ? bytesToHex(payload.subarray(0, 32)) : '（空）'],
    ['尾部 NUL 填充', `${trailingZeros} 字节${trailingZeros > 0 ? '（展示时已去掉）' : ''}`],
  ]
  lines.push(formatRows(overview, ['项目', '值']))
  lines.push('')

  lines.push('## 载荷签名检查')
  const checks = payloadSignatures(payload)
  lines.push(formatRows(checks.map(([name, hit]) => [hit ? '✅ 命中' : '—', name]), ['结果', '签名']))
  lines.push('')

  lines.push('## 说明与下一步')
  lines.push('- 位序约定：同一通道内按 MSB-first 把 LSB 拼成字节（先出现的位是高 bit），与常见 stegsolve / zsteg 默认一致。')
  lines.push('- `channel` 语义：`rgba/all` 取图像全部通道按 R→G→B→A 顺序；`rgb` 只取颜色通道；`r/g/b/a` 单通道（灰度图 R/G/B 映射到灰度通道）。')
  lines.push('- 命中压缩包/图片签名时，建议先用 `format=hex` 取 hex，解码落盘为文件，再用 `ctf_file` 做二次取证。')
  lines.push('- 如果所有通道/位都试过仍是噪声，考虑调色板排序、DCT（JPEG）、音频频谱或其他隐写载体。')
  return lines.join('\n')
}

/**
 * 构造 `ctf_stego` 工具定义。
 * @param {any} ctx 注册上下文（用于解析会话工作目录）
 */
export function createStegoTool(ctx) {
  return {
    name: 'ctf_stego',
    description:
      'PNG steganography analysis: dump the chunk table with CRC status, IHDR fields, tEXt/zTXt/iTXt contents and bytes after IEND (action=info); or extract LSB payloads from 8-bit non-interlaced PNG (grayscale/RGB/gray+alpha/RGBA) after inflating IDAT and reversing PNG row filters 0-4, with channel/bit/format options, printable ratio, first-32-byte hex and automatic payload signature detection (ZIP/gzip/PNG/PDF/flag text). Unsupported PNG variants return a readable explanation instead of throwing.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: {
          type: 'string',
          description: 'Required. PNG file to analyze; relative paths resolve against the session working directory, `~` is expanded.',
        },
        action: {
          type: 'string',
          enum: ['info', 'lsb'],
          description: 'info (default): structure/chunk/text/trailing-byte report. lsb: extract LSB payload.',
        },
        channel: {
          type: 'string',
          enum: ['rgba', 'rgb', 'r', 'g', 'b', 'a', 'all'],
          description: 'Channels contributing one LSB each, ordered R,G,B,A. rgba/all = all channels present (default), rgb = color channels only, r/g/b/a = single channel.',
        },
        bit: {
          type: 'integer',
          description: 'Which bit to read per channel byte, 0 = least significant (0-7, default 0).',
        },
        format: {
          type: 'string',
          enum: ['text', 'hex'],
          description: 'Render the extracted payload as text (default) or hex.',
        },
        maxBytes: {
          type: 'integer',
          description: 'Maximum payload bytes to extract (64-65536, default 4096).',
        },
      },
      required: ['path'],
    },
    output: textOutput('CTF stego'),
    async execute(args, exec) {
      const cwd = resolveSessionCwd(ctx, exec)
      const rawPath = typeof args?.path === 'string' ? args.path : ''
      if (rawPath.trim().length === 0) {
        return { text: '## 结论\n缺少 `path`：请给出要分析的 PNG 路径（相对路径基于会话工作目录）。' }
      }
      const target = resolveUserPath(rawPath, cwd)
      const read = await readBytesSafe(target)
      if (!read.ok) {
        return { text: `## 结论\n无法读取文件 \`${target}\`\n\n原因：${read.error}\n\n请确认路径正确、文件存在且有读权限。` }
      }
      const bytes = read.bytes
      if (bytes.length === 0) return { text: `## 结论\n文件 \`${target}\` 是空文件（0 字节），没有可分析的内容。` }
      const action = ['info', 'lsb'].includes(args?.action) ? args.action : 'info'
      const channel = ['rgba', 'rgb', 'r', 'g', 'b', 'a', 'all'].includes(args?.channel) ? args.channel : 'rgba'
      const bit = clampInt(args?.bit, 0, 7, 0)
      const format = args?.format === 'hex' ? 'hex' : 'text'
      const maxBytes = clampInt(args?.maxBytes, 64, 65536, 4096)
      try {
        if (action === 'lsb') return { text: renderLsb(bytes, target, { channel, bit, format, maxBytes }) }
        return { text: renderInfo(bytes, target) }
      } catch (error) {
        return {
          text: `## 结论\n分析 \`${target}\` 时失败，但文件已成功读取。\n\n异常：${error?.code ?? 'UNKNOWN'}: ${error?.message ?? String(error)}\n\n这通常是本工具的解析缺陷；可以先用 \`ctf_file\` 查看文件真实类型。`,
        }
      }
    },
  }
}
