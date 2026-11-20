/**
 * 取证与隐写模块的回归测试。
 *
 * 测试素材全部现场用代码构造：最小 PNG 编码器（IHDR/IDAT/IEND + 逐行过滤）、
 * 带尾部附加数据的 PNG、扩展名不符的样本、内嵌 PNG 的 PDF 容器、带 Base64 flag 的文本。
 * 这样测试不依赖仓库里的二进制素材，也能精确控制「过滤器类型」这类容易翻车的细节。
 *
 * 临时文件放在系统临时目录，测试结束统一清理，不污染工作区。
 */
import test, { after, before } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { deflateSync } from 'node:zlib'

import { COMMON_PASSWORDS, computeHash, createHashTool, identifyHash } from '../ctf/hash.js'
import { createFileTool } from '../ctf/forensics.js'
import {
  channelIndexesFor,
  crc32,
  createStegoTool,
  decodePngPixels,
  detectPayload,
  embedLsbBytes,
  extractLsbBytes,
} from '../ctf/stego.js'

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
const CHANNELS = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }

/** 组装一个 PNG chunk（长度 + 类型 + 数据 + CRC）。 */
function pngChunk(type, data) {
  const length = Buffer.alloc(4)
  length.writeUInt32BE(data.length)
  const typeBytes = Buffer.from(type, 'latin1')
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])))
  return Buffer.concat([length, typeBytes, data, crc])
}

/** PNG Paeth 预测器（编码侧用，与解码侧同一算法但独立实现，避免互相掩盖错误）。 */
function paeth(left, up, upLeft) {
  const estimate = left + up - upLeft
  const distLeft = Math.abs(estimate - left)
  const distUp = Math.abs(estimate - up)
  const distUpLeft = Math.abs(estimate - upLeft)
  if (distLeft <= distUp && distLeft <= distUpLeft) return left
  if (distUp <= distUpLeft) return up
  return upLeft
}

/** 按 PNG 过滤器类型对一行像素做过滤（编码方向）。 */
function filterRow(filterType, row, previous, bpp) {
  const out = Buffer.alloc(row.length)
  for (let i = 0; i < row.length; i += 1) {
    const left = i >= bpp ? row[i - bpp] : 0
    const up = previous === null ? 0 : previous[i]
    const upLeft = previous !== null && i >= bpp ? previous[i - bpp] : 0
    let predictor
    switch (filterType) {
      case 0: predictor = 0; break
      case 1: predictor = left; break
      case 2: predictor = up; break
      case 3: predictor = (left + up) >> 1; break
      default: predictor = paeth(left, up, upLeft); break
    }
    out[i] = (row[i] - predictor) & 0xff
  }
  return out
}

/**
 * 最小 PNG 编码器。
 * @param {{width: number, height: number, colorType: number, pixels: Uint8Array, filters?: number[], extraChunks?: Buffer[]}} options
 */
function encodePng(options) {
  const { width, height, colorType, pixels, filters = [0], extraChunks = [] } = options
  const channels = CHANNELS[colorType]
  assert.ok(channels !== undefined, `unsupported test colorType ${colorType}`)
  const rowBytes = width * channels
  assert.equal(pixels.length, rowBytes * height, 'test pixels length mismatch')
  const raw = Buffer.alloc(height * (rowBytes + 1))
  let offset = 0
  let previous = null
  for (let row = 0; row < height; row += 1) {
    const filterType = filters[row % filters.length]
    raw[offset] = filterType
    offset += 1
    const rowPixels = pixels.subarray(row * rowBytes, (row + 1) * rowBytes)
    filterRow(filterType, rowPixels, previous, channels).copy(raw, offset)
    offset += rowBytes
    previous = rowPixels
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(width, 0)
  ihdr.writeUInt32BE(height, 4)
  ihdr[8] = 8 // bitDepth
  ihdr[9] = colorType
  ihdr[10] = 0 // compression
  ihdr[11] = 0 // filter method
  ihdr[12] = 0 // interlace: none
  return Buffer.concat([
    PNG_SIGNATURE,
    pngChunk('IHDR', ihdr),
    ...extraChunks,
    pngChunk('IDAT', deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ])
}

/** 可预测的伪随机像素，保证测试可复现。 */
function makePixels(length, seed = 1) {
  const pixels = new Uint8Array(length)
  let state = seed
  for (let i = 0; i < length; i += 1) {
    state = (state * 1103515245 + 12345) >>> 0
    pixels[i] = (state >>> 16) & 0xff
  }
  return pixels
}

const hashTool = createHashTool({})
const fileTool = createFileTool({})
const stegoTool = createStegoTool({})

let tmpDir
let fixtures = {}
let plainPng
let filteredPixels

before(async () => {
  tmpDir = await mkdtemp(path.join(os.tmpdir(), 'ctf-kit-forensics-'))

  // 1) 2x2 RGBA PNG（过滤器 0）
  const tinyPixels = Uint8Array.from([
    10, 20, 30, 255,
    40, 50, 60, 255,
    70, 80, 90, 255,
    100, 110, 120, 255,
  ])
  plainPng = encodePng({ width: 2, height: 2, colorType: 6, pixels: tinyPixels, filters: [0] })
  fixtures.plainPng = path.join(tmpDir, 'plain.png')
  await writeFile(fixtures.plainPng, plainPng)

  // 2) 8x8 RGBA PNG：逐行轮换 filter 0..4，覆盖全部反过滤分支
  filteredPixels = makePixels(8 * 8 * 4, 7)
  const filteredPng = encodePng({
    width: 8,
    height: 8,
    colorType: 6,
    pixels: filteredPixels,
    filters: [0, 1, 2, 3, 4],
  })
  fixtures.filteredPng = path.join(tmpDir, 'filtered.png')
  await writeFile(fixtures.filteredPng, filteredPng)

  // 3) LSB 往返样本：16x16 RGBA，写入一段文本后按 filter 0/4 编码
  const lsbPixels = makePixels(16 * 16 * 4, 11)
  const rgbaChannels = channelIndexesFor(6, 'rgba')
  assert.equal(rgbaChannels.error, undefined)
  const textPayload = Buffer.from('flag{lsb_roundtrip_ok}', 'utf8')
  const embeddedPixels = embedLsbBytes(lsbPixels, 4, rgbaChannels.indexes, 0, textPayload)
  fixtures.lsbRgba = path.join(tmpDir, 'lsb-rgba.png')
  await writeFile(fixtures.lsbRgba, encodePng({
    width: 16,
    height: 16,
    colorType: 6,
    pixels: embeddedPixels,
    filters: [0, 4],
  }))

  // 4) 单通道 R LSB 样本
  const rPixels = makePixels(16 * 16 * 4, 13)
  const rChannels = channelIndexesFor(6, 'r')
  const rPayload = Buffer.from('single-channel-secret', 'utf8')
  fixtures.lsbR = path.join(tmpDir, 'lsb-r.png')
  await writeFile(fixtures.lsbR, encodePng({
    width: 16,
    height: 16,
    colorType: 6,
    pixels: embedLsbBytes(rPixels, 4, rChannels.indexes, 0, rPayload),
    filters: [2],
  }))

  // 5) LSB 里塞 ZIP 头，验证载荷签名识别
  const zipPixels = makePixels(16 * 16 * 4, 17)
  const zipPayload = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from('zipdata-inside-lsb')])
  fixtures.lsbZip = path.join(tmpDir, 'lsb-zip.png')
  await writeFile(fixtures.lsbZip, encodePng({
    width: 16,
    height: 16,
    colorType: 6,
    pixels: embedLsbBytes(zipPixels, 4, rgbaChannels.indexes, 0, zipPayload),
    filters: [0],
  }))

  // 6) IEND 之后追加字符串的 PNG
  fixtures.tailPng = path.join(tmpDir, 'tail.png')
  await writeFile(fixtures.tailPng, Buffer.concat([
    plainPng,
    Buffer.from('\nflag{png_trailing_tail}\n', 'utf8'),
  ]))

  // 7) 扩展名骗人：PNG 内容 + .jpg 扩展名
  fixtures.wrongJpg = path.join(tmpDir, 'wrong.jpg')
  await writeFile(fixtures.wrongJpg, plainPng)

  // 8) 文本文件：藏一个 Base64 编码的 flag
  const hiddenText = 'flag{dummy_test_flag_2024} — base64 payload for ctf_file tests'
  const encoded = Buffer.from(hiddenText, 'utf8').toString('base64')
  fixtures.base64Text = path.join(tmpDir, 'b64.txt')
  await writeFile(fixtures.base64Text, `header line\n${encoded}\nfooter line\n`, 'utf8')

  // 9) PDF 容器里内嵌一张 PNG（用于 extractEmbedded）
  fixtures.outerPdf = path.join(tmpDir, 'outer.pdf')
  await writeFile(fixtures.outerPdf, Buffer.concat([
    Buffer.from('%PDF-1.4\n', 'latin1'),
    plainPng,
    Buffer.from('\n%%EOF\n', 'latin1'),
  ]))

  // 10) 索引色 PNG（colorType=3）：LSB 不支持的样本
  const palettePixels = Uint8Array.from([0, 1, 1, 0])
  const paletteChunk = pngChunk('PLTE', Buffer.from([0, 0, 0, 255, 255, 255]))
  fixtures.palettePng = path.join(tmpDir, 'palette.png')
  await writeFile(fixtures.palettePng, encodePng({
    width: 2,
    height: 2,
    colorType: 3,
    pixels: palettePixels,
    filters: [0],
    extraChunks: [paletteChunk],
  }))

  // 11) 非 PNG 文件
  fixtures.notPng = path.join(tmpDir, 'notes.txt')
  await writeFile(fixtures.notPng, 'this is definitely not a png\n', 'utf8')
})

after(async () => {
  if (typeof tmpDir === 'string') await rm(tmpDir, { recursive: true, force: true })
})

// ---------------------------------------------------------------------------
// ctf_hash
// ---------------------------------------------------------------------------

test('ctf_hash：工具契约（name / parameters 顶层键名）', () => {
  assert.equal(hashTool.name, 'ctf_hash')
  assert.deepEqual(
    Object.keys(hashTool.parameters.properties),
    ['action', 'value', 'algorithm', 'wordlist', 'dictionary'],
  )
  assert.deepEqual(hashTool.parameters.required, ['value'])
  assert.equal(typeof hashTool.execute, 'function')
})

test('ctf_hash：identify 把 32 位 hex 识别为 MD5，并给出 hashcat 模式号', async () => {
  const identification = identifyHash('5f4dcc3b5aa765d61d8327deb882cf99')
  assert.equal(identification.candidates[0].type, 'md5')
  assert.ok(identification.candidates.some((candidate) => candidate.type === 'ntlm'), '应当提示 NTLM 歧义')
  const result = await hashTool.execute({ action: 'identify', value: '5f4dcc3b5aa765d61d8327deb882cf99' })
  assert.match(result.text, /MD5/)
  assert.match(result.text, /-m 0/)
  assert.match(result.text, /NTLM/)
})

test('ctf_hash：crack 破解 MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99', async () => {
  const result = await hashTool.execute({ action: 'crack', value: '5f4dcc3b5aa765d61d8327deb882cf99' })
  assert.match(result.text, /命中/)
  assert.match(result.text, /password/)
  assert.match(result.text, /md5/i)
})

test('ctf_hash：crack 也使用内联 wordlist 命中自定义口令', async () => {
  const secret = 'ctf-inline-secret'
  const target = computeHash(secret, 'sha256')
  const result = await hashTool.execute({
    action: 'crack',
    value: target,
    algorithm: 'auto',
    dictionary: 'none',
    wordlist: ['wrong-one', secret],
  })
  assert.match(result.text, /命中/)
  assert.match(result.text, new RegExp(secret))
  assert.match(result.text, /sha256/i)
})

test('ctf_hash：96 位 hex 识别为 SHA-384，crack 明确说明本地不暴破并给 hashcat 模式', async () => {
  const identification = identifyHash('a'.repeat(96))
  assert.equal(identification.candidates[0].type, 'sha384')
  const result = await hashTool.execute({ action: 'crack', value: 'a'.repeat(96) })
  assert.match(result.text, /未执行暴力破解/)
  assert.match(result.text, /10800/)
  assert.match(result.text, /未尝试的格式/)
})

test('ctf_hash：compute 输出四种哈希', async () => {
  const result = await hashTool.execute({ action: 'compute', value: 'hello' })
  assert.match(result.text, /5d41402abc4b2a76b9719d911017c592/)
  assert.match(result.text, /aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d/)
  assert.match(result.text, /2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824/)
  assert.match(result.text, /9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043/)
  assert.equal(COMMON_PASSWORDS.length, 200)
  assert.ok(COMMON_PASSWORDS.includes('password'))
})

// ---------------------------------------------------------------------------
// ctf_file
// ---------------------------------------------------------------------------

test('ctf_file：工具契约（name / parameters 顶层键名）', () => {
  assert.equal(fileTool.name, 'ctf_file')
  assert.deepEqual(
    Object.keys(fileTool.parameters.properties),
    ['path', 'includeStrings', 'extractEmbedded', 'maxEmbedded', 'minStringLength'],
  )
  assert.deepEqual(fileTool.parameters.required, ['path'])
})

test('ctf_file：报出 PNG 类型、IEND 之后的附加数据与 flag 命中', async () => {
  const result = await fileTool.execute({ path: fixtures.tailPng })
  assert.match(result.text, /PNG/)
  assert.match(result.text, /尾部附加数据/)
  assert.match(result.text, /IEND/)
  assert.match(result.text, /flag\{png_trailing_tail\}/)
  assert.match(result.text, /## 基本信息/)
})

test('ctf_file：交叉校验发现扩展名与真实类型不一致', async () => {
  const result = await fileTool.execute({ path: fixtures.wrongJpg })
  assert.match(result.text, /PNG/)
  assert.match(result.text, /不一致/)
})

test('ctf_file：Base64 长块解码后能看到隐藏文本', async () => {
  const result = await fileTool.execute({ path: fixtures.base64Text })
  assert.match(result.text, /Base64/)
  assert.match(result.text, /flag\{dummy_test_flag_2024\}/)
})

test('ctf_file：extractEmbedded 把内嵌 PNG 落到 <basename>_extracted/', async () => {
  const result = await fileTool.execute({ path: fixtures.outerPdf, extractEmbedded: true, maxEmbedded: 8 })
  assert.match(result.text, /落盘结果/)
  const extractedDir = path.join(tmpDir, 'outer.pdf_extracted')
  const entries = await readdir(extractedDir)
  assert.ok(entries.length >= 2, `expected >=2 extracted objects, got ${entries.join(',')}`)
  const pngEntry = entries.find((entry) => entry.endsWith('.png'))
  assert.ok(pngEntry !== undefined, `expected a .png extraction, got ${entries.join(',')}`)
  const extracted = await readFile(path.join(extractedDir, pngEntry))
  assert.deepEqual(extracted, plainPng, 'extracted PNG bytes must equal the embedded PNG')
})

// ---------------------------------------------------------------------------
// ctf_stego
// ---------------------------------------------------------------------------

test('ctf_stego：工具契约（name / parameters 顶层键名）', () => {
  assert.equal(stegoTool.name, 'ctf_stego')
  assert.deepEqual(
    Object.keys(stegoTool.parameters.properties),
    ['path', 'action', 'channel', 'bit', 'format', 'maxBytes'],
  )
  assert.deepEqual(stegoTool.parameters.required, ['path'])
})

test('ctf_stego：info 列出 IHDR / chunk CRC / 尺寸', async () => {
  const result = await stegoTool.execute({ path: fixtures.plainPng, action: 'info' })
  assert.match(result.text, /## PNG 签名/)
  assert.match(result.text, /## Chunk 表/)
  assert.match(result.text, /IHDR/)
  assert.match(result.text, /合法/)
  assert.match(result.text, /2 × 2/)
  assert.match(result.text, /IEND 之后没有尾随字节/)
})

test('ctf_stego：info 能读出 tEXt 文本块', async () => {
  const textChunk = pngChunk('tEXt', Buffer.from('Comment\0flag{text_chunk_hint}', 'latin1'))
  const withText = encodePng({
    width: 2,
    height: 2,
    colorType: 6,
    pixels: makePixels(16, 3),
    filters: [0],
    extraChunks: [textChunk],
  })
  const target = path.join(tmpDir, 'text-chunk.png')
  await writeFile(target, withText)
  const result = await stegoTool.execute({ path: target, action: 'info' })
  assert.match(result.text, /tEXt/)
  assert.match(result.text, /flag\{text_chunk_hint\}/)
})

test('ctf_stego：info 能解压 zTXt 压缩文本块', async () => {
  const compressed = deflateSync(Buffer.from('flag{compressed_text_chunk}', 'latin1'))
  const ztextChunk = pngChunk('zTXt', Buffer.concat([
    Buffer.from('Comment\0', 'latin1'),
    Buffer.from([0]), // compression method: deflate
    compressed,
  ]))
  const target = path.join(tmpDir, 'ztext-chunk.png')
  await writeFile(target, encodePng({
    width: 2,
    height: 2,
    colorType: 6,
    pixels: makePixels(16, 5),
    filters: [0],
    extraChunks: [ztextChunk],
  }))
  const result = await stegoTool.execute({ path: target, action: 'info' })
  assert.match(result.text, /zTXt/)
  assert.match(result.text, /flag\{compressed_text_chunk\}/)
})

test('ctf_stego：decodePngPixels 逐行反过滤（filter 0-4）还原像素', async () => {
  const decoded = decodePngPixels(await readFile(fixtures.filteredPng))
  assert.equal(decoded.ok, true, decoded.error)
  assert.equal(decoded.width, 8)
  assert.equal(decoded.height, 8)
  assert.deepEqual(Buffer.from(decoded.pixels), Buffer.from(filteredPixels))
})

test('ctf_stego：LSB 文本往返（rgba 通道，写入后读回）', async () => {
  const result = await stegoTool.execute({ path: fixtures.lsbRgba, action: 'lsb', channel: 'rgba', bit: 0, format: 'text' })
  assert.match(result.text, /flag\{lsb_roundtrip_ok\}/)
  assert.match(result.text, /可打印占比/)
})

test('ctf_stego：LSB 单通道 R 也能往返', async () => {
  const result = await stegoTool.execute({ path: fixtures.lsbR, action: 'lsb', channel: 'r', bit: 0, format: 'text' })
  assert.match(result.text, /single-channel-secret/)
})

test('ctf_stego：灰度（bpp=1）与灰度+Alpha（bpp=2）PNG 的 LSB 往返', async () => {
  // 灰度：bpp=1，channel=all 等价于灰度通道
  const grayPixels = makePixels(12 * 12, 29)
  const grayPayload = Buffer.from('gray-lsb-ok', 'utf8')
  const grayChannels = channelIndexesFor(0, 'all')
  assert.deepEqual(grayChannels.indexes, [0])
  const grayTarget = path.join(tmpDir, 'gray-lsb.png')
  await writeFile(grayTarget, encodePng({
    width: 12,
    height: 12,
    colorType: 0,
    pixels: embedLsbBytes(grayPixels, 1, grayChannels.indexes, 0, grayPayload),
    filters: [0, 3, 4, 1, 2],
  }))
  const grayResult = await stegoTool.execute({ path: grayTarget, action: 'lsb', channel: 'all', format: 'text' })
  assert.match(grayResult.text, /gray-lsb-ok/)

  // 灰度+Alpha：bpp=2，rgba 取 [灰度, Alpha] 两个通道
  const gaPixels = makePixels(12 * 12 * 2, 31)
  const gaPayload = Buffer.from('gray-alpha-lsb-ok', 'utf8')
  const gaChannels = channelIndexesFor(4, 'rgba')
  assert.deepEqual(gaChannels.indexes, [0, 1])
  const gaTarget = path.join(tmpDir, 'gray-alpha-lsb.png')
  await writeFile(gaTarget, encodePng({
    width: 12,
    height: 12,
    colorType: 4,
    pixels: embedLsbBytes(gaPixels, 2, gaChannels.indexes, 0, gaPayload),
    filters: [2, 4, 0, 1, 3],
  }))
  const gaResult = await stegoTool.execute({ path: gaTarget, action: 'lsb', channel: 'rgba', format: 'text' })
  assert.match(gaResult.text, /gray-alpha-lsb-ok/)
})

test('ctf_stego：hex 格式输出与载荷签名识别', async () => {
  const hexResult = await stegoTool.execute({ path: fixtures.lsbZip, action: 'lsb', channel: 'rgba', format: 'hex', maxBytes: 128 })
  assert.match(hexResult.text, /504b0304/)
  const textResult = await stegoTool.execute({ path: fixtures.lsbZip, action: 'lsb', channel: 'rgba', format: 'text', maxBytes: 128 })
  assert.match(textResult.text, /疑似内嵌 ZIP/)
})

test('ctf_stego：索引色 PNG 返回可读的「不支持」而不是抛异常', async () => {
  const info = await stegoTool.execute({ path: fixtures.palettePng, action: 'info' })
  assert.match(info.text, /不支持/)
  assert.match(info.text, /索引色/)
  const lsb = await stegoTool.execute({ path: fixtures.palettePng, action: 'lsb' })
  assert.match(lsb.text, /无法执行 LSB 提取/)
  assert.match(lsb.text, /索引色/)
})

test('ctf_stego：非 PNG 文件返回可读错误文本而不是抛异常', async () => {
  const result = await stegoTool.execute({ path: fixtures.notPng, action: 'lsb' })
  assert.match(result.text, /无法执行 LSB 提取/)
  assert.match(result.text, /PNG 签名不匹配/)
})

test('纯函数：embedLsbBytes / extractLsbBytes 往返，且 detectPayload 识别 flag 文本', () => {
  const pixels = makePixels(8 * 8 * 4, 23)
  const payload = Buffer.from('flag{pure_function}', 'utf8')
  const indexes = channelIndexesFor(6, 'rgba').indexes
  const embedded = embedLsbBytes(pixels, 4, indexes, 1, payload)
  const extracted = extractLsbBytes(embedded, 4, indexes, 1, payload.length)
  assert.deepEqual(Buffer.from(extracted), payload)
  assert.equal(detectPayload(extracted)?.kind, 'flag')
  assert.equal(detectPayload(Buffer.from([0x50, 0x4b, 0x03, 0x04]))?.kind, 'zip')
  // 非法通道必须返回错误说明而不是抛异常
  assert.match(channelIndexesFor(2, 'a').error, /没有 Alpha/)
})
