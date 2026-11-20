/**
 * ctf_codec / ctf_cipher 的单元测试（node:test，零依赖）。
 *
 * 覆盖任务要求的关键路径：
 *   - 各编码的编解码往返（base64/base32/hex/binary/URL/Morse/Bacon 等）；
 *   - `flag{...}` 经 base64 后能被 auto 模式在候选里找回；
 *   - Caesar shift=3 的密文能被爆破还原成 `flag{...}`；
 *   - 非法输入（奇数位 hex、非二进制串）返回可读错误而不是崩溃。
 *
 * 运行：node --test test/codec.test.mjs
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  autoDecode,
  createCodecTool,
  decodeAscii85,
  decodeBacon,
  decodeBase16,
  decodeBase32,
  decodeBase64,
  decodeBinary,
  decodeDecimal,
  decodeHtml,
  decodeMorse,
  decodeOctal,
  decodeOnce,
  decodeQuotedPrintable,
  decodeUnicodeEscape,
  decodeUrl,
  decodeUuencode,
  encodeAscii85,
  encodeBacon,
  encodeBase16,
  encodeBase32,
  encodeBase64,
  encodeBase64Url,
  encodeBinary,
  encodeDecimal,
  encodeHtml,
  encodeMorse,
  encodeOctal,
  encodeQuotedPrintable,
  encodeUnicodeEscape,
  encodeUrl,
  encodeUuencode,
} from '../ctf/codec.js'

import {
  applyCipher,
  atbash,
  bruteforceCaesar,
  caesar,
  columnarDecode,
  columnarEncode,
  createCipherTool,
  keyboardShift,
  railFenceDecode,
  railFenceEncode,
  rot13,
  rot47,
  vigenereDecode,
  vigenereEncode,
} from '../ctf/cipher.js'

const codecTool = createCodecTool({ get: () => undefined })
const cipherTool = createCipherTool({ get: () => undefined })

// ---------------------------------------------------------------------------
// 工具定义契约（index.js 按这些键调用，键名漂移会直接导致集成失败）
// ---------------------------------------------------------------------------

test('ctf_codec 工具定义：name / parameters 顶层键名与枚举完全符合契约', () => {
  assert.equal(codecTool.name, 'ctf_codec')
  assert.equal(typeof codecTool.description, 'string')
  assert.ok(codecTool.description.length > 40, 'description 要写给模型看，不能是占位符')
  assert.equal(codecTool.parameters.type, 'object')
  assert.equal(codecTool.parameters.additionalProperties, false)
  assert.deepEqual(Object.keys(codecTool.parameters.properties).sort(), ['action', 'encoding', 'maxDepth', 'text'])
  assert.deepEqual(codecTool.parameters.required, ['text'])
  assert.deepEqual(codecTool.parameters.properties.action.enum, ['decode', 'encode', 'auto'])
  assert.deepEqual(
    codecTool.parameters.properties.encoding.enum,
    ['auto', 'base64', 'base64url', 'base32', 'base16', 'base85', 'binary', 'decimal', 'octal', 'url', 'html', 'morse', 'bacon', 'rot13', 'quoted-printable', 'unicode-escape', 'uuencode'],
  )
  assert.equal(codecTool.parameters.properties.maxDepth.type, 'integer')
  assert.deepEqual(codecTool.output.render({}, { text: 'hello' }), [{ type: 'text', text: 'hello' }])
})

test('ctf_cipher 工具定义：name / parameters 顶层键名与枚举完全符合契约', () => {
  assert.equal(cipherTool.name, 'ctf_cipher')
  assert.equal(typeof cipherTool.description, 'string')
  assert.ok(cipherTool.description.length > 40)
  assert.equal(cipherTool.parameters.type, 'object')
  assert.equal(cipherTool.parameters.additionalProperties, false)
  assert.deepEqual(
    Object.keys(cipherTool.parameters.properties).sort(),
    ['action', 'cipher', 'key', 'maxShift', 'rails', 'shift', 'text'],
  )
  assert.deepEqual(cipherTool.parameters.required, ['text'])
  assert.deepEqual(cipherTool.parameters.properties.action.enum, ['bruteforce', 'apply'])
  assert.deepEqual(
    cipherTool.parameters.properties.cipher.enum,
    ['caesar', 'rot13', 'rot47', 'atbash', 'railfence', 'vigenere', 'columnar', 'bacon', 'morse', 'keyboard-shift'],
  )
  assert.deepEqual(cipherTool.output.render({}, { text: 'hello' }), [{ type: 'text', text: 'hello' }])
})

// ---------------------------------------------------------------------------
// 编解码往返
// ---------------------------------------------------------------------------

test('base64 往返（含中文与缺失 padding）', () => {
  const text = 'flag{base64_中文_roundtrip}'
  const encoded = encodeBase64(text)
  assert.equal(decodeBase64(encoded), text)
  assert.equal(decodeBase64(encoded.replace(/=+$/, '')), text)
})

test('base64url 往返（无 padding、URL-safe 字母表）', () => {
  const text = 'flag{base64url??>>?_test}'
  const encoded = encodeBase64Url(text)
  assert.ok(!encoded.includes('='), 'base64url 不应带 padding')
  assert.equal(decodeBase64(encoded), text)
})

test('base32 往返（RFC 4648，无 padding 容忍）', () => {
  const text = 'flag{base32_中文}'
  const encoded = encodeBase32(text)
  assert.match(encoded, /^[A-Z2-7]+=*$/)
  assert.equal(decodeBase32(encoded), text)
  assert.equal(decodeBase32(encoded.replace(/=+$/, '')), text)
  assert.equal(decodeBase32(encoded.toLowerCase()), text)
})

test('base16 / hex 往返', () => {
  const text = 'flag{hex_中文}'
  const encoded = encodeBase16(text)
  assert.match(encoded, /^[0-9a-f]+$/)
  assert.equal(decodeBase16(encoded), text)
  assert.equal(decodeBase16(encoded.toUpperCase()), text)
})

test('binary 往返', () => {
  const text = 'flag{binary_测试}'
  const encoded = encodeBinary(text)
  assert.match(encoded, /^[01]+$/)
  assert.equal(encoded.length % 8, 0)
  assert.equal(decodeBinary(encoded), text)
  assert.equal(decodeBinary([...encoded].join(' ')), text, '允许空格分组')
})

test('decimal / octal 往返', () => {
  const text = 'flag{num_测试}'
  assert.equal(decodeDecimal(encodeDecimal(text)), text)
  assert.equal(decodeOctal(encodeOctal(text)), text)
  assert.equal(decodeOctal(encodeOctal(text).replace(/ /g, '\\')), text, '支持 \\101 转义写法')
})

test('URL 往返', () => {
  const text = 'flag{url 空格+加号&中文}'
  const encoded = encodeUrl(text)
  assert.equal(decodeUrl(encoded), text)
  assert.equal(decodeUrl(encoded.replace(/%20/g, '+')), text, '表单式 + 号表示空格')
})

test('HTML 实体往返', () => {
  const text = 'flag{<a&"b">\'c\'}'
  const encoded = encodeHtml(text)
  assert.ok(encoded.includes('&lt;'))
  assert.equal(decodeHtml(encoded), text)
  assert.equal(decodeHtml('&#102;&#x6c;ag'), 'flag')
})

test('Morse 往返（A/B 与长短两种写法）', () => {
  const text = 'SOS HELP'
  assert.equal(decodeMorse(encodeMorse(text)), text)
  assert.equal(decodeMorse('短短短 长长长 / 短'), 'SO E')
  assert.equal(decodeMorse('... --- ...'), 'SOS')
})

test('Bacon 往返（A/B 与 0/1 两种写法）', () => {
  assert.equal(decodeBacon(encodeBacon('FLAG')), 'FLAG')
  assert.equal(decodeBacon(encodeBacon('AZ')), 'AZ')
  const asZeroOne = encodeBacon('FLAG').replace(/A/g, '0').replace(/B/g, '1')
  assert.equal(decodeBacon(asZeroOne), 'FLAG')
})

test('ASCII85 / base85 往返', () => {
  const text = 'flag{ascii85}'
  assert.equal(decodeAscii85(encodeAscii85(text)), text)
  assert.equal(decodeAscii85(`<~${encodeAscii85(text)}~>`), text, '支持 <~ ~> 包裹')
})

test('quoted-printable 往返', () => {
  const text = 'flag{qp 中文=test}\nsecond line'
  assert.equal(decodeQuotedPrintable(encodeQuotedPrintable(text)), text)
})

test('unicode-escape 往返', () => {
  const text = 'flag{中文\\x41\u0001}'
  assert.equal(decodeUnicodeEscape(encodeUnicodeEscape(text)), text)
  assert.equal(decodeUnicodeEscape('\\u0066\\u006c\\u0061\\u0067'), 'flag')
})

test('uuencode 往返', () => {
  const text = 'flag{uuencode_中文_}'
  const encoded = encodeUuencode(text)
  assert.ok(encoded.startsWith('begin 644'))
  assert.ok(encoded.trimEnd().endsWith('end'))
  assert.equal(decodeUuencode(encoded), text)
})

// ---------------------------------------------------------------------------
// 自动编码链爆破
// ---------------------------------------------------------------------------

test('auto 模式能从 base64 候选里找回 flag', async () => {
  const flag = 'flag{auto_chain_works}'
  const encoded = encodeBase64(flag)
  const result = await codecTool.execute({ action: 'auto', text: encoded })
  assert.match(result.text, /## 结论/)
  assert.match(result.text, /## 候选/)
  assert.match(result.text, /## 下一步建议/)
  assert.ok(result.text.includes(flag), `auto 输出里应包含还原出的 flag，实际：\n${result.text}`)
  assert.match(result.text, /★/, '疑似 flag 的候选要打标记')
  assert.match(result.text, /base64/, '候选路径里应出现 base64')
})

test('auto 模式能递归解两层（hex → base64 → flag）', () => {
  const flag = 'flag{two_layers}'
  const encoded = encodeBase16(encodeBase64(flag))
  const { candidates, maxDepth } = autoDecode(encoded, { maxDepth: 4 })
  assert.equal(maxDepth, 4)
  const hit = candidates.find((candidate) => candidate.result === flag)
  assert.ok(hit !== undefined, `候选里应出现两层还原的 flag，实际候选：${JSON.stringify(candidates.map((c) => c.pathLabel))}`)
  assert.deepEqual(hit.path, ['base16', 'base64'])
  assert.equal(hit.flagLike, true)
})

test('decode 且 encoding=auto 等价于 auto 爆破', async () => {
  const flag = 'flag{decode_auto}'
  const result = await codecTool.execute({ action: 'decode', encoding: 'auto', text: encodeBase64(flag) })
  assert.ok(result.text.includes(flag))
})

test('auto 对已经是明文的输入给出解释，而不是硬凑 flag', async () => {
  const result = await codecTool.execute({ action: 'auto', text: 'this is just plain english text' })
  assert.doesNotMatch(result.text, /★/)
  assert.match(result.text, /输入本身/)
})

test('decode 指定编码时提示「还能再解一层」', async () => {
  const inner = encodeBase32('flag{next_layer}')
  const result = await codecTool.execute({ action: 'decode', encoding: 'base64', text: encodeBase64(inner) })
  assert.ok(result.text.includes(inner), '应显示本层解出的 base32 文本')
  assert.match(result.text, /还能再解一层/)
})

test('encode 分支：base16 得到 4142', async () => {
  const result = await codecTool.execute({ action: 'encode', encoding: 'base16', text: 'AB' })
  assert.ok(result.text.includes('4142'))
  assert.match(result.text, /## 结论/)
})

test('encode 且 encoding=auto 报错，要求显式指定', async () => {
  const result = await codecTool.execute({ action: 'encode', text: 'abc' })
  assert.match(result.text, /显式指定 encoding/)
  assert.match(result.text, /处理失败/)
})

// ---------------------------------------------------------------------------
// 非法输入：返回错误文本而不是崩溃
// ---------------------------------------------------------------------------

test('奇数长度 hex：纯函数抛错，execute 返回可读失败报告', async () => {
  assert.throws(() => decodeBase16('abc'), /奇数/)
  const result = await codecTool.execute({ action: 'decode', encoding: 'base16', text: 'abc' })
  assert.equal(typeof result.text, 'string')
  assert.match(result.text, /处理失败/)
  assert.match(result.text, /## 下一步建议/)
})

test('非二进制串：纯函数抛错，execute 返回可读失败报告', async () => {
  assert.throws(() => decodeBinary('0101201'), /只能包含 0 和 1/)
  assert.throws(() => decodeBinary('0101'), /8 的倍数/)
  const result = await codecTool.execute({ action: 'decode', encoding: 'binary', text: '0101201' })
  assert.match(result.text, /处理失败/)
  assert.match(result.text, /二进制/)
})

test('非法 base64 / Bacon / Morse 输入都被拦成错误', () => {
  assert.throws(() => decodeBase64('!!!!'), /非法字符/)
  assert.throws(() => decodeBase64('abcde'), /长度非法/)
  assert.throws(() => decodeBacon('XYZ'), /只能包含 A\/B/)
  assert.throws(() => decodeMorse('abc'), /无法识别/)
  assert.throws(() => decodeOnce('auto', 'abc'), /不支持的编码/)
})

test('空 text 参数在 execute 层被拒绝', async () => {
  const codecResult = await codecTool.execute({ action: 'decode', encoding: 'base64', text: '' })
  assert.match(codecResult.text, /非空的 text/)
  const cipherResult = await cipherTool.execute({ action: 'bruteforce', cipher: 'caesar', text: '' })
  assert.match(cipherResult.text, /非空的 text/)
})

// ---------------------------------------------------------------------------
// 古典密码
// ---------------------------------------------------------------------------

test('Caesar shift=3 的 iodj{...} 能被爆破还原成 flag{...}', async () => {
  const plaintext = 'flag{test_ok}'
  const ciphertext = caesar(plaintext, 3)
  assert.equal(ciphertext, 'iodj{whvw_rn}')

  const candidates = bruteforceCaesar(ciphertext)
  assert.equal(candidates.length, 26)
  const hit = candidates.find((candidate) => candidate.result === plaintext)
  assert.ok(hit !== undefined, '爆破候选里必须有正确明文')
  assert.equal(hit.label, 'shift=3')

  const result = await cipherTool.execute({ action: 'bruteforce', cipher: 'caesar', text: ciphertext })
  assert.match(result.text, /## 结论/)
  assert.match(result.text, /## 候选/)
  assert.match(result.text, /## 下一步建议/)
  assert.ok(result.text.includes(plaintext), `工具输出里应包含明文，实际：\n${result.text}`)
  assert.match(result.text, /★/, '疑似 flag 候选要打标记')
})

test('Caesar apply 用 shift 解一次', () => {
  assert.equal(applyCipher('caesar', 'iodj{whvw_rn}', { shift: 3 }).result, 'flag{test_ok}')
  assert.equal(caesar('flag', 3), 'iodj')
})

test('ROT13 / ROT47 / Atbash 是自反或唯一映射', () => {
  assert.equal(rot13(rot13('flag{rot13}')), 'flag{rot13}')
  assert.equal(rot47(rot47('flag{rot47}')), 'flag{rot47}')
  assert.equal(decodeCipherText(atbash('flag{atbash}')), 'flag{atbash}')
})

/** atbash 自反性辅助：直接再跑一遍 atbash。 */
function decodeCipherText(text) {
  return atbash(text)
}

test('Vigenère 加解密往返', () => {
  const plaintext = 'flag{vigenere_ok}'
  const encrypted = vigenereEncode(plaintext, 'KEY')
  assert.notEqual(encrypted, plaintext)
  assert.equal(vigenereDecode(encrypted, 'KEY'), plaintext)
  assert.equal(applyCipher('vigenere', encrypted, { key: 'KEY' }).result, plaintext)
})

test('列置换加解密往返（含末尾不齐）', () => {
  for (const key of ['ZEBRA', '3124', 'KEY']) {
    for (const plaintext of ['flag{columnar_ok}', 'flag{odd_length_12345}', 'abcdefg']) {
      assert.equal(columnarDecode(columnarEncode(plaintext, key), key), plaintext, `key=${key} text=${plaintext}`)
    }
  }
})

test('栅栏加解密往返', () => {
  for (const rails of [2, 3, 5]) {
    const plaintext = 'flag{rail_fence_ok}'
    assert.equal(railFenceDecode(railFenceEncode(plaintext, rails), rails), plaintext)
  }
})

test('键盘错位可逆，bruteforce 能命中移位后的 flag', async () => {
  const shifted = keyboardShift('flag{keyboard}', 1) // 向右错一位
  assert.notEqual(shifted, 'flag{keyboard}')
  assert.equal(keyboardShift(shifted, -1), 'flag{keyboard}')
  const result = await cipherTool.execute({ action: 'bruteforce', cipher: 'keyboard-shift', text: shifted })
  assert.ok(result.text.includes('flag{keyboard}'), `键盘错位爆破应找回明文，实际：\n${result.text}`)
})

test('Morse / Bacon 作为密码类型直接解', async () => {
  const morseResult = await cipherTool.execute({ action: 'apply', cipher: 'morse', text: '... --- ...' })
  assert.ok(morseResult.text.includes('SOS'))
  const baconResult = await cipherTool.execute({ action: 'apply', cipher: 'bacon', text: encodeBacon('FLAG') })
  assert.ok(baconResult.text.includes('FLAG'))
})

test('Vigenère 缺少 key 时 apply 返回可读失败报告', async () => {
  const result = await cipherTool.execute({ action: 'apply', cipher: 'vigenere', text: 'xyz' })
  assert.match(result.text, /处理失败/)
  assert.match(result.text, /key/)
})

test('栅栏爆破在 2..12 条栅栏内命中明文', async () => {
  const plaintext = 'flag{rail_brute_ok}'
  const ciphertext = railFenceEncode(plaintext, 4)
  const result = await cipherTool.execute({ action: 'bruteforce', cipher: 'railfence', text: ciphertext })
  assert.ok(result.text.includes(plaintext), `栅栏爆破应命中明文，实际：\n${result.text}`)
})
