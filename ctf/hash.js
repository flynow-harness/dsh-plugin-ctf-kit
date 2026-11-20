/**
 * `ctf_hash` — 哈希识别、内置小字典弱口令破解、多算法计算。
 *
 * CTF 里哈希题的套路很固定：先判断这是哪种哈希（长度/前缀/字符集），
 * 再决定是查彩虹表、跑 hashcat，还是根本就是带盐慢哈希只能放弃暴力。
 * 这个模块只做确定性的本地计算：识别给出候选与 hashcat 模式号，
 * 破解只跑内置小字典 + 用户内联口令，绝不联网、绝不下载字典。
 *
 * 依赖仅 Node 内置 `node:crypto`；bcrypt / crypt(3) 这类带盐慢哈希只识别不暴破，
 * 原因在报告里明说——小字典对它们本来就没有命中率，且 Node 内置 crypto 不提供这些实现。
 */
import { createHash } from 'node:crypto'
import { formatRows, textOutput } from './util.js'

/** 本模块支持的本地计算算法（Node 内置 crypto 直接可用）。 */
export const HASH_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']

/**
 * 内置「top200 常见口令」摘编。
 * 来源是历年泄露口令统计里的高位集合；刻意保持小体积，超出口径的交给 hashcat + rockyou。
 */
export const COMMON_PASSWORDS = `
123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon
123123 baseball abc123 football monkey letmein 696969 shadow master 666666
qwertyuiop 123321 mustang 1234567890 michael 654321 superman 1qaz2wsx 7777777 fuckyou
121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm asdfgh
hunter buster soccer harley batman andrew tigger sunshine iloveyou fuckme
2000 charlie robert thomas hockey ranger daniel starwars klaster 112233
asshole computer michelle jessica pepper 1111 zxcvbn 555555 11111111 131313
freedom 777777 pass fuckmylife maggie 159753 aaaaaa ginger princess joshua
cheese amanda summer love ashley 6969 nicole chelsea biteme matthew
access yankees 987654321 dallas austin thunder taylor matrix william corvette
hello martin heather secret fucker merlin diamond 1234qwer gfhjkm hammer
silver 222222 88888888 anthony justin test bailey q1w2e3r4t5 patrick internet
scooter orange 11111 golfer cookie richard samantha bigdog guitar jackson
whatever mickey chicken sparky snoopy maverick phoenix camaro sexy peanut
morgan welcome falcon cowboy ferrari samsung andrea smokey steelers joseph
mercedes dakota arsenal eagles melissa boomer booboo spider nascar monster
tigers yellow xxxxxx 123123123 gateway marina diablo bulldog qwer1234 compaq
purple hardcore banana junior hannah 123654 porsche lakers iceman money
cowboys 987654 london tennis 999999 123abc passw0rd p@ssw0rd letmein! qwerty123
admin root toor flag ctf challenge 55555 4444 3333 george
`.trim().split(/\s+/)

/**
 * 内置「CTF 常见口令」字典：赛事镜像、练习靶场里最常出现的弱口令与 flag 占位。
 * 它比 common 更偏向题目上下文（flag/ctf/admin），两者互有重叠是有意的。
 */
export const CTF_PASSWORDS = `
flag admin ctf 123456 root toor password qwerty letmein secret key pass
12345678 111111 test guest changeme default ctf2024 flag2024 0 1 123 1234 12345
666666 888888 admin123 root123 toor123 ctf123 flag123 letmein123 hello world
welcome you win winner hackme pwn shell sh3ll 1337 31337 challenge answer
password123 qwerty123 abc123 aaa bbb ccc 000000 flag{test} ctf{test} FLAG{test}
CTF{test} flag{123} ctf{123} 1q2w3e4r 1qaz2wsx zxcvbnm asdfgh qwe123 admin888
root888 toor888 flag{flag} ctf{ctf}
`.trim().split(/\s+/)

/** 长度 → 常见无盐哈希类型。模式号对应 hashcat 的 `-m`。 */
const HEX_LENGTH_TABLE = {
  16: [
    { type: 'mysql323', label: 'MySQL 3.x OLD_PASSWORD', hashcat: 200, note: '16 位 hex；也可能只是被截断的 MD5。' },
    { type: 'des', label: 'crypt(3) DES', hashcat: 1500, note: 'DES crypt 只取前 8 个字符做密钥，强度极低。' },
  ],
  32: [
    { type: 'md5', label: 'MD5', hashcat: 0, confidence: 'high', note: '最常见；无盐，可直接查库/暴破。' },
    { type: 'ntlm', label: 'NTLM（Windows 账户哈希）', hashcat: 1000, note: '与 MD5 同为 32 位 hex，仅凭长度无法区分；需要题目上下文判断。' },
    { type: 'md4', label: 'MD4', hashcat: 900, note: 'MD4 在 CTF 里通常是 NTLM 的底层算法。' },
    { type: 'lm', label: 'LM（LAN Manager）', hashcat: 3000, note: 'LM 通常表现为全大写 hex，且固定分成两段 8 字节。' },
  ],
  40: [
    { type: 'sha1', label: 'SHA-1', hashcat: 100, confidence: 'high', note: '40 位 hex；也常见 `*` 前缀的 MySQL 4.1+ 存储格式。' },
    { type: 'ripemd160', label: 'RIPEMD-160', hashcat: 6000, note: '同为 40 位 hex，需要额外线索区分。' },
    { type: 'mysql41', label: 'MySQL 4.1+（`*` + 40 hex）', hashcat: 300, note: '真正特征是开头的 `*`；若输入以 `*` 开头优先按此识别。' },
  ],
  64: [
    { type: 'sha256', label: 'SHA-256', hashcat: 1400, confidence: 'high', note: '64 位 hex；无盐。' },
    { type: 'sha3-256', label: 'SHA3-256', hashcat: 17400, note: '长度相同，但算法不同（填充方式不同）。' },
    { type: 'keccak-256', label: 'Keccak-256（以太坊）', hashcat: 17800, note: '以太坊地址/交易哈希用 Keccak，不是 NIST SHA3。' },
  ],
  96: [
    { type: 'sha384', label: 'SHA-384', hashcat: 10800, confidence: 'high', note: '96 位 hex；无盐。' },
  ],
  128: [
    { type: 'sha512', label: 'SHA-512', hashcat: 1700, confidence: 'high', note: '128 位 hex；无盐。' },
    { type: 'whirlpool', label: 'Whirlpool', hashcat: 6100, note: '同为 128 位 hex，较少见。' },
  ],
}

/** 前缀型（带盐 / 特殊编码）哈希的识别表。 */
const PREFIX_TABLE = [
  { test: /^\$1\$/, type: 'md5crypt', label: 'md5crypt（`$1$`）', hashcat: 500, reason: '`$1$` 前缀是 Linux crypt(3) 的 MD5 变体。' },
  { test: /^\$apr1\$/, type: 'apr1', label: 'Apache APR1-MD5（`$apr1$`）', hashcat: 1600, reason: '`$apr1$` 前缀是 Apache htpasswd 的 MD5 格式。' },
  { test: /^\$2[abxy]?\$/, type: 'bcrypt', label: 'bcrypt（`$2a$/$2b$/$2y$`）', hashcat: 3200, reason: '`$2*$` 前缀是 bcrypt，自带 cost 因子。' },
  { test: /^\$5\$/, type: 'sha256crypt', label: 'sha256crypt（`$5$`）', hashcat: 7400, reason: '`$5$` 前缀是 Linux crypt(3) 的 SHA-256 变体。' },
  { test: /^\$6\$/, type: 'sha512crypt', label: 'sha512crypt（`$6$`）', hashcat: 1800, reason: '`$6$` 前缀是 Linux crypt(3) 的 SHA-512 变体。' },
  { test: /^\$argon2(?:id|i|d)?\$/, type: 'argon2', label: 'Argon2（`$argon2*$`）', hashcat: 34000, reason: '`$argon2*$` 前缀是 Argon2 密码哈希；内存硬，暴破成本极高。' },
  { test: /^\$P\$|^\$H\$/, type: 'phpass', label: 'phpass / WordPress（`$P$`、`$H$`）', hashcat: 400, reason: '`$P$` / `$H$` 是 phpass 便携哈希，WordPress 默认格式。' },
  { test: /^\{SSHA\}/i, type: 'ssha', label: 'LDAP SSHA（`{SSHA}`）', hashcat: 111, reason: '`{SSHA}` 是 Base64(SHA1(密码+盐)+盐)，带盐。' },
  { test: /^\{SHA\}/i, type: 'sha1-ldap', label: 'LDAP SHA（`{SHA}`）', hashcat: 101, reason: '`{SHA}` 是 Base64(SHA1(密码))，无盐。' },
  { test: /^\{SMD5\}/i, type: 'smd5', label: 'LDAP SMD5（`{SMD5}`）', hashcat: 20, reason: '`{SMD5}` 是 Base64(MD5(密码+盐)+盐)，带盐。' },
]

/** 已识别但明确不做本地暴破的类型 → 原因。 */
const SLOW_HASH_REASONS = {
  bcrypt: 'bcrypt 每次校验都要跑 cost 轮（默认 2^10~2^12），小字典的命中率与耗时不成比例。',
  md5crypt: 'md5crypt（`$1$`）是带盐的慢哈希，必须先按每个候选重新派生，内置小字典帮不上忙。',
  sha256crypt: 'sha256crypt（`$5$`）是带盐慢哈希，Node 内置 crypto 不提供 crypt(3) 派生。',
  sha512crypt: 'sha512crypt（`$6$`）是带盐慢哈希，Node 内置 crypto 不提供 crypt(3) 派生。',
  apr1: 'APR1-MD5 带盐且需要按 crypt 规则派生，Node 内置 crypto 不提供该实现。',
  argon2: 'Argon2 是内存硬函数，单次派生就要几十毫秒到秒级，且 Node 内置 crypto 不提供。',
  phpass: 'phpass/WordPress 哈希带盐且迭代多轮，Node 内置 crypto 不提供该派生过程。',
  ssha: 'SSHA 带盐，需要先 Base64 解出盐再逐个派生，内置小字典没有意义。',
  'sha1-ldap': 'LDAP `{SHA}` 是 Base64(SHA1)，可用 `-m 101` 配合字典；本地实现需要 Base64 解码后再比对。',
  smd5: 'LDAP SMD5 带盐，小字典命中率极低。',
}

/** 已识别但本地 crack 算法列表覆盖不到的类型 → 原因（给出 hashcat 出路）。 */
const UNSUPPORTED_LOCAL_REASONS = {
  sha384: '本工具 crack 的算法列表按契约只含 md5/sha1/sha256/sha512；SHA-384 请用 hashcat `-m 10800`。',
  'sha3-256': '本地未实现 SHA3-256 派生；请用 hashcat `-m 17400`。',
  'keccak-256': '本地未实现 Keccak-256（以太坊）派生；请用 hashcat `-m 17800`。',
  whirlpool: '本地未实现 Whirlpool 派生；请用 hashcat `-m 6100`。',
  ripemd160: '本地未实现 RIPEMD-160 派生；请用 hashcat `-m 6000`。',
  mysql323: '本地未实现 MySQL 3.x OLD_PASSWORD 派生；请用 hashcat `-m 200`。',
  des: '本地未实现 crypt(3) DES 派生；请用 hashcat `-m 1500`。',
  'sha1-ldap': 'LDAP `{SHA}` 需要先 Base64 解码再按 SHA1 派生，本地不提供该格式的解析；请用 hashcat `-m 101`。',
}

/** 归一化哈希串：去空白、去 `0x`、去常见标签前缀。 */
function normalizeHashInput(input) {
  let value = String(input ?? '').trim()
  const notes = []
  if (value.length === 0) return { value, notes }
  if (/^0x[0-9a-f]+$/i.test(value)) {
    value = value.slice(2)
    notes.push('已去掉输入里的 `0x` 前缀。')
  }
  const labeled = /^(md5|sha1|sha256|sha512|ntlm)\s*[:=]\s*(.+)$/i.exec(value)
  if (labeled !== null) {
    notes.push(`输入带有 \`${labeled[1]}:\` 标签，已按标签剥离前缀后识别。`)
    value = labeled[2].trim()
  }
  return { value, notes }
}

/**
 * 识别一个哈希串：按前缀优先、再按长度/字符集给出候选类型。
 * 纯函数，不读文件、不联网。
 * @param {string} input 待识别的哈希串
 * @returns {{input: string, normalized: string, candidates: Array<object>, notes: string[]}}
 */
export function identifyHash(input) {
  const raw = String(input ?? '').trim()
  const { value, notes } = normalizeHashInput(raw)
  const candidates = []
  if (value.length === 0) {
    return { input: raw, normalized: value, candidates: [], notes: ['输入为空。'] }
  }

  for (const entry of PREFIX_TABLE) {
    if (entry.test.test(value)) {
      candidates.push({
        type: entry.type,
        label: entry.label,
        reason: entry.reason,
        hashcat: entry.hashcat,
        note: entry.hashcat === undefined ? '' : `hashcat: -m ${entry.hashcat}`,
      })
      break
    }
  }

  if (candidates.length === 0 && /^\*[0-9a-f]{40}$/i.test(value)) {
    candidates.push({
      type: 'mysql41',
      label: 'MySQL 4.1+ 密码哈希（`*` + SHA1 大写 hex）',
      reason: '`*` 开头并跟 40 位 hex 是 MySQL 4.1+ 的 password() 存储格式。',
      hashcat: 300,
      note: 'hashcat: -m 300',
    })
  }

  if (candidates.length === 0 && /^[0-9a-f]+$/i.test(value)) {
    const table = HEX_LENGTH_TABLE[value.length]
    if (table !== undefined) {
      const upper = value.length === 32 && /^[0-9A-F]+$/.test(value)
      for (const entry of table) {
        candidates.push({
          type: entry.type,
          label: entry.label,
          reason: `${value.length} 位十六进制字符，字符集全部为 hex。`,
          hashcat: entry.hashcat,
          note: `${entry.note ?? ''}${upper && entry.type === 'lm' ? '输入全大写，LM/NTLM 的可能性更高。' : ''}`.trim(),
          confidence: entry.confidence ?? (entry.type === table[0].type ? 'high' : 'medium'),
        })
      }
    } else if (value.length % 2 === 0 && value.length >= 16) {
      notes.push(`长度为 ${value.length} 位 hex，不在常见哈希长度（32/40/64/96/128）里，可能是截断、拼接或自定义算法。`)
    }
  }

  if (candidates.length === 0) {
    const base64ish = /^[A-Za-z0-9+/]{16,}={0,2}$/.test(value)
    if (base64ish) notes.push('输入是 Base64 字符集的长串，可能不是哈希，而是被 Base64 编码的哈希/密文；先用 ctf_codec 解码再识别。')
    else if (value.length > 0 && value.length <= 64) notes.push('没有任何已知哈希前缀，可能是明文口令、自定义编码或带自定义标签的哈希。')
    if (value.length > 64 && !/^[0-9a-f]+$/i.test(value)) notes.push('输入较长且不是纯 hex，按文本/编码处理更合适。')
  } else if (/^[0-9a-f]+$/i.test(value) && HEX_LENGTH_TABLE[value.length] !== undefined) {
    notes.push('32 位 hex 无法仅凭长度区分 MD5 / NTLM / MD4；40/64/96/128 位同理存在少量同长候选。带 `$`、`{}` 前缀的格式优先按前缀识别。')
  }

  return { input: raw, normalized: value, candidates, notes }
}

/** 计算单个哈希（hex，小写）。 */
export function computeHash(text, algorithm) {
  return createHash(algorithm).update(String(text), 'utf8').digest('hex')
}

/** 对明文一次性算出 4 种哈希。 */
export function computeAllHashes(text) {
  const out = {}
  for (const algorithm of HASH_ALGORITHMS) out[algorithm] = computeHash(text, algorithm)
  return out
}

/**
 * 把 `dictionary` + `wordlist` 组装成候选口令列表。
 * 顺序：内置字典在前、内联候选在后；重复项只保留第一次出现（保证 attempt 计数有意义）。
 * @param {'none'|'common'|'ctf'} dictionary
 * @param {string[]|undefined} wordlist
 * @returns {string[]}
 */
export function buildCandidates(dictionary, wordlist) {
  const out = []
  const seen = new Set()
  const push = (entry) => {
    const value = String(entry ?? '')
    if (value.length === 0) return
    if (seen.has(value)) return
    seen.add(value)
    out.push(value)
  }
  const builtin = dictionary === 'common' ? COMMON_PASSWORDS : dictionary === 'ctf' ? CTF_PASSWORDS : []
  for (const entry of builtin) push(entry)
  if (Array.isArray(wordlist)) for (const entry of wordlist) push(entry)
  return out
}

/**
 * 根据识别结果决定 crack 尝试哪些算法。
 * @param {ReturnType<typeof identifyHash>} identification
 * @param {'auto'|'md5'|'sha1'|'sha256'|'sha512'} requested
 */
export function algorithmsForIdentification(identification, requested) {
  if (HASH_ALGORITHMS.includes(requested)) {
    return { algorithms: [requested], skipped: [], notes: [`按入参 algorithm=${requested} 限定算法。`] }
  }
  const skipped = []
  const notes = []
  const kinds = new Set(identification.candidates.map((candidate) => candidate.type))
  for (const kind of kinds) {
    if (SLOW_HASH_REASONS[kind] !== undefined) skipped.push({ type: kind, reason: SLOW_HASH_REASONS[kind] })
    else if (UNSUPPORTED_LOCAL_REASONS[kind] !== undefined) skipped.push({ type: kind, reason: UNSUPPORTED_LOCAL_REASONS[kind] })
  }
  const map = {}
  if (kinds.has('md5') || kinds.has('ntlm') || kinds.has('md4') || kinds.has('lm')) map.md5 = 'md5'
  if (kinds.has('sha1')) map.sha1 = 'sha1'
  if (kinds.has('sha256')) map.sha256 = 'sha256'
  if (kinds.has('sha512')) map.sha512 = 'sha512'
  if (kinds.has('mysql41')) {
    // `*` + SHA1 的存储格式，本地按 SHA1 尝试即可。
    map.sha1 = 'sha1'
    notes.push('MySQL 4.1+ 哈希实际是 `*` + SHA1(密码) 的大写 hex，本地按 SHA1 尝试。')
  }
  const algorithms = [...new Set(Object.values(map))]
  if (algorithms.length === 0) {
    if (skipped.length > 0) {
      return { algorithms: [], skipped, notes: ['识别结果本地不提供对应派生实现（带盐慢哈希或本工具未覆盖的算法）：只识别、不做本地暴力，原因见下表。'] }
    }
    notes.push('未能识别哈希类型，按 MD5/SHA1/SHA256/SHA512 全部尝试（小字典，成本可忽略）。')
    return { algorithms: [...HASH_ALGORITHMS], skipped, notes }
  }
  notes.push(`按识别结果尝试：${algorithms.join(' / ')}。`)
  return { algorithms, skipped, notes }
}

/**
 * 在候选口令上跑哈希比对。
 * @param {string} hashValue 目标哈希
 * @param {string[]} algorithms 要尝试的算法
 * @param {string[]} candidates 候选口令
 * @returns {{found: boolean, plaintext?: string, algorithm?: string, attempts: number, elapsedMs: number, rawHit?: boolean}}
 */
export function crackHash(hashValue, algorithms, candidates) {
  const started = process.hrtime.bigint()
  const target = String(hashValue ?? '').trim().toLowerCase()
  let attempts = 0
  for (const algorithm of algorithms) {
    for (const candidate of candidates) {
      attempts += 1
      if (computeHash(candidate, algorithm) === target) {
        return {
          found: true,
          plaintext: candidate,
          algorithm,
          attempts,
          elapsedMs: Number(process.hrtime.bigint() - started) / 1e6,
        }
      }
    }
  }
  // 有些题目直接把明文当「哈希」给出来，顺手做一次明文相等比较。
  // 这里不计入 attempts：attempts 只统计哈希派生次数，报告里的「算法 × 候选数」才对得上。
  for (const candidate of candidates) {
    if (candidate.toLowerCase() === target) {
      return {
        found: true,
        plaintext: candidate,
        algorithm: 'plaintext',
        attempts,
        elapsedMs: Number(process.hrtime.bigint() - started) / 1e6,
        rawHit: true,
      }
    }
  }
  return { found: false, attempts, elapsedMs: Number(process.hrtime.bigint() - started) / 1e6 }
}

/** 渲染 identify 的 Markdown 报告。 */
function renderIdentify(identification) {
  const lines = []
  const primary = identification.candidates[0]
  lines.push('## 结论')
  if (primary === undefined) {
    lines.push(`无法识别为标准哈希格式：\`${identification.normalized.slice(0, 96)}\``)
  } else {
    const count = identification.candidates.length
    lines.push(`\`${identification.normalized}\` → 最可能为 **${primary.label}**（hashcat \`-m ${primary.hashcat}\`）。`)
    if (count > 1) lines.push(`该输入下还有 ${count - 1} 个候选类型（见下表）；如需确定性结论，请结合题目来源/上下文判断。`)
    else lines.push('该前缀/长度下没有其他强候选，识别结果可以认为确定。')
  }
  if (identification.candidates.length > 0) {
    lines.push('')
    lines.push('## 候选模式')
    const rows = identification.candidates.map((candidate, index) => [
      String(index + 1),
      candidate.label,
      candidate.hashcat === undefined ? '-' : String(candidate.hashcat),
      candidate.reason,
    ])
    lines.push(formatRows(rows, ['#', '类型', 'hashcat -m', '判定依据']))
    const notes = identification.candidates
      .map((candidate, index) => ({ candidate, index }))
      .filter(({ candidate }) => typeof candidate.note === 'string' && candidate.note.length > 0)
    if (notes.length > 0) {
      lines.push('')
      lines.push('## 备注')
      for (const { candidate, index } of notes) lines.push(`- 候选 ${index + 1}（${candidate.label}）：${candidate.note}`)
    }
  }

  if (identification.notes.length > 0) {
    lines.push('')
    lines.push('## 说明')
    for (const note of identification.notes) lines.push(`- ${note}`)
  }

  lines.push('')
  lines.push('## 下一步建议')
  if (primary !== undefined) {
    lines.push(`- 字典暴破：\`hashcat -m ${primary.hashcat} -a 0 '${identification.normalized}' rockyou.txt\``)
    lines.push(`- 在线查表（仅题目允许时）：\`hashcat -m ${primary.hashcat} --show\` 或 cmd5 一类站点；比赛环境请先确认规则。`)
    lines.push(`- 想本地复核某个明文：用 \`ctf_hash\` 的 \`action=compute\` 算同一算法再比对。`)
  } else {
    lines.push('- 先用 `ctf_codec` 做编码识别（Base64/URL/Hex 等），确认是不是「编码过的哈希」。')
    lines.push('- 如果是带自定义前缀的哈希，把前缀特征（如 `sha256:`、`{SHA}`）一起发给 `ctf_hash` 再识别。')
  }
  if (identification.candidates.some((candidate) => SLOW_HASH_REASONS[candidate.type] !== undefined)) {
    lines.push('- 带盐慢哈希（bcrypt/crypt(3)/Argon2/phpass）建议直接上 hashcat 对应模式 + 合适的字典/规则，本地小字典暴破没有意义。')
  }
  return lines.join('\n')
}

/** 渲染 crack 的 Markdown 报告。 */
function renderCrack(identification, planned, result, candidateCount) {
  const lines = []
  lines.push('## 结论')
  if (result.found) {
    const how = result.algorithm === 'plaintext' ? '明文命中，无需哈希派生' : `${result.algorithm.toUpperCase()} 命中`
    lines.push(`命中：\`${identification.normalized}\` → \`${result.plaintext}\`（${how}）。`)
  } else if (planned.algorithms.length === 0) {
    lines.push('未执行暴力破解：识别结果本地无法直接计算（带盐慢哈希，或本工具未覆盖的算法），原因见下表；识别结果建议直接交给 hashcat 对应模式。')
  } else {
    lines.push(`未命中：已尝试 ${result.attempts} 次（${planned.algorithms.join('/')} × ${candidateCount} 个候选口令），耗时 ${result.elapsedMs.toFixed(1)}ms。`)
  }
  lines.push('')

  lines.push('## 破解详情')
  const rows = [
    ['目标哈希', identification.normalized],
    ['识别类型', identification.candidates[0]?.label ?? '未识别'],
    ['尝试算法', planned.algorithms.length > 0 ? planned.algorithms.join(', ') : '（未执行）'],
    ['候选口令数', String(candidateCount)],
    ['尝试次数', String(result.attempts)],
    ['耗时', `${result.elapsedMs.toFixed(1)} ms`],
    ['结果', result.found ? `命中：${result.plaintext}` : '未命中'],
  ]
  lines.push(formatRows(rows, ['项目', '值']))
  lines.push('')

  if (planned.notes.length > 0) {
    lines.push('## 说明')
    for (const note of planned.notes) lines.push(`- ${note}`)
  }
  if (planned.skipped.length > 0) {
    lines.push('')
    lines.push('## 未尝试的格式')
    lines.push(formatRows(planned.skipped.map((item) => [item.type, item.reason]), ['类型', '不做暴破的原因']))
  }

  lines.push('')
  lines.push('## 下一步')
  const mode = identification.candidates[0]?.hashcat
  if (result.found) {
    lines.push(`- 已得到明文 \`${result.plaintext}\`；把明文按题目的包装规则（如 \`flag{...}\`）再提交。`)
  } else {
    lines.push('- 本工具的字典只覆盖内置 top200 / CTF 常见口令 + 你传入的 `wordlist`，**未命中不等于无解**。')
    lines.push(`- 建议：\`hashcat -m ${mode ?? 0} -a 0 <hash> /usr/share/wordlists/rockyou.txt\`，再加 \`-r\` 规则文件（best64 / dive）扩大覆盖。`)
    lines.push('- 也可以把题目给的提示（用户名、flag 前缀）做成 `wordlist` 内联传给本工具，命中率会明显提高。')
    lines.push('- 若哈希是带盐格式（`$...$`），必须用 hashcat 对应模式，不能拆成无盐哈希处理。')
  }
  return lines.join('\n')
}

/** 渲染 compute 的 Markdown 报告。 */
function renderCompute(value) {
  const hashes = computeAllHashes(value)
  const lines = []
  lines.push('## 结论')
  lines.push(`已对输入明文（${[...value].length} 个字符 / ${Buffer.byteLength(value, 'utf8')} 字节 UTF-8）计算 4 种哈希。`)
  lines.push('')
  lines.push('## 哈希结果')
  const rows = HASH_ALGORITHMS.map((algorithm) => [algorithm.toUpperCase(), hashes[algorithm], String(hashes[algorithm].length)])
  lines.push(formatRows(rows, ['算法', 'hex 摘要', '长度']))
  lines.push('')
  lines.push('## 复核命令')
  lines.push('```bash')
  lines.push(`echo -n '${value.replace(/'/g, `'\\''`)}' | md5sum`)
  lines.push(`echo -n '${value.replace(/'/g, `'\\''`)}' | sha1sum`)
  lines.push(`echo -n '${value.replace(/'/g, `'\\''`)}' | sha256sum`)
  lines.push(`echo -n '${value.replace(/'/g, `'\\''`)}' | sha512sum`)
  lines.push('```')
  lines.push('')
  lines.push('## 说明')
  lines.push('- `echo -n` 不会追加换行；如果题目原文带换行，请改用 `printf` 并显式补 `\\n`。')
  lines.push('- 这些是无盐哈希；带盐哈希（bcrypt/crypt(3)）每次结果不同，需要把盐一起比较。')
  return lines.join('\n')
}

/**
 * 构造 `ctf_hash` 工具定义。
 * @param {any} ctx 注册上下文（当前未使用，保持与其他工具一致的工厂签名）
 */
export function createHashTool(ctx) {
  void ctx
  return {
    name: 'ctf_hash',
    description:
      'Identify a hash string (length/prefix/charset -> MD5, NTLM, SHA1/256/512, bcrypt, crypt(3), Argon2, LDAP SSHA...), crack weak passwords with built-in small dictionaries plus inline wordlist candidates, or compute MD5/SHA1/SHA256/SHA512 for a plaintext. Offline and deterministic: no network, no external wordlists. Salted slow hashes (bcrypt/crypt/Argon2) are identified but not brute-forced.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: {
          type: 'string',
          enum: ['identify', 'crack', 'compute'],
          description: 'identify (default): classify the hash. crack: try built-in dictionaries + wordlist. compute: hash the plaintext in `value` with 4 algorithms.',
        },
        value: {
          type: 'string',
          description: 'Required. The hash string for identify/crack, or the plaintext for compute.',
        },
        algorithm: {
          type: 'string',
          enum: ['auto', 'md5', 'sha1', 'sha256', 'sha512'],
          description: 'Limit cracking to one algorithm; auto (default) derives it from the identify result.',
        },
        wordlist: {
          type: 'array',
          items: { type: 'string' },
          description: 'Inline candidate passwords to append to the built-in dictionary.',
        },
        dictionary: {
          type: 'string',
          enum: ['none', 'common', 'ctf'],
          description: 'Built-in dictionary: ctf (default, CTF-flavoured weak passwords), common (top 200), none (only inline wordlist).',
        },
      },
      required: ['value'],
    },
    output: textOutput('CTF hash'),
    async execute(args) {
      if (args !== null && args !== undefined && typeof args !== 'object') {
        return { text: '## 结论\n`ctf_hash` 需要一个对象参数（见工具 schema）。' }
      }
      const action = ['identify', 'crack', 'compute'].includes(args?.action) ? args.action : 'identify'
      const rawValue = typeof args?.value === 'string' ? args.value : ''
      if (rawValue.trim().length === 0) {
        return { text: '## 结论\n缺少 `value`：identify/crack 需要哈希串，compute 需要明文。' }
      }
      if (action === 'identify') return { text: renderIdentify(identifyHash(rawValue)) }

      if (action === 'compute') return { text: renderCompute(rawValue) }

      // crack
      const identification = identifyHash(rawValue)
      const requested = HASH_ALGORITHMS.includes(args?.algorithm) ? args.algorithm : 'auto'
      const planned = algorithmsForIdentification(identification, requested)
      const dictionary = ['none', 'common', 'ctf'].includes(args?.dictionary) ? args.dictionary : 'ctf'
      const wordlist = Array.isArray(args?.wordlist) ? args.wordlist.filter((entry) => typeof entry === 'string') : []
      const candidates = buildCandidates(dictionary, wordlist)
      if (planned.algorithms.length === 0) {
        return { text: renderCrack(identification, planned, { found: false, attempts: 0, elapsedMs: 0 }, candidates.length) }
      }
      if (candidates.length === 0) {
        return {
          text: [
            '## 结论',
            '没有候选口令：`dictionary=none` 且 `wordlist` 为空，无法尝试任何口令。',
            '',
            '## 下一步',
            '- 至少给出 `wordlist`，或把 `dictionary` 设为 `ctf`/`common`。',
          ].join('\n'),
        }
      }
      const result = crackHash(identification.normalized, planned.algorithms, candidates)
      return { text: renderCrack(identification, planned, result, candidates.length) }
    },
  }
}
