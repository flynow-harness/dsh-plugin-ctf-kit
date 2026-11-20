/* CTF 工作台 Client 半边 —— 手写，无打包器
 *
 * 加载协议：执行时调用 window.__ModuleLoader__.load({ id, factory })，
 * id 必须精确等于 package.json 的 name。factory 是懒 CJS 形态：只用 module.exports，
 * React 从宿主 module table 里取，不另装、不引 CDN。
 *
 * 本文件做两件事，都建立在 DSH 自己的 slot 契约上（与已安装的 dsh-market-sidebar 同构）：
 *
 *   1. `sidebar.panellist` 注册 id 为 `ctf` 的入口 —— 侧边栏多一个图标；
 *   2. `main` 注册同名 key —— 点图标后在主区渲染本工作台。
 *
 * 为什么面板数据放 localStorage 而不是会话日志：题板是「人记笔记」的载体，不是模型
 * 对话的投影。会话日志只保存模型看到的东西，把笔记塞进去会让 fork/replay 变脏；
 * 面板数据留在浏览器本地，工具侧完全不依赖它，二者解耦。存储失败（隐私模式、
 * 配额满）时退化为内存态，界面明确提示「本次不持久」。
 */
window.__ModuleLoader__.load({
  id: '@local/ctf-kit',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    /** 字典命名空间。与 java-engineer / market-sidebar 的做法一致：扁平 key → 字符串。 */
    const NS = 'ctfKit'

    /** 侧边栏入口 id 同时是 `main` 面板的 key —— 这是 sidebar.panellist 的契约。 */
    const PANEL_ID = 'ctf'

    /** 内置「插件」order 0、「任务监控」order 60，取 40 落在它们之间。 */
    const ORDER = 40

    /** 题板持久化键：带版本号，改结构时可以整体失效而不是崩在半路。 */
    const STORAGE_KEY = 'ctf-kit:v1:board'

    const ZH = {
      nav: 'CTF 工作台',
      title: 'CTF 工作台',
      subtitle: '题板 · 速测 · 速查。工具在对话里由模型调用，这里管人的部分。',
      tabBoard: '题板',
      tabQuick: '速测',
      tabCheat: '速查',
      newChallenge: '新建题目',
      emptyBoard: '题板还是空的。',
      emptyBoardHint: '点「新建题目」记下第一道题：标题、分类、状态、Flag 和随手笔记都会存在本机浏览器里。',
      untitled: '未命名题目',
      fieldFlag: 'Flag',
      fieldNote: '笔记 / 思路',
      fieldCategory: '分类',
      flagPlaceholder: 'flag{...}',
      notePlaceholder: '考点、尝试过的方向、卡住的地方…',
      statusTodo: '未解',
      statusStuck: '卡住',
      statusSolved: '已解',
      catMisc: 'Misc',
      catCrypto: 'Crypto',
      catForensics: 'Forensics',
      catWeb: 'Web',
      catPwn: 'Pwn',
      catOsint: 'OSINT',
      catOther: '其他',
      delete: '删除',
      copy: '复制',
      copied: '已复制',
      copyFailed: '复制失败，请手动选中',
      statTotal: '共 {n} 题',
      statSolved: '已解 {n} 题',
      boardLocalNote: '题板存在本机浏览器（localStorage），不写入会话日志。',
      boardMemoryNote: '当前环境无法写入 localStorage，题板只存在内存里，刷新即丢。',
      quickInput: '输入',
      quickOutput: '输出',
      quickOp: '操作',
      quickHint: '纯浏览器本地计算，不会发给模型；适合随手试一层编码再用工具做深挖。',
      quickEmpty: '在上面输入内容，这里实时出结果。',
      quickError: '这条输入按该方式解不开：{msg}',
      opB64Decode: 'Base64 解码',
      opB64Encode: 'Base64 编码',
      opB64UrlDecode: 'Base64URL 解码',
      opHexDecode: 'Hex 解码',
      opHexEncode: 'Hex 编码',
      opUrlDecode: 'URL 解码',
      opUrlEncode: 'URL 编码',
      opRot13: 'ROT13',
      opCaesarBrute: '凯撒暴力（26 组）',
      opBinaryDecode: '二进制解码',
      opMorseDecode: '摩斯解码',
      opReverse: '反转字符串',
      caesarLine: 'shift {n}',
      cheatIntro: '解题时最常翻的几页。命令按需复制。',
      cheatMagic: '常见文件头',
      cheatHash: '哈希识别与 hashcat 模式',
      cheatJwt: 'JWT 速查',
      cheatPwn: 'Pwn / pwntools 速查',
      cheatMore: '更多用工具做',
      cheatMoreBody: '- 未知字符串先 ctf_codec auto\n- 古典密码先 ctf_cipher bruteforce\n- 拿到文件先 ctf_file\n- PNG 可疑先 ctf_stego info，再 lsb\n- 32 位 hex 先 ctf_hash crack\n- JWT 先 ctf_jwt attack',
      copyFailedShort: '复制失败',
      ariaStatus: '切换状态',
      ariaDelete: '删除此题',
      ariaExpand: '展开或收起',
    }

    const EN = {
      nav: 'CTF workbench',
      title: 'CTF workbench',
      subtitle: 'Board, quick decode, cheat sheet. The tools run from chat; this panel keeps the human side.',
      tabBoard: 'Board',
      tabQuick: 'Quick decode',
      tabCheat: 'Cheat sheet',
      newChallenge: 'New challenge',
      emptyBoard: 'The board is empty.',
      emptyBoardHint: 'Pick "New challenge" to record the first one: title, category, status, flag and notes stay in this browser.',
      untitled: 'Untitled challenge',
      fieldFlag: 'Flag',
      fieldNote: 'Notes',
      fieldCategory: 'Category',
      flagPlaceholder: 'flag{...}',
      notePlaceholder: 'Category tricks, attempted paths, where it got stuck…',
      statusTodo: 'Todo',
      statusStuck: 'Stuck',
      statusSolved: 'Solved',
      catMisc: 'Misc',
      catCrypto: 'Crypto',
      catForensics: 'Forensics',
      catWeb: 'Web',
      catPwn: 'Pwn',
      catOsint: 'OSINT',
      catOther: 'Other',
      delete: 'Delete',
      copy: 'Copy',
      copied: 'Copied',
      copyFailed: 'Copy failed; select it manually',
      statTotal: '{n} total',
      statSolved: '{n} solved',
      boardLocalNote: 'The board lives in this browser (localStorage) and is not written to the session log.',
      boardMemoryNote: 'localStorage is unavailable here, so the board lives in memory and is lost on reload.',
      quickInput: 'Input',
      quickOutput: 'Output',
      quickOp: 'Operation',
      quickHint: 'Computed locally in the browser and never sent to the model; useful for one quick layer before the deeper tools.',
      quickEmpty: 'Type above and the result appears here.',
      quickError: 'That input cannot be decoded this way: {msg}',
      opB64Decode: 'Base64 decode',
      opB64Encode: 'Base64 encode',
      opB64UrlDecode: 'Base64URL decode',
      opHexDecode: 'Hex decode',
      opHexEncode: 'Hex encode',
      opUrlDecode: 'URL decode',
      opUrlEncode: 'URL encode',
      opRot13: 'ROT13',
      opCaesarBrute: 'Caesar brute force (26)',
      opBinaryDecode: 'Binary decode',
      opMorseDecode: 'Morse decode',
      opReverse: 'Reverse string',
      caesarLine: 'shift {n}',
      cheatIntro: 'The pages worth keeping open during a CTF. Copy the command you need.',
      cheatMagic: 'Common file headers',
      cheatHash: 'Hash identification and hashcat modes',
      cheatJwt: 'JWT quick reference',
      cheatPwn: 'Pwn / pwntools quick reference',
      cheatMore: 'Reach for the tools instead',
      cheatMoreBody: '- Unknown string: ctf_codec auto\n- Classical cipher: ctf_cipher bruteforce\n- Any file: ctf_file\n- Suspicious PNG: ctf_stego info, then lsb\n- 32 hex chars: ctf_hash crack\n- JWT: ctf_jwt attack',
      copyFailedShort: 'Copy failed',
      ariaStatus: 'Cycle status',
      ariaDelete: 'Delete this challenge',
      ariaExpand: 'Expand or collapse',
    }

    const CATEGORIES = [
      { id: 'misc', key: 'catMisc' },
      { id: 'crypto', key: 'catCrypto' },
      { id: 'forensics', key: 'catForensics' },
      { id: 'web', key: 'catWeb' },
      { id: 'pwn', key: 'catPwn' },
      { id: 'osint', key: 'catOsint' },
      { id: 'other', key: 'catOther' },
    ]

    const STATUSES = [
      { id: 'todo', key: 'statusTodo' },
      { id: 'stuck', key: 'statusStuck' },
      { id: 'solved', key: 'statusSolved' },
    ]

    /** 全部颜色走宿主 theme token：token 改名只会让外观退化，不会让面板白屏。 */
    const CSS = `
.ctfk{display:flex;flex-direction:column;height:100%;min-height:0;min-width:0;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font-size:13px;line-height:1.5}
.ctfk *{box-sizing:border-box}
.ctfk__head{padding:16px 20px 10px;border-bottom:1px solid var(--dsw-alias-border-l1);display:flex;flex-direction:column;gap:4px}
.ctfk__titleRow{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.ctfk__title{margin:0;font-size:15px;font-weight:600;color:var(--dsw-alias-label-primary)}
.ctfk__stat{font-size:12px;color:var(--dsw-alias-label-secondary);border:1px solid var(--dsw-alias-border-l1);border-radius:999px;padding:1px 8px}
.ctfk__stat--solved{color:var(--dsw-alias-state-success-primary);border-color:var(--dsw-alias-state-success-primary)}
.ctfk__sub{margin:0;font-size:12px;color:var(--dsw-alias-label-secondary)}
.ctfk__tabs{display:flex;gap:4px;padding:8px 20px 0;border-bottom:1px solid var(--dsw-alias-border-l1)}
.ctfk__tab{appearance:none;border:none;background:none;color:var(--dsw-alias-label-secondary);font:inherit;font-size:13px;padding:6px 10px;cursor:pointer;border-bottom:2px solid transparent;border-radius:6px 6px 0 0}
.ctfk__tab:hover{color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-layer-1)}
.ctfk__tab[aria-selected="true"]{color:var(--dsw-alias-brand-primary);border-bottom-color:var(--dsw-alias-brand-primary);font-weight:600}
.ctfk__tab:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:-2px}
.ctfk__body{flex:1;min-height:0;overflow:auto;padding:16px 20px 28px;display:flex;flex-direction:column;gap:12px}
.ctfk__toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.ctfk__note{font-size:12px;color:var(--dsw-alias-label-secondary);margin:0}
.ctfk__btn{appearance:none;border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);border-radius:6px;padding:4px 10px;font:inherit;font-size:12px;cursor:pointer;white-space:nowrap}
.ctfk__btn:hover{border-color:var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-2)}
.ctfk__btn:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:1px}
.ctfk__btn--primary{border-color:var(--dsw-alias-brand-primary);color:var(--dsw-alias-brand-primary)}
.ctfk__btn--danger{border-color:var(--dsw-alias-border-l1);color:var(--dsw-alias-state-error-primary)}
.ctfk__btn--danger:hover{border-color:var(--dsw-alias-state-error-primary)}
.ctfk__empty{border:1px dashed var(--dsw-alias-border-l2);border-radius:10px;padding:20px;color:var(--dsw-alias-label-secondary);display:flex;flex-direction:column;gap:6px}
.ctfk__empty strong{color:var(--dsw-alias-label-primary);font-weight:600}
.ctfk__card{border:1px solid var(--dsw-alias-border-l1);border-radius:10px;background:var(--dsw-alias-bg-layer-1);display:flex;flex-direction:column;min-width:0}
.ctfk__card--solved{border-color:var(--dsw-alias-state-success-primary)}
.ctfk__cardHead{display:flex;align-items:center;gap:8px;padding:8px 10px;flex-wrap:wrap}
.ctfk__dot{appearance:none;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-base);width:16px;height:16px;border-radius:50%;cursor:pointer;flex:0 0 auto;padding:0}
.ctfk__dot--todo{border-color:var(--dsw-alias-state-idle-primary)}
.ctfk__dot--stuck{border-color:var(--dsw-alias-state-warn-primary);background:var(--dsw-alias-state-warn-primary)}
.ctfk__dot--solved{border-color:var(--dsw-alias-state-success-primary);background:var(--dsw-alias-state-success-primary)}
.ctfk__input,.ctfk__select,.ctfk__textarea{background:var(--dsw-alias-bg-base);border:1px solid var(--dsw-alias-border-l1);border-radius:6px;color:var(--dsw-alias-label-primary);font:inherit;font-size:13px;padding:4px 8px;min-width:0}
.ctfk__input:focus-visible,.ctfk__select:focus-visible,.ctfk__textarea:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:1px}
.ctfk__input--title{flex:1 1 200px;font-weight:600}
.ctfk__select{flex:0 0 auto}
.ctfk__textarea{resize:vertical;min-height:64px;width:100%;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.ctfk__cardBody{display:flex;flex-direction:column;gap:8px;padding:0 10px 10px;border-top:1px solid var(--dsw-alias-border-l1);margin-top:2px;padding-top:10px}
.ctfk__field{display:flex;flex-direction:column;gap:4px}
.ctfk__label{font-size:12px;color:var(--dsw-alias-label-secondary)}
.ctfk__flagRow{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.ctfk__mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.ctfk__flagRow .ctfk__input{flex:1 1 220px}
.ctfk__pre{margin:0;padding:10px;border-radius:8px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-word;max-height:340px;overflow:auto}
.ctfk__row{display:flex;gap:8px;align-items:flex-start;flex-wrap:wrap}
.ctfk__col{display:flex;flex-direction:column;gap:6px;flex:1 1 260px;min-width:0}
.ctfk__status{font-size:12px;color:var(--dsw-alias-label-secondary);min-height:16px}
.ctfk__status--ok{color:var(--dsw-alias-state-success-primary)}
.ctfk__status--warn{color:var(--dsw-alias-state-warn-primary)}
.ctfk__cheat{display:flex;flex-direction:column;gap:14px;max-width:900px}
.ctfk__cheat h3{margin:0 0 4px;font-size:13px;font-weight:600;color:var(--dsw-alias-label-primary)}
.ctfk__cheatSection{display:flex;flex-direction:column;gap:6px}
`

    /* ------------------------------------------------------------------ *
     * 浏览器侧的纯函数：速测页用。
     * 这些刻意不复用 Host 侧的 ctf/*.js —— 那是 Node 模块，进不了浏览器 bundle，
     * 而这里只需要最常用的几层，重复几十行比引一套桥接便宜。
     * ------------------------------------------------------------------ */

    function toBytesFromBinaryString(binary) {
      const out = new Uint8Array(binary.length)
      for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i) & 0xff
      return out
    }

    function decodeBytes(bytes) {
      try {
        return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
      } catch {
        return String.fromCharCode(...bytes)
      }
    }

    /** 宽容的 Base64：去空白、容忍 URL 安全字符、自动补 padding。 */
    function base64ToBytes(text, urlSafe) {
      let cleaned = String(text).replace(/[\s\r\n]+/g, '')
      if (urlSafe === true || /[-_]/.test(cleaned)) cleaned = cleaned.replace(/-/g, '+').replace(/_/g, '/')
      const remainder = cleaned.length % 4
      if (remainder === 2) cleaned += '=='
      else if (remainder === 3) cleaned += '='
      else if (remainder === 1) throw new Error('length is not valid base64')
      return toBytesFromBinaryString(atob(cleaned))
    }

    function bytesToBase64(bytes, urlSafe) {
      let binary = ''
      for (const byte of bytes) binary += String.fromCharCode(byte)
      const encoded = btoa(binary)
      return urlSafe === true ? encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '') : encoded
    }

    const MORSE_TABLE = {
      '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
      '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
      '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
      '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
      '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
      '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
      '---..': '8', '----.': '9', '..--..': '?', '.-.-.-': '.', '--..--': ',',
    }

    function decodeMorse(text) {
      const normalized = String(text).replace(/[·•]/g, '.').replace(/[−–—]/g, '-').replace(/_/g, '-')
      return normalized
        .trim()
        .split(/\s{2,}|\s*\/\s*|\s*\|\s*/)
        .map((word) => word.trim().split(/\s+/).filter(Boolean)
          .map((code) => MORSE_TABLE[code] ?? `?${code}?`)
          .join(''))
        .join(' ')
    }

    function decodeBinary(text) {
      const cleaned = String(text).replace(/[\s,;]+/g, '')
      if (cleaned.length === 0) return ''
      if (!/^[01]+$/.test(cleaned)) throw new Error('only 0 and 1 allowed')
      const padded = cleaned.length % 8 === 0 ? cleaned : cleaned.padEnd(cleaned.length + (8 - (cleaned.length % 8)), '0')
      const bytes = new Uint8Array(padded.length / 8)
      for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(padded.slice(i * 8, i * 8 + 8), 2)
      return decodeBytes(bytes)
    }

    function shiftLetters(text, shift) {
      return String(text).replace(/[a-zA-Z]/g, (char) => {
        const base = char <= 'Z' ? 65 : 97
        const offset = (char.charCodeAt(0) - base + shift + 26) % 26
        return String.fromCharCode(base + offset)
      })
    }

    function textToBytes(text) {
      return new TextEncoder().encode(String(text))
    }

    /** 速测页的操作表。每项都可能在输入非法时抛错，由 runOp 统一兜住。 */
    function buildOps(t) {
      return [
        { id: 'b64decode', label: t('opB64Decode'), run: (text) => decodeBytes(base64ToBytes(text, false)) },
        { id: 'b64encode', label: t('opB64Encode'), run: (text) => bytesToBase64(textToBytes(text), false) },
        { id: 'b64urldecode', label: t('opB64UrlDecode'), run: (text) => decodeBytes(base64ToBytes(text, true)) },
        { id: 'hexdecode', label: t('opHexDecode'), run: decodeHexToText },
        { id: 'hexencode', label: t('opHexEncode'), run: textToHex },
        { id: 'urldecode', label: t('opUrlDecode'), run: (text) => decodeURIComponent(String(text)) },
        { id: 'urlencode', label: t('opUrlEncode'), run: (text) => encodeURIComponent(String(text)) },
        { id: 'rot13', label: t('opRot13'), run: (text) => shiftLetters(text, 13) },
        { id: 'caesarbrute', label: t('opCaesarBrute'), run: null },
        { id: 'binarydecode', label: t('opBinaryDecode'), run: decodeBinary },
        { id: 'morsedecode', label: t('opMorseDecode'), run: decodeMorse },
        { id: 'reverse', label: t('opReverse'), run: (text) => [...String(text)].reverse().join('') },
      ]
    }

    function decodeHexToText(text) {
      const cleaned = String(text).replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[\s,;:_-]/g, '')
      if (cleaned.length === 0) return ''
      if (!/^[0-9a-fA-F]+$/.test(cleaned)) throw new Error('not hex')
      if (cleaned.length % 2 !== 0) throw new Error('odd number of hex digits')
      const bytes = new Uint8Array(cleaned.length / 2)
      for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(cleaned.slice(i * 2, i * 2 + 2), 16)
      return decodeBytes(bytes)
    }

    function textToHex(text) {
      return [...textToBytes(text)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
    }

    function runQuickOp(op, text, t) {
      if (op === null || op === undefined) return ''
      if (op.run !== null) return op.run(text)
      // 凯撒暴力：全 26 组，把能命中 flag 形状的行顶到前面。
      const lines = []
      for (let shift = 0; shift < 26; shift += 1) {
        const decoded = shiftLetters(text, shift)
        const marker = /(?:flag|ctf|key)\s*\{/i.test(decoded) ? '  <-- flag?' : ''
        lines.push(`${t('caesarLine').replace('{n}', String(shift))}: ${decoded}${marker}`)
      }
      return lines.join('\n')
    }

    /* ------------------------------------------------------------------ *
     * 题板存储：localStorage 失败时退化为内存态，并把「不持久」如实告诉用户。
     * ------------------------------------------------------------------ */

    function makeId() {
      return `c${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`
    }

    function sanitizeChallenge(raw) {
      if (raw === null || typeof raw !== 'object') return undefined
      const title = typeof raw.title === 'string' ? raw.title.slice(0, 200) : ''
      const category = CATEGORIES.some((item) => item.id === raw.category) ? raw.category : 'misc'
      const status = STATUSES.some((item) => item.id === raw.status) ? raw.status : 'todo'
      return {
        id: typeof raw.id === 'string' && raw.id.length > 0 ? raw.id : makeId(),
        title,
        category,
        status,
        flag: typeof raw.flag === 'string' ? raw.flag.slice(0, 500) : '',
        note: typeof raw.note === 'string' ? raw.note.slice(0, 20000) : '',
      }
    }

    function loadBoard() {
      const empty = { challenges: [], persistent: true }
      try {
        if (typeof window === 'undefined' || window.localStorage === undefined) return { ...empty, persistent: false }
        const raw = window.localStorage.getItem(STORAGE_KEY)
        if (raw === null) return empty
        const parsed = JSON.parse(raw)
        const list = Array.isArray(parsed?.challenges) ? parsed.challenges : []
        return {
          challenges: list.map(sanitizeChallenge).filter((item) => item !== undefined),
          persistent: true,
        }
      } catch {
        return { ...empty, persistent: false }
      }
    }

    function saveBoard(challenges) {
      try {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ challenges }))
        return true
      } catch {
        return false
      }
    }

    /** 复制文本，返回是否成功；剪贴板 API 不可用时回退到 execCommand。 */
    async function copyText(text) {
      try {
        if (navigator?.clipboard?.writeText !== undefined) {
          await navigator.clipboard.writeText(String(text))
          return true
        }
      } catch {
        // 继续走回退路径。
      }
      try {
        const area = document.createElement('textarea')
        area.value = String(text)
        area.setAttribute('readonly', '')
        area.style.position = 'fixed'
        area.style.opacity = '0'
        document.body.appendChild(area)
        area.select()
        const ok = document.execCommand('copy')
        area.remove()
        return ok
      } catch {
        return false
      }
    }

    /* ------------------------------------------------------------------ *
     * 组件
     * ------------------------------------------------------------------ */

    /** 侧边栏图标。只画几何，颜色跟随宿主 token / currentColor。 */
    function CtfIcon(props) {
      const size = props !== null && props !== undefined && typeof props.size === 'number' ? props.size : 18
      const active = props !== null && props !== undefined && props.active === true
      const accent = active ? 'var(--dsw-alias-brand-primary)' : 'currentColor'
      return h('svg', {
        width: size,
        height: size,
        viewBox: '0 0 20 20',
        fill: 'none',
        xmlns: 'http://www.w3.org/2000/svg',
        'aria-hidden': 'true',
        style: { display: 'block', flex: '0 0 auto' },
      },
      h('path', {
        d: 'M4.5 3v14',
        stroke: 'currentColor',
        'stroke-width': 1.7,
        'stroke-linecap': 'round',
      }),
      h('path', {
        d: 'M4.5 3.8c2.2-1.2 4.1 1 6.3-.1.7-.35 1.3-.6 2-.75v4.6c-.7.15-1.3.4-2 .75-2.2 1.1-4.1-1.1-6.3.1z',
        fill: accent,
      }),
      h('path', {
        d: 'M8 17h3.5',
        stroke: accent,
        'stroke-width': 1.6,
        'stroke-linecap': 'round',
      }),
      h('path', {
        d: 'M13.2 17h3.3',
        stroke: accent,
        'stroke-width': 1.6,
        'stroke-linecap': 'round',
        'stroke-dasharray': '1.2 1.8',
      }))
    }

    function CopyButton(props) {
      const [state, setState] = React.useState('idle')
      const { text, t, label } = props
      React.useEffect(() => {
        if (state === 'idle') return undefined
        const timer = setTimeout(() => setState('idle'), 1800)
        return () => clearTimeout(timer)
      }, [state])
      const caption = state === 'ok'
        ? t('copied')
        : state === 'fail' ? t('copyFailedShort') : (label ?? t('copy'))
      return h('button', {
        type: 'button',
        className: 'ctfk__btn',
        onClick: async () => {
          const ok = await copyText(text)
          setState(ok ? 'ok' : 'fail')
        },
      }, caption)
    }

    function BoardTab(props) {
      const { t, initialChallenges, persistent, onPersistentChange } = props
      const [challenges, setChallenges] = React.useState(initialChallenges)
      const [expandedId, setExpandedId] = React.useState(null)

      const update = React.useCallback((id, patch) => {
        setChallenges((current) => current.map((item) => (item.id === id ? { ...item, ...patch } : item)))
      }, [])

      const remove = React.useCallback((id) => {
        setChallenges((current) => current.filter((item) => item.id !== id))
        setExpandedId((current) => (current === id ? null : current))
      }, [])

      const add = React.useCallback(() => {
        const created = { id: makeId(), title: '', category: 'misc', status: 'todo', flag: '', note: '' }
        setChallenges((current) => [created, ...current])
        setExpandedId(created.id)
      }, [])

      // 每次变更落盘；写不进去就标记为非持久（隐私模式、配额满）。
      React.useEffect(() => {
        const ok = saveBoard(challenges)
        if (ok !== persistent) onPersistentChange(ok)
      }, [challenges, persistent, onPersistentChange])

      const solved = challenges.filter((item) => item.status === 'solved').length

      return h('div', { className: 'ctfk__body' },
        h('div', { className: 'ctfk__toolbar' },
          h('button', { type: 'button', className: 'ctfk__btn ctfk__btn--primary', onClick: add }, t('newChallenge')),
          h('span', { className: 'ctfk__stat' }, t('statTotal').replace('{n}', String(challenges.length))),
          h('span', { className: 'ctfk__stat ctfk__stat--solved' }, t('statSolved').replace('{n}', String(solved))),
        ),
        h('p', { className: 'ctfk__note' }, persistent ? t('boardLocalNote') : t('boardMemoryNote')),
        challenges.length === 0
          ? h('div', { className: 'ctfk__empty' },
            h('strong', null, t('emptyBoard')),
            h('span', null, t('emptyBoardHint')))
          : challenges.map((item) => {
            const statusIndex = STATUSES.findIndex((entry) => entry.id === item.status)
            const statusMeta = STATUSES[statusIndex < 0 ? 0 : statusIndex]
            const statusLabel = t(statusMeta.key)
            const expanded = expandedId === item.id
            return h('section', {
              key: item.id,
              className: `ctfk__card${item.status === 'solved' ? ' ctfk__card--solved' : ''}`,
            },
            h('div', { className: 'ctfk__cardHead' },
              h('button', {
                type: 'button',
                className: `ctfk__dot ctfk__dot--${item.status}`,
                title: `${t('ariaStatus')}: ${statusLabel}`,
                'aria-label': `${t('ariaStatus')}: ${statusLabel}`,
                onClick: () => {
                  const next = STATUSES[(statusIndex + 1 + STATUSES.length) % STATUSES.length]
                  update(item.id, { status: next.id })
                },
              }),
              h('input', {
                className: 'ctfk__input ctfk__input--title',
                value: item.title,
                placeholder: t('untitled'),
                'aria-label': t('untitled'),
                onChange: (event) => update(item.id, { title: event.target.value }),
              }),
              h('select', {
                className: 'ctfk__select',
                value: item.category,
                'aria-label': t('fieldCategory'),
                onChange: (event) => update(item.id, { category: event.target.value }),
              }, CATEGORIES.map((entry) => h('option', { key: entry.id, value: entry.id }, t(entry.key)))),
              h('span', { className: 'ctfk__note' }, statusLabel),
              h('button', {
                type: 'button',
                className: 'ctfk__btn',
                'aria-expanded': expanded ? 'true' : 'false',
                title: t('ariaExpand'),
                onClick: () => setExpandedId(expanded ? null : item.id),
              }, expanded ? '▾' : '▸'),
              h('button', {
                type: 'button',
                className: 'ctfk__btn ctfk__btn--danger',
                title: t('ariaDelete'),
                onClick: () => remove(item.id),
              }, '×'),
            ),
            expanded ? h('div', { className: 'ctfk__cardBody' },
              h('div', { className: 'ctfk__field' },
                h('span', { className: 'ctfk__label' }, t('fieldFlag')),
                h('div', { className: 'ctfk__flagRow' },
                  h('input', {
                    className: 'ctfk__input ctfk__mono',
                    value: item.flag,
                    placeholder: t('flagPlaceholder'),
                    'aria-label': t('fieldFlag'),
                    onChange: (event) => update(item.id, { flag: event.target.value }),
                  }),
                  h(CopyButton, { text: item.flag, t }),
                ),
              ),
              h('div', { className: 'ctfk__field' },
                h('span', { className: 'ctfk__label' }, t('fieldNote')),
                h('textarea', {
                  className: 'ctfk__textarea',
                  value: item.note,
                  placeholder: t('notePlaceholder'),
                  'aria-label': t('fieldNote'),
                  onChange: (event) => update(item.id, { note: event.target.value }),
                }),
              ),
            ) : null,
            )
          }),
      )
    }

    function QuickTab(props) {
      const { t } = props
      const [operationId, setOperationId] = React.useState('b64decode')
      const [input, setInput] = React.useState('')
      const ops = React.useMemo(() => buildOps(t), [t])
      const operation = ops.find((entry) => entry.id === operationId) ?? ops[0]
      const output = React.useMemo(() => {
        if (input.length === 0) return { kind: 'empty' }
        try {
          return { kind: 'ok', text: runQuickOp(operation, input, t) }
        } catch (error) {
          return { kind: 'error', text: t('quickError').replace('{msg}', String(error?.message ?? error)) }
        }
      }, [input, operation, t])

      return h('div', { className: 'ctfk__body' },
        h('p', { className: 'ctfk__note' }, t('quickHint')),
        h('div', { className: 'ctfk__row' },
          h('div', { className: 'ctfk__col' },
            h('span', { className: 'ctfk__label' }, t('quickOp')),
            h('select', {
              className: 'ctfk__select',
              value: operationId,
              'aria-label': t('quickOp'),
              onChange: (event) => setOperationId(event.target.value),
            }, ops.map((entry) => h('option', { key: entry.id, value: entry.id }, entry.label))),
            h('span', { className: 'ctfk__label' }, t('quickInput')),
            h('textarea', {
              className: 'ctfk__textarea',
              value: input,
              spellCheck: false,
              'aria-label': t('quickInput'),
              onChange: (event) => setInput(event.target.value),
            }),
          ),
          h('div', { className: 'ctfk__col' },
            h('div', { className: 'ctfk__toolbar' },
              h('span', { className: 'ctfk__label' }, t('quickOutput')),
              output.kind === 'ok' ? h(CopyButton, { text: output.text, t }) : null,
            ),
            h('pre', {
              className: 'ctfk__pre',
              'aria-live': 'polite',
            }, output.kind === 'empty' ? t('quickEmpty') : output.text),
          ),
        ),
      )
    }

    function cheatSections(t) {
      return [
        {
          title: t('cheatMagic'),
          body: [
            '89 50 4E 47 0D 0A 1A 0A   PNG',
            'FF D8 FF                  JPEG',
            '47 49 46 38 39 61         GIF89a',
            '25 50 44 46 2D            %PDF-',
            '50 4B 03 04               ZIP / jar / docx / apk',
            '1F 8B                     gzip',
            '37 7A BC AF 27 1C         7z',
            '52 61 72 21 1A 07          RAR',
            '7F 45 4C 46               ELF',
            '4D 5A                     MZ / PE',
            '53 51 4C 69 74 65 20 66    SQLite format 3',
            '00 61 73 6D                wasm',
            'CA FE BA BE               Java class / Mach-O fat',
            '25 21 50 53                  PostScript',
          ].join('\n'),
        },
        {
          title: t('cheatHash'),
          body: [
            '32 hex   MD5 (-m 0) / NTLM (-m 1000) / MD4 (-m 900)',
            '40 hex   SHA1 (-m 100) / MySQL4.1 (-m 300)',
            '56 hex   SHA224 (-m 1300)',
            '64 hex   SHA256 (-m 1400)',
            '96 hex   SHA384 (-m 1700)',
            '128 hex  SHA512 (-m 1700 for sha512)',
            '$1$      md5crypt (-m 500)',
            '$2a$ $2b$ $2y$  bcrypt (-m 3200)',
            '$5$      sha256crypt (-m 7400)',
            '$6$      sha512crypt (-m 1800)',
            '$apr1$   Apache MD5 (-m 1600)',
            '{SSHA}   LDAP SSHA (-m 111)',
            'hashcat -m <mode> hash.txt rockyou.txt',
          ].join('\n'),
        },
        {
          title: t('cheatJwt'),
          body: [
            '# 拆解',
            'python3 -c "import jwt,sys;print(jwt.decode(sys.argv[1],options={\'verify_signature\':False}))" <token>',
            '',
            '# 弱密钥爆破',
            'hashcat -m 16500 jwt.txt rockyou.txt',
            '',
            '# alg=none 绕过',
            'header  {"alg":"none","typ":"JWT"}',
            'token   b64url(header) + "." + b64url(payload) + "."',
            '',
            '# 常见坑：服务端只验签名不验 alg，或密钥来自环境变量默认值',
          ].join('\n'),
        },
        {
          title: t('cheatPwn'),
          body: [
            'from pwn import *',
            'context.arch = "amd64"',
            'p = process("./chall")           # 或 remote("host", 1337)',
            '',
            'cyclic(100)                      # 定位溢出偏移',
            'cyclic_find(0x6161616c)          # 偏移',
            'offset = cyclic_find(p64(lea...))',
            '',
            'payload  = flat(b"A"*offset, p64(pop_rdi), p64(binsh), p64(ret), p64(system))',
            '',
            'ROPgadget --binary ./chall | grep "pop rdi"',
            'one_gadget /lib/x86_64-linux-gnu/libc.so.6',
            '',
            '# 保护检查',
            'checksec --file=./chall',
          ].join('\n'),
        },
        {
          title: t('cheatMore'),
          body: t('cheatMoreBody'),
        },
      ]
    }

    function CheatTab(props) {
      const { t } = props
      const sections = React.useMemo(() => cheatSections(t), [t])
      return h('div', { className: 'ctfk__body' },
        h('p', { className: 'ctfk__note' }, t('cheatIntro')),
        h('div', { className: 'ctfk__cheat' }, sections.map((section) => h('section', {
          key: section.title,
          className: 'ctfk__cheatSection',
        },
        h('div', { className: 'ctfk__toolbar' },
          h('h3', null, section.title),
          h(CopyButton, { text: section.body, t }),
        ),
        h('pre', { className: 'ctfk__pre' }, section.body),
        ))),
      )
    }

    /** 工作台主组件。`t` 与 `localeApi` 由 apply 闭包注入，不依赖 slot 的注入座位。 */
    function CtfWorkbench(props) {
      const { t, localeApi } = props
      const [tab, setTab] = React.useState('board')
      const [, setLocaleTick] = React.useState(0)
      const initial = React.useMemo(() => loadBoard(), [])
      const [persistent, setPersistent] = React.useState(initial.persistent)

      // 语言切换后重渲染：bound 的 t 每次调用都读当前语言，但组件不重渲染就不会重画。
      React.useEffect(() => {
        if (localeApi === null || localeApi === undefined || typeof localeApi.subscribe !== 'function') return undefined
        return localeApi.subscribe(() => setLocaleTick((tick) => tick + 1))
      }, [localeApi])

      const tabs = [
        { id: 'board', label: t('tabBoard') },
        { id: 'quick', label: t('tabQuick') },
        { id: 'cheat', label: t('tabCheat') },
      ]

      return h('div', { className: 'ctfk' },
        h('style', null, CSS),
        h('div', { className: 'ctfk__head' },
          h('div', { className: 'ctfk__titleRow' },
            h('h2', { className: 'ctfk__title' }, t('title')),
          ),
          h('p', { className: 'ctfk__sub' }, t('subtitle')),
        ),
        h('div', { className: 'ctfk__tabs', role: 'tablist' },
          tabs.map((entry) => h('button', {
            key: entry.id,
            type: 'button',
            role: 'tab',
            className: 'ctfk__tab',
            'aria-selected': tab === entry.id ? 'true' : 'false',
            onClick: () => setTab(entry.id),
          }, entry.label)),
        ),
        tab === 'board' ? h(BoardTab, {
          key: 'board',
          t,
          initialChallenges: initial.challenges,
          persistent,
          onPersistentChange: setPersistent,
        }) : null,
        tab === 'quick' ? h(QuickTab, { key: 'quick', t }) : null,
        tab === 'cheat' ? h(CheatTab, { key: 'cheat', t }) : null,
      )
    }

    /** 绑定字典命名空间；注册失败时也能按当前语言退化到内置字面量。 */
    function makeTranslator(localeApi) {
      let bound
      try {
        if (localeApi !== null && localeApi !== undefined && typeof localeApi.bind === 'function') bound = localeApi.bind(NS)
      } catch {
        bound = undefined
      }
      return (key) => {
        if (bound !== undefined) {
          try {
            const value = bound(key)
            if (typeof value === 'string' && value !== key) return value
          } catch {
            // 落到内置字典。
          }
        }
        let active = 'zh'
        try {
          const snapshot = typeof localeApi?.getLocale === 'function' ? localeApi.getLocale() : undefined
          if (typeof snapshot?.active === 'string') active = snapshot.active
        } catch {
          active = 'zh'
        }
        const dict = String(active).toLowerCase().startsWith('en') ? EN : ZH
        return dict[key] ?? ZH[key] ?? key
      }
    }

    function apply(ctx) {
      let t = (key) => ZH[key] ?? key
      const localeApi = typeof ctx.get === 'function' ? ctx.get('locale') : undefined

      if (localeApi !== undefined && localeApi !== null) {
        try {
          ctx.effect(() => localeApi.register(NS, { zh: ZH, en: EN }))
        } catch (error) {
          // 双语字典注册失败不致命：makeTranslator 会退回内置字面量。
          console.warn('[ctf-kit] locale registration failed: ' + String(error?.message ?? error))
        }
        t = makeTranslator(localeApi)
      }

      const slots = ctx.slots
      // 侧边栏入口与主面板成对注册：同名 id/key 是 sidebar.panellist 的契约。
      ctx.effect(() => slots.inject('sidebar.panellist', () => slots.register({
        name: 'sidebar.panellist',
        id: PANEL_ID,
        order: ORDER,
        label: () => t('nav'),
      }, CtfIcon)))

      ctx.effect(() => slots.inject('main', () => slots.register({
        name: 'main',
        key: PANEL_ID,
      }, () => h(CtfWorkbench, { t, localeApi }))))
    }

    return {
      name: '@local/ctf-kit',
      inject: ['slots', 'locale'],
      apply,
    }
  },
})
