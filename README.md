# CTF 解题工具箱 · DeepSeek Harness 插件

给 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的 CTF 解题插件：**7 个确定性 Host 工具 + 侧边栏题板工作台**。

装好之后，侧边栏会多一个旗帜图标，点开是工作台；同时模型在对话里多出 7 个 `ctf_*` 工具，不用每次现搓一行 Python。

零第三方运行时依赖（只用 Node 内置模块与浏览器原生 API）；工具全部本地计算或只读取证，唯一会写盘的是 `ctf_file` 在显式 `extractEmbedded: true` 时释放内嵌对象。

适配 `dsh@0.2.2-alpha.2`（Desktop / Web GUI），MIT 开源。

> **English summary** — A DeepSeek Harness plugin for CTF work. Seven deterministic tools: encoding decode chains (`ctf_codec`), classical cipher brute force (`ctf_cipher`), hash identification and weak-secret checks (`ctf_hash`), single-call file triage with carving (`ctf_file`), PNG chunk/LSB steganography (`ctf_stego`), JWT dissection and forging (`ctf_jwt`), and pwn helpers for endianness, packing and cyclic offsets (`ctf_pwn`). It also adds a sidebar workbench with a per-challenge flag board, a browser-local quick codec, and a cheat sheet. No runtime dependencies; MIT licensed.

---

## 一、对话里的 7 个工具

| 工具 | 干什么 | 典型时机 |
| --- | --- | --- |
| `ctf_codec` | 解一层 / 编码 / **自动爆破解码链**（base64、base64url、base32、base16、base85、binary、decimal、octal、URL、HTML 实体、Morse、Bacon、ROT13、UUencode、quoted-printable、unicode 转义） | 拿到一段看不懂的字符串，第一个就该跑它 |
| `ctf_cipher` | 古典密码：凯撒 / ROT-N、ROT47、Atbash、栅栏、维吉尼亚、列置换、Bacon、摩斯、键盘移位；支持暴力枚举并按"可打印性"打分排序 | 明文像英文但错位、题干提到"移位/栅栏" |
| `ctf_hash` | 按长度/前缀识别哈希类型（含 hashcat `-m` 模式号），或对内置常见/CTF 小字典做校验，或算出四种哈希 | 捡到一串 32/40/64 位 hex |
| `ctf_file` | 文件取证一次到底：三种哈希、真实文件类型 vs 扩展名、内嵌对象偏移、EOF 之后追加的数据、flag 形状命中、strings 摘要、长 base64 块；`extractEmbedded` 可把内嵌对象释放到同目录 `*_extracted/` | 拿到任何附件的第一枪 |
| `ctf_stego` | PNG 体检（chunk 表、IHDR、文本 chunk、IEND 之后字节）+ 8-bit 非隔行 PNG 的 LSB 提取（可选通道/位/输出格式，自动识别 zip/gzip/文本载荷头） | 图片题、`ctf_file` 说它是 PNG |
| `ctf_jwt` | 拆 JWT（含 exp/nbf 时间判断）、验签、签发、弱密钥字典爆破 + `alg=none` 混淆手法 | Web 题里拿到 token |
| `ctf_pwn` | hexdump、整数与端序换算、p32/p64 打包成转义 shellcode、de Bruijn cyclic 生成与偏移查找、坏字符扫描 | Pwn 题里算偏移、拼 payload |

所有工具都是**纯本地计算**：不联网、不起子进程、不 attach 任何进程。唯一会写盘的是 `ctf_file` 在显式 `extractEmbedded: true` 时，往输入文件同目录的 `<basename>_extracted/` 里释放内嵌对象。

`index.js` 还会往系统提示里注入一小段工具索引（order 890），让模型在 CTF 场景优先用这些工具而不是临时 shell 拼接。

## 二、侧边栏工作台

点侧边栏的旗帜图标进入主区面板，三个页签：

- **题板** —— 一题一行：状态点（未解 → 卡住 → 已解 循环）、标题、分类、Flag（带复制）、笔记。数据存在浏览器 `localStorage`（键 `ctf-kit:v1:board`），**不写进会话日志**：题板是人的笔记本，塞进 session log 会污染 fork/replay。localStorage 不可用时退化为内存态，并在界面上如实提示。
- **速测** —— Base64 / Base64URL / Hex / URL / ROT13 / 凯撒 26 组暴力 / 二进制 / 摩斯 / 反转，输入即出结果，纯浏览器计算，不发给模型。适合先用它试一层，再用正式工具深挖。
- **速查** —— 常见文件头、哈希长度与 hashcat 模式对照、JWT 速查、pwntools 速查。

样式只用宿主 theme token（`--dsw-alias-*`），不硬编码颜色，亮/暗主题自动跟随。

## 三、安装与卸载

```bash
# 1. 克隆到任意位置（本地目录安装是链接，仓库可以就放在原地）
git clone https://github.com/flynow-harness/dsh-plugin-ctf-kit.git
```

然后在 DSH 会话里让模型执行：

```
plugin_manager  action: install_bundle  target: /绝对路径/dsh-plugin-ctf-kit
```

工具调用面板 / 设置里的「插件」页也能看到 `@local/ctf-kit`。卸载：

```
plugin_manager  action: remove_bundle  target: /绝对路径/dsh-plugin-ctf-kit
```

本仓库就是一个可直接安装的 bundle：`package.json` 声明 `dsh.bundle.patch` 与 `dsh.client`，`cordis.patch.yml` 插入一行 `ctf-kit`。

本地目录安装是**链接**而不是打包，所以改完 `client.js` 刷新页面即可生效；改 `index.js` 这类 Host 代码需要重启 DSH。

## 四、设计取舍

- **零第三方依赖。** 整个 bundle 只用 Node 内置模块和浏览器原生 API。插件装载在 DSH 进程里，一个缺失依赖会让整个 profile 起不来，CTF 里这些换算也本来不需要外部库。
- **工具输出是给人复核的证据，不是结论。** 每个工具先给结论、再给偏移/分数/候选表、最后给下一步。找不到候选时会明说"这只证明当前字典没命中"，而不是暗示"没有答案"。
- **面板与工具解耦。** 面板不调用 Host 工具、不读会话日志；工具也不知道面板存在。任一半坏掉，另一半照常工作。
- **字典是有意做小的。** `ctf_hash` 和 `ctf_jwt` 内置的是常见口令/密钥，不是 rockyou。真爆破应该交给 hashcat，工具里会直接给出对应命令。

## 五、已知边界

工具输出里都会主动写明这些限制，不会静默给结论。

**隐写与取证**
- `ctf_stego` 的 LSB 只支持 **8-bit、非隔行**、colorType 0/2/4/6 的 PNG；调色板(3)、16-bit、Adam7 隔行会返回可读的"不支持 + 原因"，不抛异常也不给错数据。
- `ctf_file` 的 gzip 流尾切分是启发式（先整体试解压，失败再从尾部逐字节回退，仅 ≤2 MiB 采样、最多 2048 次）；定位不到时会明说无法精确切分。PNG / JPEG / ZIP 的尾部判定是确定性的。
- 大于 128 MiB 的文件降级为头尾各 2 MiB 采样，报告里的 MD5/SHA1/SHA256 是**采样哈希**并显式标注。
- `ctf_file` 的 strings 只列前 60 条、Base64 长块最多 12 个、flag 每区段最多 50 条 —— 是摘要，不是全量导出。

**哈希**
- 32 位 hex 无法区分 MD5 / NTLM / MD4，只提示歧义；`crack` 只试 MD5（OpenSSL 3 已移除 MD4，Node 算不了 NTLM）。
- 带盐慢哈希（bcrypt、`$1$`、`$5$`、`$6$`、`$apr1$`、Argon2、phpass）只识别不暴破，会给出对应 hashcat `-m` 出路。
- `dictionary` 是有意做小的内置表（ctf 约 70 条 / common 200 条），命中不了就建议 hashcat + rockyou。

**编解码与密码**
- `ctf_codec` 的 `base85` 是 **ASCII85**（含 `<~ ~>` 与 `z` 缩写），不是 RFC1924 / Z85。
- `ctf_codec` 的 auto 模式是启发式：按可打印性与 flag 形状打分排序，不保证唯一正确答案排第一。
- `ctf_cipher` 的 Vigenère / 列置换**无法无密钥穷举**，bruteforce 是"用户 key + 内置常见 key 字典"的尝试，输出里写明了这一点。

**JWT 与 Pwn**
- `ctf_jwt` 的弱密钥字典约 100 条；`attack` 需要签名段本身是合法 base64url（否则会明确报错，而不是假装已爆破）。
- `ctf_pwn` 只做本地换算：不运行、不 attach、不联网。

**面板**
- 题板数据存在本机浏览器 `localStorage`：换浏览器、换机器、清站点数据都会丢；没有导入/导出，要长期留档请把 Flag 写进题解文件。
- 面板不读会话日志、不调用 Host 工具，和工具侧完全解耦。

## 六、开发与自测

```bash
cd ctf-kit
npm run check   # node --check 全部 JS
npm test        # 集成冒烟：七个工具各跑一遍典型输入
node --test test/codec.test.mjs       # 编解码/古典密码    37 例
node --test test/forensics.test.mjs   # 哈希/文件/隐写     23 例
node --test test/webpwn.test.mjs      # JWT/Pwn            28 例
```

## 七、验证记录

本目录就是交付物，已用 `plugin_manager install_bundle` 装进 `desktop` profile（`link:/Users/flynow/Desktop/ctf-kit`）。

已验证：

| 项目 | 结果 |
| --- | --- |
| `node --check`（index/client/8 个模块） | 全部通过 |
| 单元测试（3 个套件） | 88/88 通过 |
| 集成冒烟 `npm test` | 8/8 通过（七个工具各一次真实调用） |
| 会话工作目录解析 | 传入 ctx 后 `ctf_file` 能把相对路径解析到会话 cwd（已用伪造 ctx 验证） |
| 安装结果 | `application: applied`，`warnings: []`，行 `ctf-kit` 已激活 |
| Host 工具生效 | 7 个 `ctf_*` 工具已出现在模型工具表；系统提示中的工具索引段已注入 |
| Client 槽位生效 | `sidebar.panellist` 有 `@local/ctf-kit` 的 `ctf` 入口（order 40，active）；`main` 有 `ctf` key（active） |
| 展示元数据 | `list_bundles` 中可见 `@local/ctf-kit` 1.0.0，中英文 `meta.title` / `meta.description` 与 `icon.svg` 均已导出 |

**未验证**：面板的像素级外观（间距、暗色主题对比、窄窗口折行）。Web GUI 的页面加载需要 `dsh web` 打印的 token，独立浏览器打开会被 `dsh web authentication required` 拦住，因此没有截图证据。槽位 `active: true` 已经证明 client bundle 在真实页面里加载并执行了 `apply()`，但"长什么样"仍需你刷新页面后自己看一眼。

