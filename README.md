# TOTP Authenticator 插件（DSH / DeepSeek Harness 版）

基于 RFC 6238 的 TOTP 双因素认证插件，由 openclaw 技能（原 `scripts/totp.py`、`scripts/totp.js`）转换为 **DeepSeek Harness 动态 Cordis 插件**。除 TOTP 验证码生成外，还提供**关键操作防护门**（拦截递归删除文件夹等破坏性命令）和**首次使用绑定**（生成密钥 + 二维码 + 用户确认）。

## 目录结构

```
totp-authenticator/
├── harness-totp-plugin.js   # 插件唯一源码（Host 侧函数体，纯 JavaScript）
└── README.md                # 本说明文件
```

插件运行时会在此目录下生成两个本地文件（首次绑定后出现）：

| 文件 | 说明 |
| --- | --- |
| `.totp-gate.json` | 绑定状态（绑定的密钥、绑定时间），插件本地持久化 |
| `totp-gate-qrcode.svg` | 绑定用的二维码图片（扫码或手机相机识别） |

> 插件无 `fs` 服务时退化为纯内存状态（插件停止即丢失绑定）。

## 功能

### 1. `totp` — TOTP 验证码生成

| 参数 | 说明 |
| --- | --- |
| `secret`（必填） | Base32 密钥（A-Z、2-7，忽略空格/连字符/`=` 填充），或完整 `otpauth://totp/...` URI |
| `digits` | 码位数，默认 6 |
| `interval` | 时间步长（秒），默认 30（AWS MFA 等服务用 60） |
| `verify` | 可选：校验候选码，返回 PASS/FAIL |
| `time` | 可选：指定 Unix 时间戳计算（测试/复现已知向量用），默认当前时间 |

兼容 Google Authenticator、Microsoft Authenticator、Authy 等。

### 2. 关键操作防护门

通过 `tools/pre-execute` 事件在**命令执行前**拦截 `pwsh` / `bash` 的破坏性命令：

- 递归删除：`Remove-Item -Recurse`、`rm -rf/-r`、`rd /s`、`del /s`、`[IO.Directory]::Delete(x, $true)`
- 批量删除：通配符删除、管道删除（`Get-ChildItem | Remove-Item`）
- 磁盘破坏：`Format-Volume`、`Clear-Disk`、`diskpart`、`format c:`
- 其他：`git clean -f`、`git reset --hard`、`robocopy /MIR`、`find -delete`、`dd`、`mkfs`、`shred`、`sdelete`
- 豁免：`-WhatIf` 试运行不拦截

被拦截的命令不会执行；拦截提示会引导 Agent 走解锁流程。

### 3. 首次使用绑定（两步）

1. **`totp_gate_bind`**：生成新密钥 → 保存到 `.totp-gate.json` → 输出二维码（SVG 文件 + 聊天内预览）、`otpauth://` URI 和手工录入密钥 → 提示用户用 **Microsoft Authenticator 或 Google Authenticator** 扫码/手动添加。`regenerate=true` 可换新密钥重新绑定。
2. **`totp_gate_confirm(code)`**：校验用户从认证器 App 读取的 6 位验证码（±1 时间步容忍）；成功即绑定生效，防护门改用该密钥。

### 4. `totp_gate_unlock(code)` — 解锁一次关键操作

提交用户认证器 App 中的当前 6 位码；成功后 **90 秒内放行恰好一次**关键操作，用后自动重新上锁。

## 使用流程

```text
首次使用：
  1. 让 Agent 执行 totp_gate_bind
  2. 打开手机认证器 App（Microsoft/Google Authenticator）→ 添加账户 → 扫码或手动输入密钥
  3. 将 App 显示的 6 位验证码交给 Agent → totp_gate_confirm(code)

日常删除文件夹等关键操作：
  1. Agent 尝试执行 → 被防护门拦截
  2. 用户在认证器 App 中读取当前 6 位码并告诉 Agent
  3. Agent 调用 totp_gate_unlock(code)
  4. Agent 重试原命令（90 秒内，仅一次）

生成验证码（登录其他服务）：
  Agent 调用 totp(secret=...) 或 totp(secret="otpauth://...")
```

## 加载方式

动态插件是**会话级、进程内**的临时扩展（进程重启后插件本体消失，但 `.totp-gate.json` 中的绑定会保留）：

1. 将 `harness-totp-plugin.js` 头注释之后的函数体作为 `code.host` 调用 `cordis_define`
2. 用返回的 `pluginId` / `packageId` 调用 `cordis_run` 激活

停用：`cordis_stop`；永久删除：`cordis_undefine`。

## 配置常量（源码顶部）

| 常量 | 默认 | 说明 |
| --- | --- | --- |
| `GATE_DIGITS` | 6 | 门验证码位数 |
| `GATE_INTERVAL` | 30 | 时间步长（秒） |
| `GATE_WINDOW_MS` | 90000 | 解锁有效期（毫秒），一次性 |
| `GATE_ISSUER` / `GATE_LABEL` | `DSH` / `totp-gate` | otpauth URI 中的签发者/账户名 |
| `GATE_DIR` | `totp-authenticator` | 状态文件所在目录（相对会话工作区） |
| `GATED_TOOLS` / `CRITICAL_PATTERNS` | — | 被扫描的工具名与破坏性命令正则（可扩展） |

## 技术说明

- **纯 JavaScript 实现**：动态插件运行在受限 VM 沙箱中（无 Node `crypto`/`Buffer`/`require`），SHA-1、HMAC-SHA1、HOTP、Base32 乃至 **QR 码编码器**（byte 模式、纠错等级 L、版本 1–6、掩码 0、Reed-Solomon 纠错）全部内置实现，零外部依赖。
- **本地持久化**：通过 Host `fs` 服务写入会话工作区内的插件目录；路径取自 `exec.agent.session.header.cwd`（与官方文件工具同源）。
- **拦截机制**：监听 `tools/pre-execute` waterfall 事件，返回 `{ kind: 'deny', reason }` 阻断，命令不会执行。
- **已验证**：
  - TOTP 通过 RFC 6238 附录 B 全部测试向量（如 T=59 → `94287082`）与 Google 演示向量（`JBSWY3DPEHPK3PXP` @ t=0 → `282760`）
  - QR 码被 OpenCV `QRCodeDetector` 独立解码成功
  - 防护门拦截 / 解锁 / 一次性消费全流程实测通过

## 安全边界（重要）

这是**防误操作的安全联锁**，而非对抗恶意 Agent 的安全边界：Agent 拥有本插件（可停止它、读取 `.totp-gate.json` 中的密钥）。绑定密钥保存在本地文件（`.totp-gate.json`）与用户手机认证器 App 中，请勿挪作他用、勿泄露。

## 版本历史

| 版本 | 内容 |
| --- | --- |
| pkg-1 | `totp` 生成工具（RFC 6238） |
| pkg-2 | 关键操作防护门 + `totp_gate_unlock`（硬编码示例密钥） |
| pkg-3 | 首次使用绑定流程 + QR（含编码器缺陷） |
| pkg-4 | 修复 QR 填充到 RS 总数据码字数 |
| pkg-5 | 状态文件路径改为会话工作区 |
| pkg-6 | 修复 Reed-Solomon ECC（高次优先长除法）；当前版本 |
