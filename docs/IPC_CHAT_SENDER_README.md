# VS Code IPC Chat Sender

通过纯 IPC 通道向 VS Code Copilot Chat 发送消息，不依赖任何 UI 自动化（pywinauto / AHK）。

## 架构总览

```
外部脚本 (PowerShell / Python)
    │  写入 %TEMP%\vscode_chat_send_cmd_<targetPid>.json
    │  （targetPid 自动检测或 -TargetPid 指定）
    ▼
vscode-chat-sender 扩展（轮询 300ms）
    │  仅处理匹配自身 process.ppid 的命令文件
    │  读取 mode 字段决定路径：
    │
    │  ┌─ visible (默认) ─────────────────────┐
    │  │  剪贴板粘贴 → 聊天面板可见            │
    │  │  removeAllPendingRequests + submit    │
    │  └──────────────────────────────────────┘
    │
    │  ┌─ silent ─────────────────────────────┐
    │  │  LM API 直达 → 捕获 AI 响应          │
    │  │  零 UI / 零剪贴板 / 零输入框污染      │
    │  │  失败 → 报 lm_api_unavailable        │
    │  └──────────────────────────────────────┘
    │
    │  ┌─ auto ───────────────────────────────┐
    │  │  先 LM API → 失败回退剪贴板           │
    │  └──────────────────────────────────────┘
    ▼
VS Code Copilot Chat 收到消息
    │  写入 %TEMP%\vscode_chat_send_res_<targetPid>.json
    ▼
外部脚本读取结果
```

### 多实例路由

每个 VS Code 实例的扩展只监听**以自己主窗口 PID 命名的文件**（`process.ppid`），
调用方通过 `-TargetPid` 指定目标实例 PID，即可精确投递到特定 VS Code 窗口。

- 集成终端调用：自动读取 `$env:VSCODE_PID`，精确匹配当前实例。
- 外部终端调用：自动探测第一个 Code.exe 进程，或通过 `-TargetPid` 手动指定。
- 未指定且无法探测时：降级为旧版共享文件路径（`vscode_chat_send_cmd.json`），
  扩展仍以兼容模式处理。

## 文件说明

| 文件 | 用途 |
|------|------|
| `tools/test/vscode-chat-sender/package.json` | VS Code 扩展清单 |
| `tools/test/vscode-chat-sender/extension.js` | 扩展逻辑主体 |
| `tools/test/Send-IpcChatMessage.ps1` | **推荐的 PowerShell 调用脚本** |
| `tools/test/ipc_chat_sender.py` | Python 备用调用脚本 |
| `tools/test/install_ipc_chat_extension.ps1` | 一键安装/更新扩展 |

## 安装

### 前提

- VS Code >= 1.82
- GitHub Copilot 扩展已安装并登录

### 步骤

```powershell
# 1. 安装扩展到 VS Code
powershell -NoProfile -ExecutionPolicy Bypass -File "tools/test/install_ipc_chat_extension.ps1" -Force

# 2. 重新加载 VS Code 窗口（Ctrl+Shift+P → Developer: Reload Window）
```

安装后不需要重复执行。

### 更新

扩展代码修改后，重新运行安装脚本并重载 VS Code 窗口即可：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "tools/test/install_ipc_chat_extension.ps1" -Force
```

## 使用方法

### PowerShell（推荐）

```powershell
# 最基本用法
.\Send-IpcChatMessage.ps1 -Message "你的消息"

# 带 request-id（用于追踪）
.\Send-IpcChatMessage.ps1 -Message "你好" -RequestId "msg001"

# 高优先级——打断当前 AI 工作，立即发送（事件驱动票）
.\Send-IpcChatMessage.ps1 -Message "紧急事件" -Priority high

# 正常优先级——排队等待，AI 忙时不打断（状态票）
.\Send-IpcChatMessage.ps1 -Message "状态报告" -Priority normal

# JSON 格式输出（供其他脚本解析）
.\Send-IpcChatMessage.ps1 -Message "test" -JsonOutput

# 自动升级：先以 normal 发送，超时时自动用 high 重试（无人值守状态票）
.\Send-IpcChatMessage.ps1 -Message "状态报告" -Priority normal -AutoEscalate

# 自定义超时和轮询间隔（适合快速冒烟）
.\Send-IpcChatMessage.ps1 -Message "test" -TimeoutSec 10 -PollIntervalMs 100

# 长超时（适合慢速网络/RIR 查询等待）
.\Send-IpcChatMessage.ps1 -Message "慢查询" -TimeoutSec 120

# Silent 模式——LM API 直达，零 UI 干扰，捕获 AI 响应
.\Send-IpcChatMessage.ps1 -Message "例行状态" -Mode Silent -TimeoutSec 90 -JsonOutput

# Visible 模式——强制走剪贴板，消息在聊天面板可见
.\Send-IpcChatMessage.ps1 -Message "重要通知" -Mode Visible
```

**参数说明：**

| 参数 | 必填 | 说明 |
|------|------|------|
| `-Message` | 是 | 要发送的消息文本 |
| `-RequestId` | 否 | 请求标识符，会在结果中原样返回 |
| `-Priority` | 否 | `normal`（排队，默认） / `high`（打断当前，立即发送） |
| `-AutoEscalate` | 否 | 与 `-Priority normal` 配合使用：若发送超时，自动用 `high` 重试 |
| `-Mode` | 否 | 投递模式：`Visible`（剪贴板，聊天面板可见，默认）/ `Silent`（LM API，捕获 AI 响应）/ `Auto`（优先 LM API，回退剪贴板） |
| `-Model` | 否 | 指定 LM API 使用的模型名称或 ID（Silent/Auto 模式），如 `DeepSeek V4 Flash`、`GPT-5.5`、`auto`。留空使用默认选择逻辑 |
| `-ModelOptions` | 否 | 模型特定选项哈希表，原样传给 LM API 的 modelOptions。用于配置思考模式、Thinking Effort、上下文大小等。示例：`@{ thinking_effort = "high" }` |
| `-DiscoverModels` | 否 | 列出所有可用 LM 模型及其元数据（name/vendor/id/family/version/maxInputTokens），不发送消息。默认表格输出，配合 `-JsonOutput` 可供脚本解析 |
| `-TimeoutSec` | 否 | 等待扩展响应的最大秒数（1-300，默认 30） |
| `-PollIntervalMs` | 否 | 轮询间隔毫秒数（50-2000，默认 200） |
| `-JsonOutput` | 否 | 以 JSON 格式打印结果 |
| `-KeepTempFiles` | 否 | 发送后保留结果文件（默认自动删除），用于事后诊断 |
| `-TargetPid` | 否 | 目标 VS Code 主窗口 PID，0=自动检测（默认值）。若指定的 PID 不存在或不属于 Code.exe 进程，自动回退到自动检测模式 |

**`Priority` 行为说明：**

| 优先级 | 效果 | 适用场景 |
|--------|------|----------|
| `normal`（默认） | 先 `removeAllPendingRequests` 清空待处理队列，再用 `queueMessage` 提交。AI 忙时静默排队，**不弹窗** | 交互式、无人值守状态票 |
| `high` | 先 `removeAllPendingRequests` 清空队列 + `cancel` 取消活动请求，再粘贴+提交。**不弹窗** | 无人值守事件驱动票、紧急通知 |

两种优先级都会在发送前清空待处理队列，从根本上避免了 VS Code"保留/移除"对话框。



**退出码：**

| 退出码 | 含义 |
|--------|------|
| 0 | 消息发送成功 |
| 2 | 发送失败（含扩展返回失败、本地超时、命令文件写入失败等；详见 JSON 输出的 `reason` 字段） |
| 3 | 参数错误（空消息等） |

### Python（备用）

```powershell
python ipc_chat_sender.py --message "你的消息"
python ipc_chat_sender.py --message "test" --priority high --json-output
python ipc_chat_sender.py --message "发给实例 A" --target-pid 6288 --json-output
python ipc_chat_sender.py --message "状态报告" --priority normal --auto-escalate --json-output
python ipc_chat_sender.py --message "快速测试" --timeout 10 --poll-interval 100
python ipc_chat_sender.py --message "例行状态" --mode silent --timeout 90 --json-output
python ipc_chat_sender.py --message "重要通知" --mode visible
python ipc_chat_sender.py --discover
python ipc_chat_sender.py --discover --json-output
```

参数及退出码与 PowerShell 版本一致（含 `--target-pid`、`--auto-escalate`、`--timeout`、`--poll-interval`、`--mode`、`--discover`）。

## 通信协议

扩展与外部脚本通过临时文件进行 IPC：

### 文件命名规则

```
# PID 作用域文件（v1.1+，推荐）
命令文件:  %TEMP%\vscode_chat_send_cmd_<targetPid>.json
结果文件:  %TEMP%\vscode_chat_send_res_<targetPid>.json

# 旧版共享文件（v1.0，兼容）
命令文件:  %TEMP%\vscode_chat_send_cmd.json
结果文件:  %TEMP%\vscode_chat_send_result.json
```

PID 作用域文件实现多实例路由：每个 VS Code 实例仅监听以自己主窗口 PID
（`process.ppid`，与 `$env:VSCODE_PID` 一致）命名的命令文件，
调用方通过 `-TargetPid` 精确投递到指定实例。

扩展会优先检查 PID 作用域文件，不存在时降级检查旧版共享文件
（向后兼容，但多实例场景不推荐）。

### 命令文件（输入）

```json
{
  "message": "要发送的消息",
  "request_id": "可选追踪ID",
  "priority": "normal",
  "mode": "silent",
  "model": "DeepSeek V4 Flash",
  "model_options": {
    "thinking_mode": "deep"
  }
}
```

### 结果文件（输出）

```json
{
  "success": true,
  "reason": "sent_via_lm_api",
  "request_id": "",
  "model_name": "DeepSeek V4 Flash",
  "model_vendor": "deepseek",
  "model_id": "deepseek-v4-flash",
  "ai_response": "状态已记录，当前一切正常。",
  "ai_response_truncated": false
}
```

| 字段 | 说明 |
|------|------|
| `success` | 是否发送成功 |
| `reason` | 状态码（见下表） |
| `request_id` | 回显请求 ID |
| `ai_response` | AI 的响应文本（仅 Silent/Auto 走 LM API 时有） |
| `ai_response_truncated` | 响应是否因超时被截断（仅 LM API 路径） |
| `model_name` | LM API 使用的模型名称（如 `DeepSeek V4 Flash`） |
| `model_vendor` | 模型供应商（如 `deepseek`、`copilot`） |
| `model_id` | 模型标识符（如 `deepseek-v4-flash`、`auto`） |

### 模型选择策略

LM API 路径按以下优先级选择模型（由 `extension.js` 的 `pickModel()` 控制）：

0. **调用方指定** — 若命令文件中包含 `model` 字段（如 `"model": "GPT-5.5"`），优先按名称或 ID 匹配
1. **`Auto`** — 让 VS Code Copilot 自动路由到当前默认模型，通常与聊天面板一致
2. **`DeepSeek V4 Flash`** — 当前聊天面板的常用默认模型
3. **第一个可用模型** — 兜底

每次发送的结果中会包含 `model_name`、`model_vendor`、`model_id`，您可以验证 LM API 实际使用了哪个模型。

**PS 指定模型 + 思考模式：**
```powershell
\Send-IpcChatMessage.ps1 -Message "hello" -Mode Silent -Model "DeepSeek V4 Flash" -ModelOptions @{ thinking_mode = "deep" } -JsonOutput
```
**Python 指定模型：**
```powershell
python ipc_chat_sender.py --message "hello" --mode silent --model "DeepSeek V4 Flash" --model-options '{"thinking_mode":"deep"}'
```
**JSON 命令文件直接指定：**
```json
{
  "message": "hello",
  "priority": "normal",
  "mode": "silent",
  "model": "auto",
  "model_options": {
    "thinking_mode": "deep"
  }
}
```

**发现可用模型：**
```powershell
\Send-IpcChatMessage.ps1 -DiscoverModels -JsonOutput
```

> **注意：** `model_options` 的可用键值取决于具体模型，VS Code 和 AI 提供商未公开文档化。
> 常见键包括：
> - `thinking_mode` — DeepSeek 专用：`"disabled"`/`"standard"`/`"deep"`
> - `thinking_effort` — GPT/Gemini 通用：`"low"`/`"medium"`/`"high"`/`"xhigh"`（部分模型支持 `"none"`）

**可能的 `reason` 值：**

| reason | 含义 |
|--------|------|
| `sent_via_lm_api` | 发送成功（LM API 直达，含 `ai_response`） |
| `sent_via_clipboard_fallback` | 发送成功（剪贴板粘贴回退路径） |
| `lm_api_unavailable` | Silent 模式下 LM API 不可用，发送失败 |
| `discovery` | 模型发现结果（`models` 字段包含完整模型列表） |
| `discovery_failed` | 模型发现因异常而失败 |
| `no_message` | 命令文件中没有消息内容 |
| `clipboard_fallback_failed` | 剪贴板回退方案因异常而失败 |
| `poll_timeout` | 扩展未在超时时间内响应 |

## 工作原理

1. 扩展在 VS Code 启动时激活（`onStartupFinished`）
2. 写入激活诊断文件 `%TEMP%\vscode_chat_send_diag_<pid>.json`
3. 每 300ms 轮询，依次检查：
   - PID 作用域文件 `vscode_chat_send_cmd_<ppid>.json`（实例专属，推荐）
   - 旧版共享文件 `vscode_chat_send_cmd.json`（兼容降级）
4. 检测到命令文件后，立即删除文件（保证 at-most-once 语义）
5. 发送消息，两级回退：
   - **优先**：`vscode.lm.selectChatModels` + `model.sendRequest()` —
     直接调用语言模型 API，**完全不碰剪贴板、输入框或任何 UI 元素**。
     即使正在聊天框里打字，也不会造成消息污染。
   - **回退**（LM API 不可用时）：剪贴板粘贴路径：
     - `vscode.env.clipboard.writeText()` — 写入剪贴板
     - `workbench.action.chat.open` — 打开聊天面板
     - `workbench.action.chat.focusInput` — 聚焦输入框
     - `editor.action.clipboardPasteAction` — 粘贴文本
     - 两种优先级**均先调用 `removeAllPendingRequests` 清空队列**：
       - **`normal`**：`removeAllPendingRequests` + `queueMessage`
       - **`high`**：`removeAllPendingRequests` + `cancel` + `submit`
6. 将结果写入对应的结果文件（`vscode_chat_send_res_<pid>.json` 或 `vscode_chat_send_result.json`）
7. 外部脚本轮询结果文件，超时 30 秒

### 为什么不用 `code --command` 调用扩展命令？

VS Code 的 `code --command` CLI 只向主进程发送 IPC 消息，主进程不会将自定义扩展命令转发给扩展宿主进程，因此无法触发扩展注册的命令。这也是我们改用文件轮询模式的原因。

### 编码注意事项

PowerShell 5.1 的 `Set-Content -Encoding utf8` 会写入 UTF-8 **带 BOM** 的文件，导致 Node.js 的 `JSON.parse()` 解析失败。本脚本已使用 `[System.IO.File]::WriteAllText()` 配合无 BOM 编码来规避此问题。

### 扩展侧时序常量

扩展内部有三个硬编码的时序常量，控制轮询频率和粘贴提交之间的等待时间：

| 常量 | 位置 | 默认值 | 作用 |
|------|------|--------|------|
| 命令文件轮询间隔 | `setInterval(tryProcessCommand, …)` | **300ms** | 扩展每 300ms 检查一次是否有新的命令文件 |
| paste 前等待 | `focusInput` → `clipboardPasteAction` 之间 | **150ms** | 等输入框获得焦点后再粘贴 |
| submit 前等待 | `clipboardPasteAction` → `submit`/`queueMessage` 之间 | **100ms** | 等粘贴完成后再提交 |

可通过环境变量覆盖（需重启 VS Code 生效）：

| 环境变量 | 对应常量 | 默认 | 范围 |
|----------|---------|------|------|
| `VSCODE_CHAT_SENDER_POLL_MS` | 轮询间隔 | 300 | 100–1000 |
| `VSCODE_CHAT_SENDER_PASTE_DELAY_MS` | paste 前等待 | 150 | 0–500 |
| `VSCODE_CHAT_SENDER_SUBMIT_DELAY_MS` | submit 前等待 | 100 | 0–500 |
| `VSCODE_CHAT_SENDER_LM_RESPONSE_TIMEOUT_MS` | LM API 响应超时 | 60000 | 5000–300000 |

```powershell
# 示例：加快轮询和粘贴节奏（适合低延迟本地环境）
$env:VSCODE_CHAT_SENDER_POLL_MS = 200
$env:VSCODE_CHAT_SENDER_PASTE_DELAY_MS = 80
$env:VSCODE_CHAT_SENDER_SUBMIT_DELAY_MS = 50
# 然后重启 VS Code 窗口
```

> **注意：** 粘贴/提交延迟设得太低可能导致 VS Code 命令在 UI 未就绪前执行而失败。建议不要低于 50ms。

## 调试

### 检查扩展是否激活

激活诊断现在写入独立文件，不干扰结果文件轮询：

```powershell
# 诊断文件路径包含 VS Code 主窗口 PID
Get-Content "$env:TEMP\vscode_chat_send_diag_$env:VSCODE_PID.json" -Raw -Encoding utf8
# 预期输出：{"success":false,"reason":"extension_activated","instance_pid":XXXX}
```

### 查看最后一次发送结果

使用 `-KeepTempFiles` 参数保留结果文件以供事后分析：

```powershell
.\Send-IpcChatMessage.ps1 -Message "test" -KeepTempFiles

# 结果文件路径取决于目标 PID
Get-Content "$env:TEMP\vscode_chat_send_res_$env:VSCODE_PID.json" -Raw -Encoding utf8
```

### 检查扩展是否已安装

```powershell
code --list-extensions | Select-String -Pattern 'larsonzh'
# 预期输出：larsonzh.vscode-chat-sender
```

### 清理临时文件

```powershell
# 清理 PID 作用域文件
Remove-Item "$env:TEMP\vscode_chat_send_cmd_*.json" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\vscode_chat_send_res_*.json" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\vscode_chat_send_diag_*.json" -Force -ErrorAction SilentlyContinue

# 清理旧版共享文件
Remove-Item "$env:TEMP\vscode_chat_send_cmd.json" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\vscode_chat_send_result.json" -Force -ErrorAction SilentlyContinue
```

### 多实例场景下指定目标窗口

当有多个 VS Code 实例时，用 `-TargetPid` 指定目标窗口 PID。

**先找到目标窗口的 PID：**

`Get-Process -Name Code` 会返回包括扩展宿主、监视进程在内的所有 Code 进程，
其中只有**带 `MainWindowTitle`（窗口标题）的才是主窗口**。

```powershell
# 只看主窗口（过滤掉子进程）
Get-Process -Name Code | Where-Object { $_.MainWindowTitle } |
    Format-Table Id, StartTime, MainWindowTitle -AutoSize
```

示例输出：
```
  Id StartTime          Title
  -- ---------          -----
6288 2026/5/28 12:16:43 IPC_CHAT_SENDER_README.md - whois (工作区) - Visual Studio Code
```

**向指定实例发送消息：**

```powershell
.\Send-IpcChatMessage.ps1 -Message "发给实例 A" -TargetPid 6288
```

**自动检测说明：**
- **集成终端**：自动读取 `$env:VSCODE_PID`，精确匹配当前实例（无需手动指定）
- **外部终端**（不指定 `-TargetPid`）：自动找到最新的带 `MainWindowTitle` 的 Code.exe 进程
- **指定 `-TargetPid`**：精确投递到指定 PID 的实例（最可靠）

### 扩展不响应

1. 确认 VS Code 已重新加载窗口（`Ctrl+Shift+P` → `Developer: Reload Window`）
2. 检查扩展是否存在：`code --list-extensions | Select-String larsonzh`
3. 查看激活诊断文件（见上）
4. 如果仍然不工作，重新安装扩展：`install_ipc_chat_extension.ps1 -Force`

## 常见问题

### Q1: 所有 VS Code 实例窗口的 PID 都相同，如何将消息发送到指定的实例窗口？

**实际情况：每个 VS Code 窗口是一个独立进程，拥有唯一的 PID。**
如果多个 VS Code 窗口的 PID 确实相同，说明它们是**同一进程内的多个窗口**（通过 `--add` / `File → New Window` 且复用同一进程），这种情况下 `Get-Process` 只能返回该进程的 PID，无法在进程层面区分窗口。

**解决思路：**

| 方法 | 说明 | 可行性 |
|------|------|--------|
| **使用不同 VS Code 配置文件（Profile）** | 为每个实例创建独立的 Profile，安装不同的扩展拷贝（使用不同的发布者名/扩展 ID），各自监听不同的命令文件路径 | 可行，但管理成本高 |
| **使用不同 VS Code 版本/分支** | 如 `Code.exe`（稳定版）和 `Code - Insiders.exe`（预览版）是不同进程，PID 必然不同 | 适合开发和测试环境 |
| **只能发到最上层窗口** | 如果所有窗口确实是同一进程，IPC 不分层，消息只能进入该进程的 Copilot Chat，由 VS Code 自身决定路由到哪个窗口 | 固有局限 |

**推荐方案：**
- 对于同一 VS Code 进程内的多窗口场景，消息会发到**当前活跃（聚焦）的窗口**的 Copilot Chat。
- 若需要严格区分，请使用不同的 VS Code 配置文件或不同的 VS Code 分支。
- `-TargetPid` 在不同进程之间（不同 PID）有效，在同进程多窗口（同 PID）场景下退化为“发到活跃窗口”，效果与不指定 `-TargetPid` 相同。

### Q2: 聊天会话异常结束时如何避免"保留/移除"弹窗？

**问题背景：**
当 Copilot Chat 会话因错误/超时结束，且队列中有未消费消息时，普通 `submit` 会触发：
> "你已有待处理的请求。是要将这些请求保留在队列中，还是在发送此消息前将其移除？"

弹窗会阻塞 VS Code 渲染线程，无法通过扩展 API 拦截或自动确认。

**当前解决方案（v1.1+）：两种优先级均先清空队列再发送**

| 优先级 | 清队列方式 | 提交方式 | 效果 |
|--------|-----------|---------|------|
| `normal` | `removeAllPendingRequests` | `queueMessage` | 队列清空后再排队，AI 忙时静默等待 |
| `high` | `removeAllPendingRequests` + `cancel` | `submit` | 清队列+终止活动请求，立即提交 |

**根本机制：** `removeAllPendingRequests` 清空待处理请求队列后，`submit`/`queueMessage` 不会触发对话框。

**关于 `-AutoEscalate`：**
`-AutoEscalate` 仍保留作为兜底机制：若 `normal` 发送因未知原因（如扩展未响应、错误状态等）超时，会自动升级为 `high` 重试。在绝大多数正常场景下，`normal` 即可无弹窗发送。

**推荐用法：**

```powershell
# 事件驱动票——high，立即送达
.\Send-IpcChatMessage.ps1 -Message "紧急事件" -Priority high -JsonOutput

# 状态票——normal，不打断当前工作流，超时时自动升级
.\Send-IpcChatMessage.ps1 -Message "例行状态报告" -Priority normal -AutoEscalate -JsonOutput
```

### Q3: 消息中能否包含换行符和单/双引号？

**可以。** 消息文本通过 JSON 编码传递，JSON 天然支持：
- **换行符**：在消息字符串中使用 `\n` 即可（JSON 会在解析时将其还原为真正的换行）
- **单引号 `'`**：直接使用，不需要转义
- **双引号 `"`**：JSON 中需要转义为 `\"`

**PowerShell 传参注意事项：**

```powershell
# ---- 多行消息示例 ----

# 方法 A：PowerShell here-string（最清晰）
.\Send-IpcChatMessage.ps1 -Message @"
第一行
第二行
第三行
"@

# 方法 B：使用 PowerShell 换行符 `n
.\Send-IpcChatMessage.ps1 -Message "第一行`n第二行`n第三行"

# 方法 C：用 JsonOutput 参数验证实际内容
# JSON 中的 \n 会被扩展解析为换行
.\Send-IpcChatMessage.ps1 -Message "第一行\n第二行\n第三行"

# ---- 双引号示例 ----
# 用单引号包裹外层参数，内部双引号无需转义
.\Send-IpcChatMessage.ps1 -Message '他说："你好，世界。"'

# 若用双引号包裹外层，内部双引号需重复写（PowerShell 转义）
.\Send-IpcChatMessage.ps1 -Message "他说：""你好，世界。"""

# ---- 单引号示例 ----
# 用双引号包裹外层
.\Send-IpcChatMessage.ps1 -Message "It's working"

# ---- 混合示例 ----
.\Send-IpcChatMessage.ps1 -Message "报告：`"CPU 使用率 45%`"\n状态：正常\n时间：$(Get-Date -Format 'HH:mm:ss')"
```

**Python 传参：**

```bash
# 多行消息（--message 中的 \n 会被 JSON 序列化保留）
python ipc_chat_sender.py --message "第一行\n第二行\n第三行"

# 含双引号——用单引号包裹外层
python ipc_chat_sender.py --message '他说："你好"'

# 含单引号——用双引号包裹外层
python ipc_chat_sender.py --message "It's working"

# 混合
python ipc_chat_sender.py --message "CPU 45%\n内存 60%\n磁盘 80%"
```

**底层原理：** 消息在 `cmdPayload.message` 中以 JSON 字符串形式存储，JSON 序列化时会自动处理转义。扩展读取后传给 VS Code Chat API，Chat 输入框原生支持多行文本和各类引号。
