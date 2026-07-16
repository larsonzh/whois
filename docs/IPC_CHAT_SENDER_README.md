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

# Silent 模式 + 按请求覆盖扩展侧超时（无需设系统环境变量，仅对本次生效）
.\Send-IpcChatMessage.ps1 -Message "长任务" -Mode Silent -TimeoutSec 120 -LmResponseTimeoutMs 180000 -JsonOutput

# Visible 模式——强制走剪贴板，消息在聊天面板可见
.\Send-IpcChatMessage.ps1 -Message "重要通知" -Mode Visible
```

**参数说明：**

| 参数 | 必填 | 说明 |
|------|------|------|
| `-Message` | 是 | 要发送的消息文本 |
| `-RequestId` | 否 | 请求标识符。留空时脚本自动生成（`auto-<guid>`）并用于结果绑定校验；结果中回显实际 request_id |
| `-Priority` | 否 | `normal`（排队，默认） / `high`（打断当前，立即发送） |
| `-AutoEscalate` | 否 | 与 `-Priority normal` 配合使用：若发送超时，自动用 `high` 重试 |
| `-Mode` | 否 | 投递模式：`Visible`（剪贴板，聊天面板可见，默认）/ `Silent`（LM API，捕获 AI 响应）/ `Auto`（优先 LM API，回退剪贴板） |
| `-Model` | 否 | 指定 LM API 使用的模型名称或 ID（Silent/Auto 模式），如 `DeepSeek V4 Flash`、`GPT-5.5`、`auto`。留空使用默认选择逻辑 |
| `-ModelOptions` | 否 | 模型特定选项哈希表，原样传给 LM API 的 modelOptions。用于配置思考模式、Thinking Effort、上下文大小等。示例：`@{ thinking_effort = "high" }` |
| `-DiscoverModels` | 否 | 列出所有可用 LM 模型及其元数据（name/vendor/id/family/version/maxInputTokens），不发送消息。默认表格输出，配合 `-JsonOutput` 可供脚本解析 |
| `-TimeoutSec` | 否 | 等待扩展响应的最大秒数（1-5400，默认 30）。长任务（>90 分钟）见[长耗时回复处理](#长耗时回复处理） |
| `-LmResponseTimeoutMs` | 否 | 按请求覆盖 LM API 响应超时毫秒数（1000-3600000，0=使用环境变量或默认 60000）。无需重启 VS Code，仅对本次 IPC 消息生效。见[长耗时回复处理](#长耗时回复处理） |
| `-PollIntervalMs` | 否 | 轮询间隔毫秒数（50-2000，默认 200） |
| `-JsonOutput` | 否 | 以 JSON 格式打印结果 |
| `-KeepTempFiles` | 否 | 发送后保留结果文件（默认自动删除），用于事后诊断 |
| `-TargetPid` | 否 | 目标 VS Code 主窗口 PID，0=自动检测（默认值）。若指定的 PID 不存在或不属于 Code.exe 进程，自动回退到自动检测模式 |


**JSON 输出管道转换（PowerShell 5.1 兼容）**

`-JsonOutput` 输出的 JSON 字符串可通过管道直接反序列化为普通文本显示，供人阅读：

```powershell
# 最简：仅提取 AI 回复文本
.\Send-IpcChatMessage.ps1" -Message "你的消息" -Mode Silent -TimeoutSec 4200 -LmResponseTimeoutMs 3600000 -JsonOutput | ConvertFrom-Json | Select-Object -ExpandProperty ai_response

# 完整展示所有字段（适合调试）
.\Send-IpcChatMessage.ps1" -Message "你的消息" -Mode Silent -TimeoutSec 4200 -LmResponseTimeoutMs 3600000 -JsonOutput | ConvertFrom-Json | Format-List

# 带成功/失败判断
.\Send-IpcChatMessage.ps1" -Message "你的消息" -Mode Silent -TimeoutSec 4200 -LmResponseTimeoutMs 3600000 -JsonOutput | ConvertFrom-Json | ForEach-Object {
    if ($_.success) { "✓ $($_.ai_response)" } else { "✗ $($_.reason)" }
}
```

说明：
- `ConvertFrom-Json` 将 JSON 字符串反序列化为 PowerShell 对象（PS 5.1 原生支持）
- `Select-Object -ExpandProperty ai_response` 提取 `ai_response` 字段的值作为纯文本输出
- `Format-List` 以 `key: value` 格式展示所有字段
- `ForEach-Object` 可自定义格式化逻辑


**`Priority` 行为说明：**

| 优先级 | 效果 | 适用场景 |
|--------|------|----------|
| `normal`（默认） | 先 `removeAllPendingRequests` 清空待处理队列，再用 `queueMessage` 提交。AI 忙时静默排队，**不弹窗** | 交互式、无人值守状态票 |
| `high` | 先 `removeAllPendingRequests` 清空队列 + `cancel` 取消活动请求，再粘贴+提交。**不弹窗** | 无人值守事件驱动票、紧急通知 |

两种优先级都会在发送前清空待处理队列，从根本上避免了 VS Code"保留/移除"对话框。



**退出码：**

| 退出码 | 含义 |
|--------|------|
| 0 | 消息发送或模型发现成功 |
| 1 | 本地传输失败（如 `poll_timeout`、`write_cmd_failed:*`） |
| 2 | 扩展侧返回失败（详见 JSON 输出的 `reason` 字段） |
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
python ipc_chat_sender.py --message "长任务" --mode silent --timeout 120 --lm-response-timeout-ms 180000
python ipc_chat_sender.py --discover
python ipc_chat_sender.py --discover --json-output
```

参数及退出码与 PowerShell 版本一致（含 `--target-pid`、`--auto-escalate`、`--timeout`、`--poll-interval`、`--mode`、`--discover`、`--lm-response-timeout-ms`）。

> 说明：Python 版本同样在未传入 `--request-id` 时自动生成 `auto-<guid>`，并在轮询结果时做 request_id 绑定校验。

## 无人值守分发接入（dispatch_takeover_to_chat.ps1）

当无人值守分发脚本接入 IPC 发送路径时，推荐通过策略键控制：

| 键 | 建议值 | 说明 |
|----|--------|------|
| `AI_CHAT_POLICY_DELIVERY_PRIMARY` | `ipc` | 主发送路径切换到 IPC |
| `AI_CHAT_DISPATCH_USE_IPC` | `true` | 策略编译器生成的派生开关 |
| `AI_CHAT_DISPATCH_IPC_MODE` | `visible` | IPC 投递模式；默认 `visible` |
| `AI_CHAT_DISPATCH_INTERACTIVE_PRE_ACTIONS_ENABLED` | `false` | IPC 路径默认关闭窗口前后动作（剪贴板预写、chat.open、新窗口关停） |

说明：

- `AI_CHAT_DISPATCH_IPC_MODE` 支持 `visible` / `silent` / `auto`，未设置或非法值会回落到 `visible`。
- 分发脚本支持 `-UseIpcSender` 进行一次性强制切换。
- IPC 路径默认不依赖窗口操控，避免 legacy UI 自动化副作用。

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
  },
  "lm_response_timeout_ms": 180000
}
```

| 命令文件字段 | 说明 |
|-------------|------|
| `message` | 要发送的消息文本 |
| `request_id` | 可选追踪 ID |
| `priority` | `normal` / `high` |
| `mode` | `silent` / `visible` / `auto` |
| `model` | 可选，指定 LM API 模型名称或 ID |
| `model_options` | 可选，模型特定选项对象（如思考模式） |
| `lm_response_timeout_ms` | 可选，按请求覆盖 LM API 响应超时毫秒数。优先于 `VSCODE_CHAT_SENDER_LM_RESPONSE_TIMEOUT_MS` 环境变量，仅对本次请求生效 |
| `discover` | 可选，`true` 时列出可用模型，不发送消息 |

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
| `poll_timeout` | 扩展未在超时时间内响应（长任务见[长耗时回复处理](#长耗时回复处理） |
| `write_cmd_failed:*` | 调用脚本写命令文件失败（本地错误） |

## 长耗时回复处理

当 AI 需要长时间（如 10–30 分钟）处理任务时，默认超时设置会导致提前截断或超时失败。

### 双超时关卡

| 关卡 | 位置 | 默认值 | 当前上限 |
|------|------|--------|---------|
| PowerShell 侧 `-TimeoutSec` | `Send-IpcChatMessage.ps1` 轮询超时 | 30s | **5400s**（`[ValidateRange(1,5400)]` 硬限制） |
| 扩展侧 `VSCODE_CHAT_SENDER_LM_RESPONSE_TIMEOUT_MS` | `extension.js` 收集 `response.text` 超时 | 60000ms | 无代码硬限制（环境变量可设任意正数） |

**关键约束**：PowerShell 脚本的 `-TimeoutSec` 参数上限为 **5400 秒（90 分钟）**，由 `[ValidateRange(1, 5400)]` 特性强制限制。要支持超过 90 分钟的长任务，需修改此上限或改用其他调用方式。

> 扩展侧的 `LM_RESPONSE_TIMEOUT_MS` 现在支持通过命令文件字段 `lm_response_timeout_ms` 按请求覆盖，**无需重启 VS Code**，仅对本次 IPC 消息生效。这是处理长耗时任务的首选方式。

### 关键架构约束：扩展环境变量独立于终端

`extension.js` 在 VS Code 的**扩展宿主进程**中运行，它读取的 `process.env` 来自该进程启动时的环境快照。**集成终端的 PowerShell 设置 `$env:VAR` 对扩展不可见**——它们是两个独立的进程。

```
VS Code
 ├── 扩展宿主进程 ← extension.js 读取 process.env（启动时固化）
 ├── 集成终端 PowerShell ← $env:VAR 仅在此进程有效
 └── ...
```

因此 `VSCODE_CHAT_SENDER_LM_RESPONSE_TIMEOUT_MS` 只能通过以下方式设置：
- **用户/系统环境变量**（推荐，一直生效）：`setx VSCODE_CHAT_SENDER_LM_RESPONSE_TIMEOUT_MS 5400000`，然后**重启 VS Code**。
- **启动前设置**（仅当次生效）：在外部终端（非集成终端）执行 `set VAR=5400000 && code .`。
- **按请求覆盖**（推荐，无需重启）：通过 `-LmResponseTimeoutMs` 参数（PowerShell）或 `--lm-response-timeout-ms`（Python）或命令文件字段 `lm_response_timeout_ms`，**仅对本次 IPC 消息生效**，不依赖环境变量。

> `Send-IpcChatMessage.ps1` 的 `-TimeoutSec` 是 PowerShell 脚本自己的轮询超时，与扩展无关，可以在每次调用时自由调整。

### Silent 模式下的消息模型

- **一次请求，一次响应**：AI 在执行多次中间操作（读文件、改代码、调终端）时，这些过程**不会**单独回传。扩展持续收集 `response.text` chunk，待 AI 完全生成后才一次性写入结果文件。
- **接收端是轮询等待**：PowerShell 以 `PollIntervalMs`（默认 200ms）轮询结果文件，不是持续阻塞连接。直到文件出现或超时。
- **超时截断**：若 AI 生成时间超过 `LM_RESPONSE_TIMEOUT_MS`，`ai_response_truncated` 标记为 `true`，响应内容截断。

### 应对长耗时任务的方案

> **首选方案**：使用 `-LmResponseTimeoutMs` 参数按请求覆盖扩展侧超时，无需设置环境变量或重启 VS Code。

#### 方案 A：按请求覆盖扩展侧超时（推荐，无需重启）

```powershell
# 仅需设 PowerShell 侧超时 + 按请求覆盖扩展侧超时
& "path\to\Send-IpcChatMessage.ps1" -Message "指令" -Mode Silent -TimeoutSec 120 -LmResponseTimeoutMs 180000 -JsonOutput
```

- `-TimeoutSec`：PowerShell 侧轮询超时（可每次调整）
- `-LmResponseTimeoutMs`：扩展侧 LM API 响应超时（毫秒），仅对本次 IPC 消息生效，覆盖环境变量
- 无需设置系统环境变量，无需重启 VS Code

`-LmResponseTimeoutMs` 取值范围 1000–3600000（1 秒–1 小时），0=使用环境变量或默认值（60000ms）。

#### 方案 B：调大两个超时（≤90 分钟，通过系统环境变量）

如果不想每次指定 `-LmResponseTimeoutMs`，也可以设系统环境变量一次生效：

```powershell
# 1. 设置系统环境变量（仅需一次，然后重启 VS Code）
setx VSCODE_CHAT_SENDER_LM_RESPONSE_TIMEOUT_MS 5400000

# 2. 重启 VS Code 后，调用时仅需设 PowerShell 侧超时（可每次调整）
& "path\to\Send-IpcChatMessage.ps1" -Message "指令" -Mode Silent -TimeoutSec 5400 -JsonOutput
```

90 分钟以内的任务够用。注意 `-TimeoutSec 5400` 已是当前脚本上限。

#### 方案 C：修改脚本上限后调用（>90 分钟，系统环境变量）

如需支持更长时间（如 100–120 分钟），需要先修改 `Send-IpcChatMessage.ps1` 中的 `[ValidateRange(1, 5400)]`，将 5400 放宽到目标值（如 9000），然后：

```powershell
# 1. 设置系统环境变量（仅需一次，然后重启 VS Code）
setx VSCODE_CHAT_SENDER_LM_RESPONSE_TIMEOUT_MS 9000000

# 2. 重启 VS Code 后，调用时仅设 PowerShell 侧超时
& "path\to\Send-IpcChatMessage.ps1" -Message "长任务指令" -Mode Silent -TimeoutSec 7200 -JsonOutput
```

#### 方案 D：Visible 模式仅投递（无需 AI 回复）

如果调用方只需将消息投递给 AI 即可，不需要等待 AI 回复内容：

```powershell
# Visible 模式在粘贴+提交后立即返回，不阻塞
& "path\to\Send-IpcChatMessage.ps1" -Message "指令" -Mode Visible -Priority high
```

结果文件在粘贴成功后立即写入（`sent_via_clipboard_fallback`），但 `ai_response` 字段不存在。

### 三种模式对比

| 模式 | 能否拿到 `ai_response` | 调用方阻塞时间 | 适用场景 |
|------|----------------------|---------------|---------|
| Silent + `-LmResponseTimeoutMs` | ✅ 完整回复 | 等于 AI 生成时长 | 需要回复内容，可接受长阻塞 |
| Visible | ❌ 无回复 | 极短（粘贴完成即返回） | 只投递不关心回复 |
| Auto | ⚠️ 有则拿，无则退 | 取决于走哪条路径 | 兼容模式 |

### 分发脚本注意事项

`dispatch_takeover_to_chat.ps1` 中已根据 `$TimeoutMs` 推导 PowerShell 侧超时（行 2736）。扩展侧超时现在**可以在命令文件层面动态控制**——分发脚本在构造命令文件时可以写入 `lm_response_timeout_ms` 字段，无需系统环境变量，无需重启 VS Code。这解决了扩展与终端进程隔离的固有限制。

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
另外，`Set-Content` 在 Windows 下默认会写入 CRLF 行尾；若目标文件要求 LF（例如 start-file 或需要稳定跨平台 diff 的文本），应显式构造 `"\n"` 换行后再写入，避免 LF 被回写为 CRLF。

### 扩展侧时序常量

扩展内部有三个硬编码的时序常量，控制轮询频率和粘贴提交之间的等待时间：

| 常量 | 位置 | 默认值 | 作用 |
|------|------|--------|------|
| 命令文件轮询间隔 | `setInterval(tryProcessCommand, …)` | **300ms** | 扩展每 300ms 检查一次是否有新的命令文件 |
| paste 前等待 | `focusInput` → `clipboardPasteAction` 之间 | **150ms** | 等输入框获得焦点后再粘贴 |
| submit 前等待 | `clipboardPasteAction` → `submit`/`queueMessage` 之间 | **100ms** | 等粘贴完成后再提交 |

可通过环境变量覆盖（**需重启 VS Code 生效**，且必须在系统/用户环境变量中设置，集成终端的 `$env:...` 对扩展不可见）：

| 环境变量 | 对应常量 | 默认 | 范围 |
|----------|---------|------|------|
| `VSCODE_CHAT_SENDER_POLL_MS` | 轮询间隔 | 300 | 100–1000 |
| `VSCODE_CHAT_SENDER_PASTE_DELAY_MS` | paste 前等待 | 150 | 0–500 |
| `VSCODE_CHAT_SENDER_SUBMIT_DELAY_MS` | submit 前等待 | 100 | 0–500 |
| `VSCODE_CHAT_SENDER_LM_RESPONSE_TIMEOUT_MS` | LM API 响应超时 | 60000 | ≥5000（代码无硬上限，可被命令文件 `lm_response_timeout_ms` 按请求覆盖，见[长耗时回复处理](#长耗时回复处理） |

```powershell
# 设置方式一：系统环境变量（一直生效，重启 VS Code 后生效）
setx VSCODE_CHAT_SENDER_POLL_MS 200
setx VSCODE_CHAT_SENDER_PASTE_DELAY_MS 80
setx VSCODE_CHAT_SENDER_SUBMIT_DELAY_MS 50

# 设置方式二：启动 VS Code 前在外部终端设置（仅当次生效）
set VSCODE_CHAT_SENDER_POLL_MS=200 && code .
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

### Q3: 工单消息被队列清除时如何兜底？

**问题背景：**
当前实现（v1.1+）的两种优先级都会在发送前执行 `removeAllPendingRequests` 清空待处理队列，
这可能导致已排队但未被 AI 消费的工单消息被清除。对于无人值守场景，这可能造成工单遗漏。

**任务兜底建议：**

由于 VS Code 不暴露查询消息队列状态的公开 API，无法在传输层保证工单不丢失。
建议在**业务层**通过幂等设计和执行后校验来解决，而不是在传输层追求绝对可靠：

1. **幂等工单设计** — 每条工单消息应包含足够的信息使 AI 能够判断是否已执行过。
   常见的做法是在消息中嵌入一个唯一的工单 ID（`RequestId` 或自定义标识），
   AI 在处理任务前先检查该 ID 是否已被记录为"已执行"。

2. **执行后校验** — 在 AI 工单处理脚本的提示词末尾附加校验指令，要求 AI 在处理完当前消息后：
   - 检查指定位置（如文件系统、状态标记）是否存在未执行的遗留工单
   - 对发现的未执行工单进行补偿处理
   - 记录已执行工单 ID 到持久化位置

  在本仓库无人值守链路中，可直接复用 `tools/test/poll_agent_tickets.ps1` 返回字段：
  - `atomic_closeout_command`：事件票业务动作完成后只执行一次；统一写入 `handled_at`、processed、ledger receipt 并完成 closure 校验。仅当退出码为 0 且机器事实门禁全部通过时才可声称闭环。
  - `mark_processed_command`、`handled_receipt_command`、`validate_receipt_command`、`post_check_command`：保留为审计兼容字段，不得由 Agent 逐条执行。
  - 状态票去重：post-check 仅执行最新一条 `running-status-report`；更早未完成状态票会在同轮自动标记已执行，避免短时间重复执行相同任务流

3. **监控重试** — `-AutoEscalate` 可在 normal 超时时自动升级为 high 重试，
   减少队列清除导致的偶然丢单。

**推荐用法示例（PowerShell 工单脚本）：**

```powershell
# 每个工单携带唯一 RequestId，AI 执行后标记为已完成
.\Send-IpcChatMessage.ps1 -Message @"
检查未完成工单。

如果发现未完成工单，请依次处理。

任务完成后，将已处理工单 ID 记录到状态文件中。
"@ -Priority normal -AutoEscalate -JsonOutput
```

**底层思路：**
> 不在传输层保证不丢失，而在业务层保证已处理。
>
> 被清掉的工单不在 AI 的当前会话里出现，但 AI 在处理下一条工单的任务流末尾，
> 会主动去检查未执行的遗留工单 —— 相当于一个 "catch‑up" 步骤。

### Q4: 消息中能否包含换行符和单/双引号？

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
