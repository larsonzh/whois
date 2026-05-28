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
    │  vscode.env.clipboard.writeText()
    │  vscode.commands.executeCommand('workbench.action.chat.open')
    │  vscode.commands.executeCommand('workbench.action.chat.focusInput')
    │  vscode.commands.executeCommand('editor.action.clipboardPasteAction')
    │  vscode.commands.executeCommand('workbench.action.chat.submit')
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
powershell -NoProfile -ExecutionPolicy Bypass -File "tools/test/install_ipc_chat_extension.ps1 -Force"

# 2. 重新加载 VS Code 窗口（Ctrl+Shift+P → Developer: Reload Window）
```

安装后不需要重复执行。

### 更新

扩展代码修改后，重新运行安装脚本并重载 VS Code 窗口即可：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "tools/test/install_ipc_chat_extension.ps1 -Force"
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
```

**参数说明：**

| 参数 | 必填 | 说明 |
|------|------|------|
| `-Message` | 是 | 要发送的消息文本 |
| `-RequestId` | 否 | 请求标识符，会在结果中原样返回 |
| `-Priority` | 否 | `normal`（排队，默认） / `high`（打断当前，立即发送） |
| `-JsonOutput` | 否 | 以 JSON 格式打印结果 |
| `-KeepTempFiles` | 否 | 发送后保留结果文件（默认自动删除），用于事后诊断 |
| `-TargetPid` | 否 | 目标 VS Code 主窗口 PID，0=自动检测（默认值） |

**`Priority` 行为说明：**

| 优先级 | 效果 | 适用场景 |
|--------|------|----------|
| `normal`（默认） | `submit` 静默排队；AI 忙时不打断，当前回复完成后自动发送 | 状态票、定时报告 |
| `high` | 提交前 `chat.clear` 清除活动请求 → 粘贴 → 提交，立即发送 | 事件驱动票、紧急通知 |



**退出码：**

| 退出码 | 含义 |
|--------|------|
| 0 | 消息发送成功 |
| 2 | 发送失败（详见 JSON 输出的 `reason` 字段） |
| 3 | 参数错误（空消息等） |
| 1 | 其他错误（文件写入失败等） |

### Python（备用）

```powershell
python ipc_chat_sender.py --message "你的消息"
python ipc_chat_sender.py --message "test" --priority high --json-output
python ipc_chat_sender.py --message "发给实例 A" --target-pid 6288 --json-output
```

参数及退出码与 PowerShell 版本一致（含 `--target-pid`）。

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
  "priority": "normal"
}
```

### 结果文件（输出）

```json
{
  "success": true,
  "reason": "sent_via_clipboard_fallback",
  "request_id": ""
}
```

**可能的 `reason` 值：**

| reason | 含义 |
|--------|------|
| `sent_via_clipboard_fallback` | 发送成功（通过剪贴板+命令粘贴） |
| `sent` | 发送成功（通过 vscode.chat.sendRequest） |
| `sent_default` | 发送成功（默认参与者） |
| `chat_api_unavailable` | vscode.chat 相关 API 不可用 |
| `no_message` | 命令文件中没有消息内容 |
| `all_participants_failed` | 所有参与者都失败 |
| `clipboard_fallback_failed` | 剪贴板回退方案失败 |
| `poll_timeout` | 扩展未在超时时间内响应 |

## 工作原理

1. 扩展在 VS Code 启动时激活（`onStartupFinished`）
2. 写入激活诊断文件 `%TEMP%\vscode_chat_send_diag_<pid>.json`
3. 每 300ms 轮询，依次检查：
   - PID 作用域文件 `vscode_chat_send_cmd_<ppid>.json`（实例专属，推荐）
   - 旧版共享文件 `vscode_chat_send_cmd.json`（兼容降级）
4. 检测到命令文件后，立即删除文件（保证 at-most-once 语义）
5. 通过 VS Code API 执行以下 IPC 操作：
   - `vscode.env.clipboard.writeText()` — 写入剪贴板
   - `workbench.action.chat.open` — 打开聊天面板
   - `workbench.action.chat.focusInput` — 聚焦输入框
   - `editor.action.clipboardPasteAction` — 粘贴文本（从扩展宿主执行，非 `code --command`）
   - `workbench.action.chat.submit` — 提交消息
6. 将结果写入对应的结果文件（`vscode_chat_send_res_<pid>.json` 或 `vscode_chat_send_result.json`）
7. 外部脚本轮询结果文件，超时 30 秒

### 为什么不用 `code --command` 调用扩展命令？

VS Code 的 `code --command` CLI 只向主进程发送 IPC 消息，主进程不会将自定义扩展命令转发给扩展宿主进程，因此无法触发扩展注册的命令。这也是我们改用文件轮询模式的原因。

### 编码注意事项

PowerShell 5.1 的 `Set-Content -Encoding utf8` 会写入 UTF-8 **带 BOM** 的文件，导致 Node.js 的 `JSON.parse()` 解析失败。本脚本已使用 `[System.IO.File]::WriteAllText()` 配合无 BOM 编码来规避此问题。

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
code --list-extensions | Select-String -Pattern 'lzispro'
# 预期输出：lzispro.vscode-chat-sender
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
2. 检查扩展是否存在：`code --list-extensions | Select-String lzispro`
3. 查看激活诊断文件（见上）
4. 如果仍然不工作，重新安装扩展：`install_ipc_chat_extension.ps1 -Force`
