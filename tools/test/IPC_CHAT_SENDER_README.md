# VS Code IPC Chat Sender

通过纯 IPC 通道向 VS Code Copilot Chat 发送消息，不依赖任何 UI 自动化（pywinauto / AHK）。

## 架构总览

```
外部脚本 (PowerShell / Python)
    │  写入 %TEMP%\vscode_chat_send_cmd.json
    ▼
vscode-chat-sender 扩展（轮询 300ms）
    │  vscode.env.clipboard.writeText()
    │  vscode.commands.executeCommand('workbench.action.chat.open')
    │  vscode.commands.executeCommand('workbench.action.chat.focusInput')
    │  vscode.commands.executeCommand('editor.action.clipboardPasteAction')
    │  vscode.commands.executeCommand('workbench.action.chat.submit')
    ▼
VS Code Copilot Chat 收到消息
    │  写入 %TEMP%\vscode_chat_send_result.json
    ▼
外部脚本读取结果
```

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

# 指定提交快捷键风格（仅用于协议对齐，不影响实际提交行为）
.\Send-IpcChatMessage.ps1 -Message "测试" -SubmitChord ctrl-enter

# JSON 格式输出（供其他脚本解析）
.\Send-IpcChatMessage.ps1 -Message "test" -JsonOutput
```

**参数说明：**

| 参数 | 必填 | 说明 |
|------|------|------|
| `-Message` | 是 | 要发送的消息文本 |
| `-RequestId` | 否 | 请求标识符，会在结果中原样返回 |
| `-SubmitChord` | 否 | `enter` / `ctrl-enter` / `alt-enter`，默认 `enter` |
| `-JsonOutput` | 否 | 以 JSON 格式打印结果 |

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
python ipc_chat_sender.py --message "test" --submit-chord ctrl-enter --json-output
```

参数及退出码与 PowerShell 版本一致。

## 通信协议

扩展与外部脚本通过临时文件进行 IPC：

### 命令文件（输入）

路径：`%TEMP%\vscode_chat_send_cmd.json`

```json
{
  "message": "要发送的消息",
  "request_id": "可选追踪ID",
  "submit_chord": "enter"
}
```

### 结果文件（输出）

路径：`%TEMP%\vscode_chat_send_result.json`

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
2. 每 300ms 轮询命令文件 `vscode_chat_send_cmd.json`
3. 检测到命令文件后，立即删除文件（保证 at-most-once 语义）
4. 通过 VS Code API 执行以下 IPC 操作：
   - `vscode.env.clipboard.writeText()` — 写入剪贴板
   - `workbench.action.chat.open` — 打开聊天面板
   - `workbench.action.chat.focusInput` — 聚焦输入框
   - `editor.action.clipboardPasteAction` — 粘贴文本（从扩展宿主执行，非 `code --command`）
   - `workbench.action.chat.submit` — 提交消息
5. 将结果写入 `vscode_chat_send_result.json`
6. 外部脚本轮询结果文件，超时 30 秒

### 为什么不用 `code --command` 调用扩展命令？

VS Code 的 `code --command` CLI 只向主进程发送 IPC 消息，主进程不会将自定义扩展命令转发给扩展宿主进程，因此无法触发扩展注册的命令。这也是我们改用文件轮询模式的原因。

### 编码注意事项

PowerShell 5.1 的 `Set-Content -Encoding utf8` 会写入 UTF-8 **带 BOM** 的文件，导致 Node.js 的 `JSON.parse()` 解析失败。本脚本已使用 `[System.IO.File]::WriteAllText()` 配合无 BOM 编码来规避此问题。

## 调试

### 检查扩展是否激活

```powershell
# 检查结果文件是否有激活诊断标记
Get-Content "$env:TEMP\vscode_chat_send_result.json" -Raw -Encoding utf8
# 预期输出：{"success":false,"reason":"extension_activated"}
```

### 检查扩展是否已安装

```powershell
code --list-extensions | Select-String -Pattern 'lzispro'
# 预期输出：lzispro.vscode-chat-sender
```

### 清理临时文件

```powershell
Remove-Item "$env:TEMP\vscode_chat_send_cmd.json" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\vscode_chat_send_result.json" -Force -ErrorAction SilentlyContinue
```

### 扩展不响应

1. 确认 VS Code 已重新加载窗口（`Ctrl+Shift+P` → `Developer: Reload Window`）
2. 检查扩展是否存在：`code --list-extensions | Select-String lzispro`
3. 查看激活诊断文件（见上）
4. 如果仍然不工作，重新安装扩展：`install_ipc_chat_extension.ps1 -Force`
