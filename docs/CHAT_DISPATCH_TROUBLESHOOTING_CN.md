# Chat 投送快速排障清单（CN）

适用范围：
- `tools/test/send_chat_message_ahk.ps1`
- `tools/test/dispatch_takeover_to_chat.ps1`
- 无人值守触发链路（trigger -> dispatch -> AHK send）

## 1. 30 秒快速判定

1. 先看发送脚本退出码：`Exit Code = 0` 基本表示发送链路已执行完成。
2. 再看结果对象：`sent=True`、`ahk_exit_code=0`。
3. 如使用 dispatch：检查输出中的 `ahk_attempts` 与 `ahk_auto_resend_triggered`。
4. 若消息已送达但对话中断，优先判定为 chat worker 问题（例如 OOM），不要先怀疑发送链路。
5. 若结果为 `sent=False` 且 `ahk_exit_code=38`，表示“发送前聊天输入焦点校验未通过”，这是防误投到终端的保护命中。

## 2. 常见故障 -> 处理动作

### A. AHK 弹 Warning 窗口后卡住（超时）

现象：
- 弹窗提示类似 `A_CaretX` / `A_CaretY`。
- PowerShell 报 `AHK dispatch timed out after ... ms`。

处理：
- 已修复为 `CaretGetPos` 路径；确认你在用最新 `send_chat_message_ahk.ps1`。
- 若仍出现，先执行一次：
  - `& .\tools\test\send_chat_message_ahk.ps1 -Message "ahk-warning-check" -DryRun`

### B. 发送成功率下降（窗口经常被其它应用覆盖）

现象：
- 外部终端/邮件客户端常在前台。

处理：
- 保持默认策略：前台抢占 + 最大化 + 安全区点击。
- 不要加 `-NoActivateWindow`。
- 若历史脚本在外部终端误加了 `-NoActivateWindow`，且当前前台不是 VS Code，发送脚本会在“未启用 `-RequireActiveCodeWindow`”前提下自动改为允许激活窗口，并在结果对象 `code_focus_policy` 中标记：`no_activate_window_auto_disabled=True`。
- 如必须禁最大化，可显式 `-NoMaximizeCodeWindow`，但稳定性会下降。

### C. 聊天面板隐藏时命中失败

处理：
- 默认启用保守恢复（快捷键 `Ctrl+Alt+B`）。
- 若团队键位不同，在 start file 设置：
  - `AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT=<your-shortcut>`

### D. 对话显示 OOM / worker terminated

现象：
- `Worker terminated due to reaching memory limit: JS heap out of memory`。

处理：
- 这通常是 chat worker 响应阶段故障，不是发送侧故障。
- 当前链路支持“一次自动补发”兜底；查看：
  - `ahk_auto_resend_triggered=True/False`
  - `ahk_auto_resend_reason`

### E. Heartbeat 超时发送被严格聚焦防护拦截

现象：
- dispatch 日志出现 `heartbeat_timeout_require_code_focus=True`，并伴随 `ahk_reason` 或结果备注 `required-code-chat-focus-failed`。

处理：
- 这是保守防护在生效，不是异常：当 heartbeat 超时发送被启用时，发送前必须先通过 VS Code 命令成功聚焦聊天输入框。
- 若确需放宽（不建议），可在 start file 设置 `AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_REQUIRE_CODE_FOCUS=false`。

### F. 消息误投到集成终端

现象：
- 聊天面板隐藏或可见时，脚本执行后文本出现在集成终端。

处理：
- 默认策略不再依赖面板命令聚焦，优先使用窗口激活 + 安全区点击聚焦，避免顶部搜索框/QuickPick 抖动。
- 如果焦点无法确认，脚本会返回 `ahk_exit_code=38` 并停止发送（宁可失败，不会盲发到终端）。
- 如需显式走面板命令聚焦（仅用于定向排障），可手动加 `-EnablePaletteFocusCommand`。

## 3. 无人值守链路检查点

1. trigger 是否启用：
- `EXTERNAL_TRIGGER_EXECUTE=true`
- `AUTO_START_TAKEOVER_TRIGGER=true`

2. dispatch 是否启用 AHK：
- `AI_CHAT_DISPATCH_USE_AHK=true`
- `AI_CHAT_DISPATCH_AHK_EXE=<AutoHotkey64.exe path>`

3. 推荐默认策略键（可按需覆盖）：
- `AI_CHAT_DISPATCH_AUTO_RECONNECT_RESEND=true`
- `AI_CHAT_DISPATCH_RECONNECT_DELAY_MS=1800`
- `AI_CHAT_DISPATCH_RECONNECT_WINDOW_SEC=300`
- `AI_CHAT_DISPATCH_MAXIMIZE_WINDOW=true`
- `AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT_ENABLED=false`
- `AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT=^!b`
- `AI_CHAT_DISPATCH_X_MODE=right-offset`
- `AI_CHAT_DISPATCH_RIGHT_OFFSET_PX=300`
- `AI_CHAT_DISPATCH_BOTTOM_AVOID_PX=170`
- `AI_CHAT_DISPATCH_PRESEND_DELAY_MS=700`
- 模板/默认已设置 `AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY=false`，适合 A/B 监控进程在外部终端常驻时由 dispatch 主动拉起 VS Code 发送；若需严格限制“仅当前前台已是 VS Code 才允许发送”，可改为 `true`。
- `AI_CHAT_HEARTBEAT_WRITE_ON_POLL=false`（推荐，避免非会话轮询误续命）

4. 无人值守启动前硬约束与运行策略（建议强制）：
- 启动无人值守前，应在目标聊天会话中发出启动指令；此时默认聊天面板已打开。
- 启动前做一次人工确认：聊天输入框可见且可输入（光标在输入区）。
- 运行中不做“每条消息发送前的聊天面板开关态预检”；保持现有发送路径，避免额外焦点抖动。
- 仅在焦点保护失败时恢复：若出现 `ahk_exit_code=38` 或 `ahk_exit_code=41`，执行一次聊天面板恢复（`workbench.action.chat.open` + `workbench.action.chat.focusInput` 或 `repro_chat_panel_hide_by_esc.ps1`），随后重发。
- 当前 `dispatch_takeover_to_chat.ps1` 已内置一次 38/41 失败后的自动恢复重发（failure-driven recovery）；若该次恢复仍失败，再按日志手工排障。

5. 会话存活心跳建议由聊天回合主动发出（而不是由 poll 脚本被动写入）：

```powershell
& .\tools\test\update_chat_session_heartbeat.ps1 -StartFile "testdata\unattended_start\active\unattended_ab_start_20260504-1123.md" -Source "chat-session-active" -AsJson
```

## 4. 最小验证命令

直接发送验证：

```powershell
& .\tools\test\send_chat_message_ahk.ps1 -Message "chat-send-selftest"
```

无人值守分发集成验证（真实 AHK，避免编辑器/剪贴板副作用）：

```powershell
& .\tools\test\dispatch_takeover_to_chat.ps1 -TicketId "ahk-integ-selftest" -TicketEvent "chat-recovery-selftest" -StartFile "testdata\unattended_start\smoke\unattended_ab_start_status_ticket_smoke.md" -UseAhk -NoOpenEditor -SkipClipboard
```

状态票抑制路径验证（不触发交互动作）：

```powershell
& .\tools\test\dispatch_takeover_to_chat.ps1 -TicketId "ahk-status-selftest" -TicketEvent "running-status-report" -StartFile "testdata\unattended_start\smoke\unattended_ab_start_status_ticket_smoke.md" -UseAhk
```

聊天面板显示/隐藏切换（单命令模式，推荐）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/repro_chat_panel_hide_by_esc.ps1 -Mode toggle -EscCount 0 -ObserveDelayMs 1200 -TargetWindowTitle "whois" -ChatToggleShortcut "^!b" -AhkExePath "C:/Users/妙妙呜/AppData/Local/Programs/AutoHotkey/v2/AutoHotkey64.exe"
```

聊天面板显示/隐藏切换（最短写法，省略默认 `-Mode toggle`）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/repro_chat_panel_hide_by_esc.ps1 -EscCount 0 -ObserveDelayMs 1200 -TargetWindowTitle "whois" -ChatToggleShortcut "^!b" -AhkExePath "C:/Users/妙妙呜/AppData/Local/Programs/AutoHotkey/v2/AutoHotkey64.exe"
```

聊天面板切换后补发 Esc（对照模式）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/repro_chat_panel_hide_by_esc.ps1 -Mode toggle -EscCount 1 -ObserveDelayMs 1200 -TargetWindowTitle "whois" -ChatToggleShortcut "^!b" -AhkExePath "C:/Users/妙妙呜/AppData/Local/Programs/AutoHotkey/v2/AutoHotkey64.exe"
```

说明：旧模式 `toggle-shortcut` 与 `toggle-then-esc` 仍兼容，但内部已统一映射到 `-Mode toggle`。

排障汇总固定命令模板（文本模式）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/summarize_chat_dispatch_incident.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20260504-1123.md" -Last 12
```

排障汇总固定命令模板（JSON 模式）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/summarize_chat_dispatch_incident.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20260504-1123.md" -Last 12 -AsJson | Out-String
```

按 ticket 精确取证（推荐与 smoke/no-send 验证配套）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/summarize_chat_dispatch_incident.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20260504-1123.md" -TicketId "<ticket-id>" -AsJson | Out-String
```

## 5. 证据与日志位置

- Dispatch 日志：`out/artifacts/ab_agent_queue/chat_dispatch/dispatch_<start-token>.log`
- Relay 文件：`out/artifacts/ab_agent_queue/chat_dispatch/relay_*.md`
- Trigger 日志：`out/artifacts/ab_agent_queue/takeover_trigger_<start-token>.log`
- 会话心跳：`out/artifacts/ab_agent_queue/chat_session_heartbeat_<start-token>.json`

结论判定优先级：
- 先看脚本返回与 dispatch 日志。
- 再看 chat worker 是否存在 OOM/重连事件。
- 不要把“等待回复阶段的 worker 中断”误判成“发送失败”。
