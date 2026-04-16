# A/B 无人值守启动文本模板（CN）

## 强绑定句（建议原样保留）
进入实时监控，按 D1 固定容忍窗口策略判挂（90/30/10/20，重启前先留证）。

## 触发文本模板（复制后按需替换）
请执行 A/B 无人值守串行重跑（前台可见模式，单参提速入口）：

- A 任务定义：`testdata/<A_TASK_DEFINITION>.json`
- B 任务定义：`testdata/<B_TASK_DEFINITION>.json`
- 目标时间窗：`<YYYY-MM-DD ~ YYYY-MM-DD>`

工作要求：
1. 严格串行：先 A 后 B。
2. B 启动时不得回滚 A 基线（state-only）。
3. 全程持续实时监控并报告状态。
4. D1 判挂必须按固定运行策略：
   - 90 分钟窗口。
   - 前 30 分钟仅观测。
   - 30~90 分钟每 10 分钟做进展判定。
   - 仅当三条件连续 20 分钟同时成立才判挂并重跑。
5. 发生卡滞或需要重启时：
   - 先保留快照证据（进程快照、产物目录快照、summary_partial 若存在）。
   - 再关闭本地和远端相关进程。
   - 最后重启无人值守进程。
6. 会话中禁止提前结束，直到 A/B 都有最终结论。

建议执行命令（单参提速入口）：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_A.ps1 <A_TASK_DEFINITION>.json
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_B.ps1 <B_TASK_DEFINITION>.json
```

## 本轮默认示例
- A：`autopilot_code_step_tasks_20260613_20260620.json`
- B：`autopilot_code_step_tasks_20260621_20260628.json`
