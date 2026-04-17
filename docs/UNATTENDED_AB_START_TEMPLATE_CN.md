# A/B 无人值守启动文本模板（CN）

## 强绑定句（建议原样保留）
进入实时监控，按 D1 固定容忍窗口策略判挂（90/30/10/20，重启前先留证）。

## 触发文本模板（复制后按需替换）
请执行 A/B 无人值守串行重跑（前台可见模式，单参提速入口）：

- A 任务定义：`testdata/<A_TASK_DEFINITION>.json`
- B 任务定义：`testdata/<B_TASK_DEFINITION>.json`
- 目标时间窗：`<YYYY-MM-DD ~ YYYY-MM-DD>`

工作要求：
1. 执行前必须完成无人值守运行环境检查（本地与远端无残留相关进程、SSH 连通、任务定义文件存在且无 TODO、记录当前工作区状态）；检查未通过不得启动 A/B。
2. 严格串行：先 A 后 B。
3. B 启动时不得回滚 A 基线（state-only）。
4. 全程持续实时监控并报告状态。
5. D1 判挂必须按固定运行策略：
   - 90 分钟窗口。
   - 前 30 分钟仅观测。
   - 30~90 分钟每 10 分钟做进展判定。
   - 仅当三条件连续 20 分钟同时成立才判挂并重跑。
6. 发生卡滞或需要重启时：
   - 先保留快照证据（进程快照、产物目录快照、summary_partial 若存在）。
   - 再关闭本地和远端相关进程。
   - 最后重启无人值守进程。
7. 会话中禁止提前结束，直到 A/B 都有最终结论。
8. 归档口径：只有 A/B 运行成功后，运行结果统一回填到 RFC 文档，不回填本模板。
9. A -> B 切换前必须获取 A 成功快照（至少包含：A 的 `final_status.json` 路径、`summary.csv` 路径、A 结束时源码状态摘要），并记录在本轮任务启动文件中。
10. 若 B 任一轮次出现编译失败：
   - 优先仅重启 B（不回到 A），但必须先将源码恢复到 A 成功快照状态，再应用修订后的 B 任务定义并从 B-D1 重新执行。
   - 若无法可靠恢复到 A 成功快照，则按保守策略从 A 重新执行，再串行进入 B。

建议执行命令（单参提速入口）：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_A.ps1 <A_TASK_DEFINITION>.json
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_B.ps1 <B_TASK_DEFINITION>.json
```

## 本轮默认示例
- A：`autopilot_code_step_tasks_20260613_20260620.json`
- B：`autopilot_code_step_tasks_20260621_20260628.json`

## 任务启动文件（推荐每轮同时生成）
为避免发布任务时手填错误，建议每次在起草“下次开工清单 + 任务定义文件”后，同时生成一个可直接触发执行的任务启动文件（纯文本即可，建议放在 `tmp/` 目录）。

建议文件名：
- `tmp/unattended_ab_start_<YYYYMMDD-HHMM>.md`

建议内容模板（复制后替换尖括号）：
```text
AB_UNATTENDED_START_V1
A_TASK_DEFINITION=testdata/<A_TASK_DEFINITION>.json
B_TASK_DEFINITION=testdata/<B_TASK_DEFINITION>.json
WINDOW=<YYYY-MM-DD ~ YYYY-MM-DD>
RESET_POLICY_A=restore-source
RESET_POLICY_B=state-only
START_ROUND=1
END_ROUND=8
DEV_VERIFY_STRIDE_A=2
DEV_VERIFY_STRIDE_B=2
VERIFY_EXECUTION_PROFILE=d6-only
ENABLE_GUARDED_FAST_MODE=true
ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP=true
TASK_DESIGN_QUALITY_POLICY=enforce
UNKNOWN_NOOP_BUDGET=1
UNKNOWN_NOOP_CONSECUTIVE_LIMIT=2
DISABLE_UNKNOWN_NOOP_BUDGET_GATE=false
RB_PREFLIGHT=1
RB_PRECLASS_TABLE_GUARD=1
REMOTE_IP=10.0.0.199
REMOTE_USER=larson
REMOTE_KEYPATH=/c/Users/妙妙呜/.ssh/id_rsa
QUERIES=8.8.8.8 1.1.1.1 10.0.0.8
MONITOR_POLICY_D1=90/30/10/20
RESULT_BACKFILL_TARGET=RFC_ONLY
A_SUCCESS_SNAPSHOT_REQUIRED=true
A_SUCCESS_SNAPSHOT_FINAL_STATUS=<out/artifacts/dev_verify_multiround/<A_RUN>/final_status.json>
A_SUCCESS_SNAPSHOT_SUMMARY=<out/artifacts/dev_verify_multiround/<A_RUN>/summary.csv>
B_FAILURE_RECOVERY=prefer-restart-b-from-a-snapshot
B_FAILURE_FALLBACK=rerun-a-then-b-if-snapshot-unreliable
```

### 与 Copilot 协作触发方式
你可直接下达：
- 按 `tmp/unattended_ab_start_<YYYYMMDD-HHMM>.md` 启动 A/B 无人值守任务。

执行约定：
1. 我先做预检并回显解析参数，再按 A -> B 严格串行启动。
2. 我按 D1 固定容忍窗口策略实时监控并处理卡滞重启（先留证再清场再重启）。
3. 仅在 A/B 运行成功后，运行结果统一回填 RFC，不回填本模板。
4. A 成功后我会先固化 A 成功快照，再启动 B；若 B 编译失败，将优先按“A 快照恢复 -> B 重启”路径执行。
5. 仅当 A 快照无法可靠恢复时，我才会建议并执行“从 A 重新开始”的保守路径。
