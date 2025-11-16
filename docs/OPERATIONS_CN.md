# whois 操作与发布手册（中文）

英文版见：`docs/OPERATIONS_EN.md`

本手册汇总日常“提交/发布/远端构建/镜像到 Gitee”相关的常用操作与注意事项，便于随时查阅。

链接风格转换说明请参考：`docs/RELEASE_LINK_STYLE.md`（绝对直链与相对路径的切换策略与脚本）。

---

## 一键发布（Windows PowerShell）

入口脚本：`tools/release/full_release.ps1`（内部调用 Bash 脚本 `tools/release/full_release.sh`）

常用用法：

- 默认发布（自动补丁位 + 联网冒烟）
  ```powershell
  .\tools\release\full_release.ps1
  ```
- 指定多查询目标（空格分隔）
  ```powershell
  .\tools\release\full_release.ps1 -Queries "8.8.8.8 1.1.1.1"
  ```
- 跳过冒烟测试（更快）
  ```powershell
  .\tools\release\full_release.ps1 -NoSmoke
  ```
- 手动指定 Tag（例如 v3.1.10）
  ```powershell
  .\tools\release\full_release.ps1 -Tag v3.1.10
  ```
- 指定 lzispro 路径（当不在 whois 同级目录时）
  ```powershell
  .\tools\release\full_release.ps1 -LzisproPath "D:\\LZProjects\\lzispro"
  ```
- 演练（不做变更）
  ```powershell
  .\tools\release\full_release.ps1 -DryRun -NoSmoke -Queries "8.8.8.8 1.1.1.1"
  ```

参数说明：
- `-Tag vX.Y.Z`：省略则自动把最新标签补丁位 +1
- `-Queries "..."`：供冒烟测试使用；当 `-NoSmoke` 时会被忽略（脚本会打印提醒）
- `-NoSmoke`：跳过联网冒烟测试
- `-LzisproPath`：可显式传入 lzispro 路径（自动转换为 MSYS `/d/...`）
- `-DryRun`：只打印步骤，不执行

产物与日志：
- 7 个静态二进制会同步到：`<lzispro>/release/lzispro/whois/`
- 详细日志：`whois/out/release_flow/<timestamp>/step1_remote.log`
- 严格模式：默认将 Warnings 视为失败并提前退出（STRICT_WARN=1）

---

## 远端交叉编译启动器（本地）

脚本：`tools/remote/remote_build_and_test.sh`

关键参数（可用 `-h` 查看完整帮助）：
- `-t`：目标架构（默认：`aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64`）
- `-r 0|1`：是否跑冒烟测试
- `-q "8.8.8.8 example.com"`：冒烟测试查询目标（空格分隔）
- `-a` 追加冒烟参数（示例：`-a '-g Org|Net|Country'`）。更新：VS Code 任务现已统一为参数值加引号并安全引用，`rbSmokeArgs` 输入框直接填内容（如：`-g Domain|Registrar|Name Server|DNSSEC`）或留空表示无额外参数；不再推荐裸 `--` 作为占位。显式空值可留空或输入 `''`。`-g` 为不区分大小写的“前缀匹配”，不是正则；需正则过滤请用 `--grep/--grep-cs`。
- `-s <dir>`：把 whois-* 同步到本机某目录（配合 `-P 1` 可在同步前清理非 whois-*）
- `-o/-f`：远端输出目录、本地拉取目录基准（默认 `out/artifacts/<ts>/build_out`）

## Git 提交与推送（SSH）

```powershell
# 确认远程地址为 SSH（示例：git@github.com:larsonzh/whois.git）
git remote -v

git add -A
git commit -m "your change"

# 同步与推送（推荐先 rebase）
git pull --rebase origin master
git push origin master

# 打标签（发布现需手动触发工作流）
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
# 首次添加（按你的仓库改）
git remote add gitee git@gitee.com:larsonzh/whois.git
# 后续推送
git push gitee master
git push gitee --tags
```

## 三跳模拟与重试指标（3.2.7+）

目的：在不破坏“头/尾契约”的前提下，稳定复现 `apnic → iana → arin` 三跳链路，并通过连接级别的重试指标观测成功/失败与错误分类。

关键标志（组合使用）：
- `--selftest-force-iana-pivot`：仅首次强制从区域 RIR 透传至 IANA，后续按真实 referral 继续（解锁三跳链路）。
- `--selftest-blackhole-arin` / `--selftest-blackhole-iana`：模拟最终跳/中间跳“连接超时”。
- `--retry-metrics`：开启每次连接尝试与聚合统计输出。
- `-t 3 -r 0`：连接超时 3s，禁用通用重试（仅观察连接内部的多候选/多次尝试）。
- `--ipv4-only`：在特定网络环境下提升确定性（可选）。

示例 1（最终跳失败：arin 被黑洞）：
```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois; \
tools/remote/remote_build_and_test.sh -H <host> -u <user> -k '<key>' -r 1 -q '8.8.8.8' \
  -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 \
  -a '--host apnic --selftest-force-iana-pivot --selftest-blackhole-arin --retry-metrics -t 3 -r 0 --ipv4-only' -G 0 -E ''"
```
输出特征（节选）：
```
[RETRY-METRICS-INSTANT] attempt=1 success=1 ...
[RETRY-METRICS-INSTANT] attempt=2 success=1 ...
Error: Query failed for 8.8.8.8 (connect timeout, errno=110|145)
[RETRY-METRICS] attempts=7 successes=2 failures=5 ... p95_ms≈3000
[RETRY-ERRORS] timeouts=5 refused=0 net_unreach=0 host_unreach=0 addr_na=0 interrupted=0 other=0
=== Authoritative RIR: whois.arin.net @ unknown ===
```

示例 2（中间跳失败：iana 被黑洞）：
```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois; \
tools/remote/remote_build_and_test.sh -H <host> -u <user> -k '<key>' -r 1 -q '8.8.8.8' \
  -s '/d/LZProjects/lzispro/release/lzispro/whois' -P 1 \
  -a '--host apnic --selftest-force-iana-pivot --selftest-blackhole-iana --retry-metrics -t 3 -r 0 --ipv4-only' -G 0 -E ''"
```
输出特征（节选）：
```
[RETRY-METRICS-INSTANT] attempt=1 success=1 ...
Error: Query failed for 8.8.8.8 (connect timeout, errno=110|145)
[RETRY-METRICS] attempts≈5–8 successes≥1 failures≥1 p95_ms≈3000
[RETRY-ERRORS] timeouts>0 其余通常为 0
=== Authoritative RIR: whois.iana.org @ unknown ===
```

提示：
- 冒烟的超时策略对含 `--retry-metrics` 的运行更宽松：默认 `SMOKE_TIMEOUT_ON_METRICS_SECS=45`，先发送 SIGINT，5s 后必要时再 SIGKILL，避免丢失尾部聚合指标；常规运行默认 8s（`SMOKE_TIMEOUT_DEFAULT_SECS`）。
- 多同步目录：`-s` 支持以分号分隔的多个本地目标；脚本会归一化并逐一同步。
- 指标含义：
  - `[RETRY-METRICS-INSTANT]` 为“单次连接尝试”的即时报文。
  - `[RETRY-METRICS]` 为汇总统计（attempts/successes/failures/min/max/avg/p95/sleep_ms）。
  - `[RETRY-ERRORS]` 为“连接阶段 errno 分类统计”（仅统计 connect() 级别错误）：若连接成功但后续读取阶段超时，则可能出现“失败计入 [RETRY-METRICS]、而 [RETRY-ERRORS] 不增”的现象。

说明：Git 的 SSH 与远端构建机的 SSH（用于交叉编译）是两回事，互不影响。

---

## CI 简述（GitHub Actions）

工作流文件：`.github/workflows/build.yml`、`.github/workflows/publish-gitee.yml`

触发：
- push 到 main/master（常规构建与产物归档）
- PR（常规构建与产物归档）
- push 打标签 `vX.Y.Z`（触发 build.yml 的 `release` 任务，创建/更新 Release 并上传资产）
- 手动触发（workflow_dispatch）：可在 build.yml 的 `release` 任务中输入 tag 重跑；`publish-gitee.yml` 可手动补发到 Gitee

主要 Job：
- `build-linux`：构建 `whois-x86_64-gnu` 并保存为构建产物
- `release`（标签推送或手动触发）：
  - 收集 whois 仓库 `release/lzispro/whois/` 的 7 个静态二进制
  - 生成合并的 `SHA256SUMS.txt`
  - 创建/更新 GitHub Release，上传所有资产（支持覆盖同名资产）
  - 可选：若设置了 Secrets（见下），在 Gitee 创建同名 Release，正文附 GitHub 下载直链
  - 如需后续改为仓库相对路径以改善国内网络体验，可使用 `relativize_static_binary_links.sh`（详见 `docs/RELEASE_LINK_STYLE.md`）

  - `GITEE_OWNER`（如：`larsonzh`）
  - `GITEE_REPO`（如：`whois`）
  - `GITEE_TOKEN`（你的 Gitee PAT，具备发布权限）
- 验证：发布 Job 日志显示 `Gitee create release HTTP 200/201` 即成功；未配置将自动跳过

提示（远程 SSH）：
- 仓库不再提供依赖远程 SSH 的工作流。如需在 CI 中执行远程构建，请使用自托管 Runner；常规情况下建议在本机使用 `tools/remote/remote_build_and_test.sh` 完成交叉编译与冒烟。
- 如遇 SSH 连接问题，可设置环境变量 `WHOIS_DEBUG_SSH=1`，脚本会开启 `ssh -vvv` 详细日志以便排查。

---

## 故障排查速查

- 第一步失败或有告警：查看 `whois/out/release_flow/<ts>/step1_remote.log`（默认严格模式，Warning 也会中止）
- `-NoSmoke` 与 `-Queries` 同时使用：Queries 会被忽略（脚本会打印提示）
- Windows 路径：PowerShell 包装器会自动把 `D:\...` 转为 `/d/...`
- 多查询参数：PowerShell 已修复自动引用，`-Queries "8.8.8.8 1.1.1.1"` 可直接使用
- Gitee 步骤失败：不阻断 GitHub 主发布；日志会打印返回码与响应体
- 自 v3.2.0 起，`out/artifacts/` 不再纳入版本控制；如需清理本地历史产物，使用 `tools/dev/prune_artifacts.ps1`（支持 `-DryRun`）。
- `out/`、`release_assets/`：已在 `.gitignore` 忽略，避免误提交

### Lookup 自检与“空响应”回退验证（3.2.6+）

目的：在网络可用的前提下，快速验证“连接失败/空正文”统一回退策略是否生效，且不改变既有头/尾契约。

方法：
- 直接运行自测（含 lookup 覆盖）：
  ```powershell
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -a '--selftest'"
  ```
- 显式触发“空响应注入”路径（需要网络）：
  ```powershell
  $env:WHOIS_SELFTEST_INJECT_EMPTY = '1'; & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./out/build_out/whois-x86_64 --selftest"; Remove-Item Env:\WHOIS_SELFTEST_INJECT_EMPTY
  ```

说明：lookup 自测为建议性检查（网络影响较大），失败会记录但不改变自测退出码；核心自测（折叠/重定向）仍决定 `--selftest` 的总体通过/失败。

---

## 术语

- CI（Continuous Integration，持续集成）：在服务器自动执行构建/测试/打包/检查，保证主干可构建、问题早发现
- CD（Continuous Delivery/Deployment）：在 CI 通过后自动交付/部署（发布版本、上线等）

---

## 快速清单（Cheat Sheet）

- 发布（自动补丁 + 冒烟）：`.\\tools\\release\\full_release.ps1`
- 跳过冒烟：`.\\tools\\release\\full_release.ps1 -NoSmoke`
- 多查询：`.\\tools\\release\\full_release.ps1 -Queries "8.8.8.8 1.1.1.1"`
- 指定 Tag：`.\\tools\\release\\full_release.ps1 -Tag vX.Y.Z`
- 日志：`whois/out/release_flow/<ts>/step1_remote.log`
- Gitee Secrets：`GITEE_OWNER / GITEE_REPO / GITEE_TOKEN`

---

## 快速提交（可选）

- 脚本：`tools/dev/quick_push.ps1`
- 用法示例：
  ```powershell
  # 推送到 origin master（自动 add/commit/pull --rebase/push）
  .\tools\dev\quick_push.ps1 -Message "fix: xxx"

  # 同时推送到 gitee 远程
  .\tools\dev\quick_push.ps1 -Message "docs: update" -PushGitee

  # 推送其它分支
  .\tools\dev\quick_push.ps1 -Message "feat: abc" -Branch develop

  # 同时推送标签（若已本地创建）
  .\tools\dev\quick_push.ps1 -Message "release" -PushTags
  ```
- 注意：
  - 若无改动且未加 `-AllowEmpty`，脚本会提示“不存在需要提交的变更”。
  - 使用 `-PushGitee` 前需先 `git remote add gitee git@gitee.com:<owner>/<repo>.git`。

### VS Code 任务

已内置任务（Terminal → Run Task）：
- Git: Quick Push
- Remote: Build and Sync whois statics（远端一键构建并同步 7 个静态二进制）

使用说明：
- 运行任务后会弹出参数输入框（可保留默认再按需修改）：
  - Remote build host (SSH)：远端主机（IP/域名）
  - Remote SSH user：默认 ubuntu
  - Private key path：私钥路径（Git Bash 风格，如 /c/Users/you/.ssh/id_rsa）
  - Run smoke tests?：1/0 是否在远端对产物做联网冒烟
  - Smoke queries：冒烟查询目标（空格分隔）
  - Local sync dir：本机同步目录（Git Bash 路径），默认 `/d/LZProjects/lzispro/release/lzispro/whois`
- 任务会在远端交叉编译完成后，把 7 个静态二进制拉回并同步到本机目录；同步前用 `-P 1` 清理非 `whois-*` 文件，保持目录整洁。

运行时会弹出输入框填写 commit message。

注意：根据当前策略，不建议自动向 Gitee 推送代码；如需同步，请在 Gitee 侧手动执行或单次使用命令行推送以避免双向冲突。

---

## 打标签发布（可选）

- 脚本：`tools/dev/tag_release.ps1`
- 用法：
  ```powershell
  .\tools\dev\tag_release.ps1 -Tag v3.1.10 -Message "Release v3.1.10"
  # 可选同步到 gitee：
  .\tools\dev\tag_release.ps1 -Tag v3.1.10 -PushGitee
  ```
- 说明：
  - 会校验格式 `vX.Y.Z`，并检查同名标签是否已存在；创建后自动推送到 origin。
  - 推送标签会触发 GitHub Actions 的发布流程，自动创建 Release 并上传产物。

### 重新生成同名版本的发布（删除并重建标签）

适用场景：需要替换已发布版本的资产（例如更新为最新静态二进制），且保持版本号不变（如 `v3.2.7`）。

步骤：
1) 若 GitHub 页面上仍存在同名 Release，请先删除该 Release 页面（不会影响代码）。
2) 删除本地与远端同名标签：
  ```powershell
  git tag -d vX.Y.Z
  git push origin :refs/tags/vX.Y.Z
  ```
3) 准备最新静态产物（任选其一）：
  - 运行 VS Code 任务“Remote: Build and Sync whois statics”
  - 或执行一键发布任务/脚本并开启构建同步：`One-Click Release`（`buildSync=true`），将 whois 仓库 `release/lzispro/whois/` 目录内的 7 个静态产物更新、提交并推送
4) 重建并推送同名标签：
  ```powershell
  git tag -a vX.Y.Z -m "Release vX.Y.Z"
  git push origin vX.Y.Z
  ```
5) 等待发布工作流重新运行并收集 whois 仓库 `release/lzispro/whois/` 的 7 个静态二进制与 `SHA256SUMS.txt`。
6) 仅需更新发布正文而不改标签时，可执行：
  ```powershell
  .\tools\release\one_click_release.ps1 -Version X.Y.Z -SkipTagIf true
  ```

提示：当前发布流程已与 lzispro 仓库解耦，资产来源为 whois 仓库内的 `release/lzispro/whois/`，非 lzispro 仓库路径。

---

  ## 开发者附注：安全日志自测钩子（可选，默认关闭）

  目的：快速验证 `--security-log` 的“限频防洪”是否生效，而无需构造复杂的网络场景。该钩子仅在你显式开启时运行，不改变正常行为。

  启用方式（需同时满足）：
  - 构建时：为 whois 加上编译宏 `-DWHOIS_SECLOG_TEST`
  - 运行时：设置环境变量 `WHOIS_SECLOG_TEST=1`

  运行效果：程序启动早期会向安全日志打出一小段高频事件，用于触发与观察限频；事件仅输出到 stderr，stdout 的“标题/尾行”契约不受影响。结束后自动恢复原先的 `security_logging` 设置。

  示例（本机 Linux）：
  ```bash
  make CFLAGS_EXTRA="-DWHOIS_SECLOG_TEST"
  WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help
  ```

  示例（通过 SSH 在远端 Linux 主机执行）：
  ```bash
  ssh ubuntu@203.0.113.10 '
    cd ~/whois && \
    make CFLAGS_EXTRA="-DWHOIS_SECLOG_TEST" && \
    WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help
  '
  ```

  示例（Windows PowerShell，远端自测，推荐）：
  ```powershell
  # 1) 准备远端工作目录（与旧目录隔离）
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@remote 'rm -rf ~/whois-wip; mkdir -p ~/whois-wip'

  # 2) 上传本地 whois 项目（请按需替换本地路径、远端账户与主机）
  scp -r -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "D:/LZProjects/whois/*" user@remote:~/whois-wip/

  # 3) 远端编译并运行自测（宏 + 环境变量 同时开启）
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@remote `
    'cd ~/whois-wip && make clean || true; make CFLAGS_EXTRA=-DWHOIS_SECLOG_TEST && WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help'
  ```

  提示：
  - 可执行文件名为 `whois-client`（静态可选 `whois-client.static`）。
  - `--help` 仅用于快速退出流程，便于观察 stderr 的 SECURITY 行与“抑制汇总”。
  - Windows 需已安装 OpenSSH（PowerShell 可直接运行 `ssh/scp`）。

  说明：
  - `--help` 仅用于快速退出流程，便于你观察到 stderr 的 SECURITY 行与“抑制汇总”提示；也可以换成任意命令行，不影响自测。
  - 未加编译宏或未设置环境变量时，自测钩子不会运行。

  ---

  ## 开发者附注：grep 过滤自测钩子（可选）

  目的：在不依赖真实 WHOIS 响应的情况下，验证 wc_grep 在块模式与行模式下的匹配与续行保留逻辑是否正确。

  启用条件（需同时满足）：
  - 构建：加入编译宏 `-DWHOIS_GREP_TEST`
  - 运行：设置环境变量 `WHOIS_GREP_TEST=1`

  运行效果：程序启动时用内置的微型样本做三轮过滤测试，输出：
  ```
  [GREPTEST] block mode: PASS
  [GREPTEST] line mode (no-cont): PASS
  [GREPTEST] line mode (keep-cont): PASS
  ```
  若失败，会附带 `[GREPTEST-OUT]` 行列出产生的输出，便于快速定位。

  示例（本地 Linux）：
  ```bash
  make CFLAGS_EXTRA="-DWHOIS_GREP_TEST"
  WHOIS_GREP_TEST=1 ./whois-client --help 2>&1 | grep GREPTEST || true
  ```

  示例（Windows 远端脚本）：
  ```powershell
  # 使用远端构建脚本 -X 1 一次性开启编译宏与运行期环境变量
  & 'C:\Program Files\Git\bin\bash.exe' -lc "tools/remote/remote_build_and_test.sh -H <host> -u <user> -k '<key>' -r 1 -q '8.8.8.8 1.1.1.1' -s '<sync_dir>' -P 1 -a '' -G 0 -E '-O3 -s' -X 1"
  ```

  启发式（当前逻辑简述）：
  - Header 必须从第 0 列开始；任意前导空白的行视为续行。
  - 块模式：保留匹配块的续行，过滤无关续行。
  - 为避免把首个“看起来像 header 的”缩进行（如地址行）错误丢弃，允许全局保留第一个此类缩进行；后续若继续出现 header-like 缩进行则需匹配正则才保留。

  说明：
  - 行模式由 `--grep-line` 开启，`--grep-line-keep-cont` 控制是否保留续行。
  - 未同时满足编译宏与环境变量时，自测逻辑完全禁用，不影响正常输出。

  ---

## 后续规划（RFC）

- 条件输出（Phase 2.5）：通过参数化过滤/投影与轻量统计，降低外部脚本负担并提升性能；默认行为保持不变，全部能力为可选开启。
  - 设计文档（RFC）：`docs/RFC-conditional-output-CN.md`
  - 第一阶段（v3.2.0 目标）：基础过滤（RIR/家族/私网/状态）、`--no-body` 抑制正文、`--print meta` 元信息行与 `--fields` 字段选择、`--stats` 统计。

### VS Code 任务

- Git: Tag Release（会弹出输入框填写 tag 与 message）

---

## 手动补发 Gitee Release（publish-gitee-manual）

适用场景：历史标签发布时，CI 因缺少 target_commitish 导致“Publish release to Gitee”返回 400，或你想对已存在的 GitHub Release 进行“补发到 Gitee”。该流程不会把代码/标签推到 Gitee，仅创建 Gitee Release 页面并附上 GitHub 下载直链。

前置条件：在 GitHub 仓库 Settings → Secrets 配置以下项（与自动发布相同）：
- GITEE_OWNER：Gitee 用户/组织名
- GITEE_REPO：Gitee 仓库名
- GITEE_TOKEN：Gitee PAT（需具备创建发布的权限）
- 可选 GITEE_TARGET_COMMITISH：若不设，默认 `master`（用于在 Gitee 端创建 tag 时的指向）

操作步骤：
1) GitHub → Actions → 选择工作流 `publish-gitee-manual`
2) 右上角 Run workflow：
   - tag：如 `v3.2.0`
   - target_commitish：默认为 `master`（可改为具体分支/提交）
3) 运行完成后，在步骤“Publish release to Gitee (manual)”看到 `Gitee create release HTTP 201/200` 即成功。

说明：
- 本工作流仅创建 Gitee Release 页面，正文来自 `RELEASE_NOTES.md` 并追加 GitHub Releases 的下载直链。
- 不会向 Gitee 仓库推送代码/标签；若确需镜像 refs，请在 Gitee 账户添加 SSH 公钥后，手动执行：
  - `git push gitee master`
  - `git push gitee --tags`
- 自 v3.2.1（及之后新标签）起，CI 的自动发布已包含 `target_commitish`，通常无需再手动补发。

---

## VS Code 任务（新增：One-Click Release）

除了已有的“Git: Quick Push”和“Remote: Build and Sync whois statics”，现新增任务：

- One-Click Release（调用 `tools/release/one_click_release.ps1`，用于快速更新 GitHub/Gitee Release；可选择是否跳过创建/推送标签；支持可选的“远程编译+冒烟+同步并推送静态二进制”）

运行后会出现以下输入项：
- releaseVersion：纯版本号，不带 `v`（用于拼接 `docs/release_bodies/vX.Y.Z.md`）
- releaseName：发布显示名称（GitHub/Gitee 共用，默认 `whois v<version>`）
- skipTag：是否跳过创建/推送标签（`true`/`false`）
 - buildSync：是否执行“远程编译 + 冒烟 + 同步静态二进制并提交推送”（默认 `true`）
 - 远程构建参数：`rbHost/rbUser/rbKey/rbSmoke/rbQueries/rbSmokeArgs/rbGolden/rbCflagsExtra/rbSyncDir`
   - 同步目录默认包含 whois 仓库自身的 `release/lzispro/whois`，用于收集 7 个静态产物（已与 lzispro 解耦）。

底层等价命令（PowerShell）：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/release/one_click_release.ps1 `
  -Version <releaseVersion> -GithubName <releaseName> -GiteeName <releaseName> -SkipTagIf <skipTag> `
  -BuildAndSyncIf <buildSync> -RbHost <rbHost> -RbUser <rbUser> -RbKey '<rbKey>' `
  -RbSmoke <rbSmoke> -RbQueries '<rbQueries>' -RbSmokeArgs '<rbSmokeArgs>' -RbGolden <rbGolden> `
  -RbCflagsExtra '<rbCflagsExtra>' -RbSyncDir '<rbSyncDir>'
```

注意：
- 若 `skipTag=true`，脚本仅更新已有标签对应的 Release 正文/名称，不会创建/推送新标签。
- 若 `buildSync=false`，将跳过“远程编译/冒烟/同步并推送”阶段，直接进入打标签与更新发布正文。
- GitHub 需要 `GH_TOKEN` 或 `GITHUB_TOKEN`；Gitee 需要 `GITEE_TOKEN`。未设置的会被自动跳过并提示。
- 支持 `WHOIS_DEBUG_SSH=1` 在远程脚本中开启 `ssh -vvv` 诊断。
- 建议等到“下一个版本”发布时再实际联通两端更新，避免频繁改动当前稳定内容。

---

## 新增脚本：one_click_release.ps1 使用说明

脚本位置：`tools/release/one_click_release.ps1`

用途：一键更新 GitHub/Gitee Release 正文与显示名称；可通过参数选择是否跳过打标签（与 VS Code 任务一致）。

常用示例：
```powershell
# 正常创建标签 + 更新 Release（需要本地 git 与 Git Bash 可用）
./tools/release/one_click_release.ps1 -Version 3.2.5

# 仅更新已有标签对应的 Release，跳过打标签
./tools/release/one_click_release.ps1 -Version 3.2.5 -SkipTagIf true

# 自定义显示名称（GitHub/Gitee 共用或分别指定）
./tools/release/one_click_release.ps1 -Version 3.2.5 -GithubName "whois v3.2.5" -GiteeName "whois v3.2.5"
```

参数要点：
- `-Version X.Y.Z` 必填；正文文件固定读取 `docs/release_bodies/vX.Y.Z.md`
- `-SkipTag` 与 `-SkipTagIf 'true'` 二选一或同时指定均可，任意为真即跳过打标签
- `-PushGiteeTag` 可将标签同步到 gitee 远程（如无需要可忽略）
- GitHub 更新有重试机制（`-GithubRetry/-GithubRetrySec`），用于等待 Actions 创建 Release 占位

---

## 简易远程 Makefile 快速编译与测试（新增）

适用：需要在一台普通 Linux 主机上，直接用仓库自带 `Makefile` 做快速功能验证与冒烟，不依赖交叉编译脚本。

前置：远端可 `ssh` 登录，已安装 `gcc`，对外可访问 whois 端口 43。

步骤（Windows PowerShell 示例，按需替换路径/主机/账户）：
```powershell
# 1) 远端准备隔离目录
ssh user@host 'rm -rf ~/whois-fast && mkdir -p ~/whois-fast'

# 2) 仅同步最小必需文件（减少带宽与污染）
scp -r D:/LZProjects/whois/src D:/LZProjects/whois/Makefile user@host:~/whois-fast/

# 3) 远端编译（默认生成 whois-client）
ssh user@host 'cd ~/whois-fast && make -j$(nproc)'

# 4) 单条查询快速检视
ssh user@host 'cd ~/whois-fast && ./whois-client 8.8.8.8 | head -n 40'

# 5) 批量检视 + 过滤（利用 stdin）
ssh user@host "cd ~/whois-fast && printf '8.8.8.8\n1.1.1.1\n' | ./whois-client -B -g 'netname|country' --grep 'GOOGLE|CLOUDFLARE' --grep-line"

# 6) 可选静态链接（工具链支持时）
ssh user@host 'cd ~/whois-fast && make static'

# 7) 清理
ssh user@host 'rm -rf ~/whois-fast'
```

提示：
- `Makefile` 支持 `CFLAGS_EXTRA` 追加编译选项，例如 `make CFLAGS_EXTRA=-DWHOIS_SECLOG_TEST`。
- 批量模式输出遵循“头/尾契约”，便于人工快速审阅。
- 该方法仅用于快速验证，不会生成多架构静态产物；如需多架构或统一日志，请使用 `tools/remote/remote_build_and_test.sh`。
