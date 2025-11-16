# 一键发布流程（whois）

本文档描述如何在本地一键完成完整发布：

- 远程交叉编译 7 个架构静态二进制 + 联网冒烟
- 同步静态产物到 lzispro，并自动提交/推送
- （可选）提交更新后的 `RELEASE_NOTES.md`
- 打标签触发 GitHub Release（自动附上 CI 的 `whois-x86_64-gnu` + 7 个静态二进制）

> CI 与远程 SSH 说明：
> - 与远程 SSH（跨机交叉编译/抓取产物）相关的 GitHub Actions 工作流现已改为“手动触发（workflow_dispatch）”，以避免托管 Runner 无法直连私网主机导致失败。
> - 建议：在本机通过 `tools/remote/remote_build_and_test.sh` 完成远端构建与冒烟；需要 CI 化时，优先考虑自托管 Runner。
> - 排错：设置 `WHOIS_DEBUG_SSH=1` 可开启 `ssh -vvv` 详细调试日志。

## 快速使用（PowerShell）

在 whois 仓库根目录执行：

```powershell
# 自动递增标签（基于当前最大 vX.Y.Z 的补丁号），默认联网冒烟，默认查询 8.8.8.8
# 自动探测同级目录的 lzispro，或用 --lzispro-path 指定
./tools/release/full_release.ps1

# 指定标签与查询目标
./tools/release/full_release.ps1 -Tag v3.1.9 -Queries '8.8.8.8 1.1.1.1'

# 关闭冒烟测试
./tools/release/full_release.ps1 -NoSmoke

# 指定 lzispro 路径（例如 D:\LZProjects\lzispro）
./tools/release/full_release.ps1 -LzisproPath 'D:\LZProjects\lzispro'
```

等效的 Git Bash（可用于 CI 宿主或 WSL）：

```bash
./tools/release/full_release.sh --tag v3.1.9 --queries '8.8.8.8 1.1.1.1'
```

## 版本号规则
- 未显式指定 `--tag/ -Tag` 时，脚本会读取 whois 仓库现有标签中最大的 `vX.Y.Z`，将 Z 自增 1 作为下一版。
- 若该标签已存在，脚本会报错退出，避免重复发布。
- 版本标记策略（自 3.2.6 起）：默认构建不再附加 `-dirty` 后缀以减少不必要的标签/提交操作；若需要严格检测并在存在已跟踪改动时附加 `-dirty`（用于审计或正式发布复核），可在调用远程构建脚本前设置环境变量 `WHOIS_STRICT_VERSION=1`。例如：
   ```powershell
   $env:WHOIS_STRICT_VERSION = 1
   & 'C:\Program Files\Git\bin\bash.exe' -lc "tools/remote/remote_build_and_test.sh -r 1"
   ```
   或在 VS Code 中使用新增的严格模式 Task（Remote: Build (Strict Version)）。

## 目录与同步说明
- 7 个静态二进制默认同步到：`<lzispro>/release/lzispro/whois/`。
- GitHub Actions 的发布工作流会在打标签后自动从 lzispro 的 master 分支读取该目录（或 `<lzispro>/release/lzispro/whois/whois`，两者兼容）收集附件并生成合并校验 `SHA256SUMS.txt`。

## 执行细节（full_release.sh）
1. 调用 `tools/remote/remote_build_and_test.sh`：
   - 参数：`-r 1`（可关闭）、`-q '<queries>'`、`-s '<lzispro>/release/lzispro/whois' -P 1`（先清理目标内非 whois-* 文件）
   - 默认将 Step1 的输出存入 `out/release_flow/<timestamp>/step1_remote.log`；若检测到任意警告/错误（包含 `warning:`、`[WARN]`、`[ERROR]`），脚本会立即终止。可用 `--strict-warn 0` 关闭此行为。
2. 在 lzispro 仓库执行 `git add release/lzispro/whois/whois-* && commit && push`（若无变更则跳过）
3. 在 whois 仓库执行 `git add RELEASE_NOTES.md && commit && push`（若无变更则跳过）
4. 在 whois 仓库创建并推送标签 `vX.Y.Z` 触发 Release

## 常见问题
- 标签不存在/已存在：未提供标签时自动递增，若目标标签已存在脚本会终止避免重复。
- 未找到 lzispro：脚本默认探测 whois 同级目录下的 `lzispro`。也可用 `--lzispro-path` 明确指定。
- 附件缺失：确认步骤 2 已提交并推送到 GitHub，且工作流日志里能看到已从 lzispro 正确复制 7 个静态二进制。

---

## 稳定发布最佳实践

- 关键原则：一次完成。所有代码与文档先提交推送后，再用 VS Code 任务 One-Click Release 完成“打标签 + 远程编译 + 冒烟 + 同步 + 提交推送 + 触发工作流 + 更新 GitHub/Gitee 发布正文”。不要拆成多步手工执行。
- 预检清单：
   - 工作区干净：没有未提交变更（含 `release/lzispro/whois/`、`docs/release_bodies/vX.Y.Z.md`）。
   - 文档一致：`README.md`、`RELEASE_NOTES.md`、`docs/release_bodies/vX.Y.Z.md` 已对齐；双语顺序统一为“中文在上，英文在下（或同行中文在前、英文在后）”。
   - 下载直链：发布正文内资产为 GitHub 绝对直链，并补充 `SHA256SUMS.txt`。
   - 版本确认：计划发布版本未被占用；若需复用必须先删除线上旧 Release 与旧标签。
   - 凭据就绪：GitHub `GITHUB_TOKEN/GH_TOKEN`，Gitee `GITEE_TOKEN`（如需同步）。
- One-Click Release 建议：
   - `skipTag=false`、`buildSync=true`；远程 `rbHost/rbUser/rbKey` 正确；`rbSmoke=1`、`rbQueries` 给出 1～2 个目标；`rbSmokeArgs` 留空或仅填必要参数；`rbSyncDir` 支持多目录用分号分隔。
   - 严格版本：使用任务内“严格构建”或设置 `WHOIS_STRICT_VERSION=1`，确保产物版本为干净的 `vX.Y.Z`。
- 常见误区：
   - 先手动推标签或先手动远程构建再调用任务，容易导致“标签与正文/资产不同步”。
   - 在任务表单里随手填了 `rbSmokeArgs` 等占位值（即便正确）也可能改变冒烟行为，建议为空即留空。
   - 频繁删除/重推同名标签可能让 Release 进入草稿或无资产状态。
- 发布后验证：
   - Actions 运行：release 工作流成功，7 个二进制 + `SHA256SUMS.txt` 已出现在 Release 附件中。
   - 产物版本：本地同步目录的二进制 `-v` 输出应为干净 `vX.Y.Z`。
   - 正文：GitHub/Gitee 发布正文名称与内容匹配当前版本。
- 修复策略：
   - 仅正文有误：One-Click Release（`skipTag=true`、`buildSync=false`）只刷新正文。
   - 资产缺失：删除本地+远端 Tag → 确认产物已提交推送 → 再完整执行 One-Click（不跳过 Tag）。
   - 版本带 `-dirty`：说明构建时工作区不干净，清理后重新完整执行。


English short note: See script headers; the PowerShell wrapper simply forwards arguments to the bash script. The release job will attach both CI-built glibc x86_64 binary and seven statically linked multi-arch binaries from the lzispro repository.
