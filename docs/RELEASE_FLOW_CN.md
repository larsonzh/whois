# 一键发布流程（whois）

本文档描述如何在本地一键完成完整发布：

- 远程交叉编译 7 个架构静态二进制 + 联网冒烟
- 同步静态产物到 lzispro，并自动提交/推送
- （可选）提交更新后的 `RELEASE_NOTES.md`
- 打标签触发 GitHub Release（自动附上 CI 的 `whois-x86_64-gnu` + 7 个静态二进制）

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

## 目录与同步说明
- 7 个静态二进制默认同步到：`<lzispro>/release/lzispro/whois/`。
- GitHub Actions 的发布工作流会在打标签后自动从 lzispro 的 master 分支读取该目录（或 `<lzispro>/release/lzispro/whois/whois`，两者兼容）收集附件并生成合并校验 `SHA256SUMS.txt`。

## 执行细节（full_release.sh）
1. 调用 `tools/remote/remote_build_and_test.sh`：
   - 参数：`-r 1`（可关闭）、`-q '<queries>'`、`-s '<lzispro>/release/lzispro/whois' -P 1`（先清理目标内非 whois-* 文件）
2. 在 lzispro 仓库执行 `git add release/lzispro/whois/whois-* && commit && push`（若无变更则跳过）
3. 在 whois 仓库执行 `git add RELEASE_NOTES.md && commit && push`（若无变更则跳过）
4. 在 whois 仓库创建并推送标签 `vX.Y.Z` 触发 Release

## 常见问题
- 标签不存在/已存在：未提供标签时自动递增，若目标标签已存在脚本会终止避免重复。
- 未找到 lzispro：脚本默认探测 whois 同级目录下的 `lzispro`。也可用 `--lzispro-path` 明确指定。
- 附件缺失：确认步骤 2 已提交并推送到 GitHub，且工作流日志里能看到已从 lzispro 正确复制 7 个静态二进制。

---

English short note: See script headers; the PowerShell wrapper simply forwards arguments to the bash script. The release job will attach both CI-built glibc x86_64 binary and seven statically linked multi-arch binaries from the lzispro repository.
