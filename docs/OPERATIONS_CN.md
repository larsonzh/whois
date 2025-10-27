# whois 操作与发布手册（最小可用版）

本手册汇总日常“提交/发布/远端构建/镜像到 Gitee”相关的常用操作与注意事项，便于随时查阅。

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
- `-H/-u/-p/-k`：SSH 主机/用户/端口/私钥
- `-t`：目标架构（默认：`aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64`）
- `-r 0|1`：是否跑冒烟测试
- `-q "8.8.8.8 example.com"`：冒烟测试查询目标（空格分隔）
- `-a` 追加冒烟参数（示例：`-a '-g Org|Net|Country'`）。注意：在 VS Code 任务的输入框里，rbSmokeArgs 不要再加内层引号，直接填 `-g Domain|Registrar|Name Server|DNSSEC`，脚本会自动做安全引用；否则会出现 `Registrar: command not found` 之类的解析错误。此外，`-g` 为不区分大小写的“前缀匹配”，不是正则表达式；若需正则过滤，请使用 `--grep/--grep-cs`。
- `-s <dir>`：把 whois-* 同步到本机某目录（配合 `-P 1` 可在同步前清理非 whois-*）
- `-o/-f`：远端输出目录、本地拉取目录基准（默认 `out/artifacts/<ts>/build_out`）
- 扩展（可选）：`-U 1 -T vX.Y.Z` 表示构建后将拉取到本地的静态二进制直传至 GitHub 的 `vX.Y.Z` Release（需要 `GH_TOKEN`）

---

## Git 提交与推送（SSH）

在仓库根目录 `D:\LZProjects\whois`：

```powershell
# 确认远程地址为 SSH（示例：git@github.com:larsonzh/whois.git）
git remote -v

# 提交
git add -A
git commit -m "your change"

# 同步与推送（推荐先 rebase）
git pull --rebase origin master
git push origin master

# 打标签触发发布
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

可选：推送到 Gitee 以镜像代码/标签
```powershell
# 首次添加（按你的仓库改）
git remote add gitee git@gitee.com:larsonzh/whois.git
# 后续推送
git push gitee master
git push gitee --tags
```

说明：Git 的 SSH 与远端构建机的 SSH（用于交叉编译）是两回事，互不影响。

---

## CI 简述（GitHub Actions）

工作流文件：`.github/workflows/build.yml`

触发：
- push 到 main/master
- PR
- 打标签 `vX.Y.Z`

主要 Job：
- `build-linux`：构建 `whois-x86_64-gnu` 并保存为构建产物
- `release`（仅标签）：
  - 重新构建并收集 lzispro 的 7 个静态二进制
  - 生成合并的 `SHA256SUMS.txt`
  - 创建 GitHub Release，上传所有资产
  - 可选：若设置了 Secrets（见下），在 Gitee 创建同名 Release，正文附 GitHub 下载直链

Gitee 可选镜像（只创建 Release + 直链）：
- 在仓库 Settings → Secrets 新建：
  - `GITEE_OWNER`（如：`larsonzh`）
  - `GITEE_REPO`（如：`whois`）
  - `GITEE_TOKEN`（你的 Gitee PAT，具备发布权限）
- 验证：发布 Job 日志显示 `Gitee create release HTTP 200/201` 即成功；未配置将自动跳过

---

## 故障排查速查

- 第一步失败或有告警：查看 `whois/out/release_flow/<ts>/step1_remote.log`（默认严格模式，Warning 也会中止）
- `-NoSmoke` 与 `-Queries` 同时使用：Queries 会被忽略（脚本会打印提示）
- Windows 路径：PowerShell 包装器会自动把 `D:\...` 转为 `/d/...`
- 多查询参数：PowerShell 已修复自动引用，`-Queries "8.8.8.8 1.1.1.1"` 可直接使用
- Gitee 步骤失败：不阻断 GitHub 主发布；日志会打印返回码与响应体
- 自 v3.2.0 起，`out/artifacts/` 不再纳入版本控制；如需清理本地历史产物，使用 `tools/dev/prune_artifacts.ps1`（支持 `-DryRun`）。
- `out/`、`release_assets/`：已在 `.gitignore` 忽略，避免误提交

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

---

## 后续规划 / RFC

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
