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
