# Release Body 链接风格与转换脚本使用说明 / Link Style & Conversion Scripts Guide

## 背景 / Background
发布正文中二进制下载链接有两种呈现方式：
1. 绝对直链（GitHub Release 下载 URL）——任何页面一点击即可下载，适合 Gitee 尚未同步代码或需要立即可用的场景。
2. 仓库相对路径（`release/lzispro/whois/<asset>`）——在国内网络或镜像场景下可由加速/代理统一处理，减少跨域/防火墙阻断。

为兼顾“发布即刻可用”与“后续网络友好”，提供两个脚本实现发布正文内链接的双向转换：
`absolutize_release_body_links.sh` 与 `relativize_static_binary_links.sh`。

> 核心理念：刚发布 → 先绝对化保障可下载；Gitee/镜像同步完成后 → 可再相对化以改善国内网络体验。

## 资产列表 / Assets
静态多架构（7 个）：`whois-x86_64`, `whois-x86`, `whois-aarch64`, `whois-armv7`, `whois-mipsel`, `whois-mips64el`, `whois-loongarch64`
附加资产（可选）：`whois-x86_64-gnu`（CI glibc 构建）, `SHA256SUMS.txt`（校验文件）

## 风格对比 / Style Comparison
| 场景 | 推荐风格 | 优点 | 缺点 |
|------|----------|------|------|
| 刚发布、Gitee 未同步 | 绝对直链 | 立即可点击 | URL 环境差时易超时 |
| 国内网络/镜像加速后 | 相对路径 | 可被镜像/代理重写 | 初次可能不可用（需同步） |
| 自动生成 fallback body | 绝对直链 | 无需额外脚本 | 噪音稍多（若展示完整 URL） |

在手工版本化 body（`docs/release_bodies/vX.Y.Z.md`）中采用“隐式直链”风格：只把资产名称做超链接，正文不排长串 URL，降低视觉噪音。

## 脚本一：绝对化 / Absolutize
文件：`tools/release/absolutize_release_body_links.sh`

作用：将 `release/lzispro/whois/<asset>` 相对链接替换为 `https://github.com/<owner>/<repo>/releases/download/<tag>/<asset>`。

用法示例（PowerShell 调用 Bash）：
```powershell
bash tools/release/absolutize_release_body_links.sh -t v3.2.6 docs/release_bodies/v3.2.6.md
```
扩展参数：
- `-o/--owner` 指定 owner（默认 `larsonzh`）
- `-p/--repo` 指定仓库（默认 `whois`）
- `--also-gnu` 同时处理 `whois-x86_64-gnu`
- `--also-checksums` 同时处理 `SHA256SUMS.txt`

幂等性：重复执行不影响已转换行（匹配模式一次生效）。

## 脚本二：相对化 / Relativize
文件：`tools/release/relativize_static_binary_links.sh`

作用：将 7 个静态二进制的绝对直链恢复为仓库相对路径（不处理 glibc 与校验，可按需扩展）。

用法示例：
```powershell
bash tools/release/relativize_static_binary_links.sh docs/release_bodies/v3.2.6.md
```

幂等性：已是相对路径的链接不会被重复修改。

## 操作时序建议 / Recommended Sequence
1. 新版本准备：生成或编辑 `docs/release_bodies/vX.Y.Z.md`，初稿可先写相对路径或直接留空。
2. 发布前（或刚发布）：执行绝对化脚本 → 确保 GitHub/Gitee 用户立即可点击下载。
3. 等待镜像/同步完成（可人工验证 Gitee 上源码/产物可访问）。
4. 视网络诉求执行相对化脚本 → 降低跨站下载失败概率。
5. 如需再次切回绝对直链（例如用户反馈相对路径访问慢）→ 重新绝对化即可。

## 常见问题 / FAQ
Q: relativize 为什么不处理 `whois-x86_64-gnu`？
A: 该构建有时仅用于部分调试/兼容场景，保持显式绝对链接更利于区分；可在脚本内添加一行 sed 扩展。

Q: 能否自动检测 Gitee 同步后再相对化？
A: 可以，但当前选择保持手动控制的透明性与可预测性；以后可加一个检测 API 的辅助脚本。

Q: 是否会破坏其他 Markdown 链接？
A: 两个脚本的 sed 规则仅匹配资产名单或含有 `/releases/download/.../<asset>` 结构，不会影响其他内容。

## 扩展 / Extensibility
- 增加更多架构时：只需在两个脚本的 `assets` 数组中补入新文件名。
- 想让 relativize 也处理 glibc / checksums：仿照 absolutize 添加对应 sed 替换即可。

## 快速参考 / Quick Reference
绝对化：
```powershell
bash tools/release/absolutize_release_body_links.sh -t v3.2.7 --also-gnu --also-checksums docs/release_bodies/v3.2.7.md
```
相对化：
```powershell
bash tools/release/relativize_static_binary_links.sh docs/release_bodies/v3.2.7.md
```

## English Short Form
- Two styles: Absolute (immediate availability) vs Relative (mirror/proxy friendly).
- Scripts: `absolutize_release_body_links.sh` and `relativize_static_binary_links.sh`.
- Flow: Publish → Absolutize → (After mirror sync) Relativize if desired.
- Idempotent transformations; safe to re-run.

---
如需将本说明链接添加到其它文档，可引用：`docs/RELEASE_LINK_STYLE.md`。
