# whois v3.2.0 公告 / Release Announcement

发布日期 / Date: 2025-10-28

## TL;DR（逐条中英对照 / CN ⇄ EN）
- 新增正则过滤：`--grep/--grep-cs`；支持“行/块”选择（`--grep-line`/`--grep-block`），行模式可选“续行展开”（`--keep-continuation-lines`）。
	- Added regex filtering: `--grep/--grep-cs`; supports line/block selectors (`--grep-line`/`--grep-block`), with optional block expansion in line mode (`--keep-continuation-lines`).
- 保持 `-g/--title` 为不区分大小写“前缀匹配”（非正则）；处理顺序为“先标题投影，再正则过滤”。
	- Preserves `-g/--title` semantics as case-insensitive prefix match (NOT regex); pipeline remains "title projection first, then regex filter".
- BusyBox 友好默认不变；lzispro 默认改为“行模式 + 不展开续行”，可通过环境变量调整。
	- BusyBox-friendly defaults unchanged; lzispro now defaults to "line mode + no continuation expansion", overridable via env vars.
- 连接缓存更稳：使用 `getsockopt(SO_ERROR)` 校验存活并在异常时清理。
	- More robust cached-connection aliveness check via `getsockopt(SO_ERROR)` with cleanup on error.
- 文档与流程完善：USAGE（中/英）与 Operations 更新；Gitee Release 支持 target_commitish，提供“手动补发”工作流。
	- Docs/operations updated (CN/EN); Gitee Release supports `target_commitish` and provides a manual backfill workflow.
- 产物：CI 动态 x86_64 + 七个全静态多架构；配套远程交叉编译与 QEMU 冒烟测试脚本。
	- Artifacts: CI x86_64-gnu plus seven fully static multi-arch binaries; with remote cross-compile and QEMU smoke-test scripts.

## 下载 / Downloads
- GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.0
	- GitHub release page with binaries and checksums
- Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.0）
	- Gitee release page with mirrored links

## 文档 / Docs
- 使用说明 / Usage: `docs/USAGE_CN.md` | `docs/USAGE_EN.md`
- 发布说明 / Release notes: `RELEASE_NOTES.md#320`
- 操作与发布 / Operations: `docs/OPERATIONS_CN.md` | `docs/OPERATIONS_EN.md`

---

可将以上内容直接复制为置顶 issue 的正文；如需更精简版本，可仅保留 TL;DR 与“下载”两节。
You can copy the above as the pinned issue content; for a shorter version, keep only TL;DR and Downloads.
