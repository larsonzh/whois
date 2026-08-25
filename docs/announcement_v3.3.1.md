# whois v3.3.1 公告 / Announcement

*条件输出观测增强、批量统计、fold 性能优化、发布工具收口 / Observability, batch stats, fold performance, release tooling closure*

v3.3.1 在既有 BusyBox 管道输出契约不变的前提下，扩展条件输出与观测能力，新增批量统计，并完成 fold 热点优化与一键发布工具链收口（WP-01 关闭）。

## 亮点 / Highlights

- 条件输出与观测增强：新增 `--no-body`（仅抑制正文，保留查询首行与权威尾行）、`--print-meta`（逐查询 TAB 分隔 `k=v`：query/rir/status/duration_ms/attempts/redirects）、`--print-chain`（`chain=server1>server2>...`，无网络为 `chain=unknown`，上限 16 hop）与 `--pick`（标题字段精确抽取：netname/country/inetnum/inet6num/origin/route/descr，`first|join`）。处理顺序冻结 title → grep → pick → fold/body，观测顺序 pick → chain → meta；全部默认关闭，与 `--plain` 组合查询前 fail-fast。
	- Conditional-output and observability: adds `--no-body` (body suppression only, keeping the query header and authoritative tail), `--print-meta` (per-query TAB-separated `k=v`: query/rir/status/duration_ms/attempts/redirects), `--print-chain` (`chain=server1>server2>...`, `chain=unknown` without network, up to 16 hops), and `--pick` (exact header-field extraction: netname/country/inetnum/inet6num/origin/route/descr, `first|join`). Processing is frozen as title → grep → pick → fold/body and observations as pick → chain → meta; all options default off and fail before lookup with `--plain`.
- 批量统计 `--stats`：批量模式 stdout 尾部固定 18 字段汇总（total/success/error、lookup/rejected/internal 错误分类、固定 RIR 桶、精确 nearest-rank p50/p95），仅批量可用、1,000,000 项上限；溢出/失败/SIGINT 不输出部分汇总。真实联网复核修复了渲染清空正文后成功查询被误计为 lookup error 的问题，成功状态于渲染前冻结。
	- Batch statistics `--stats`: a fixed 18-field stdout summary after all batch records (total/success/error, lookup/rejected/internal error classes, fixed RIR buckets, exact nearest-rank p50/p95); batch-only, capped at 1,000,000 inputs, with no partial summary on overflow/failure/SIGINT. Live-network review fixed successful queries being miscounted as lookup errors after rendering cleared the body; success is now frozen before rendering.
- fold 性能与正确性：`append_token_with_format` 由逐字节 workbuf reserve 改为逐 token 严格上界预留，reserve 从 `1,417,000/1,420,000` 降至 `26,000/29,000`，高密度 stress median 提升 3.9%~55.1%；同时修复 workbuf 扩容后读取旧 token 指针的 `fold-unique` heap-use-after-free。
	- Fold performance and correctness: `append_token_with_format` now reserves workbuf capacity once per token with a strict upper bound instead of per output byte, cutting reserves from `1,417,000/1,420,000` to `26,000/29,000` and improving dense-stress medians by 3.9%–55.1%; it also fixes a `fold-unique` heap-use-after-free from stale token pointers after workbuf growth.
- 发布工具收口（WP-01 done）：一键发布顺序冻结为 build/verify → statics 同步与提交 → annotated tag → GitHub/Gitee Release；目标 tag 缺失时经进程环境强制远程构建版本，token 不再进入命令文本与日志，dry-run 断言发布顺序、强制版本、token 内联与九架构加校验集合；v3.3.1 真实 one-click 演练全程无故障。
	- Release tooling closure (WP-01 done): one-click release is frozen as build/verify → statics sync/commit → annotated tag → GitHub/Gitee Release; an absent tag forces the remote build version through the process environment, tokens never enter command text or logs, and the dry-run asserts ordering, forced version, inline-token risk, and the nine-architecture-plus-checksum set; the v3.3.1 real one-click rehearsal completed with no incidents.
- 验证（2026-08-24/08-25）：WP 阶段三架构 46/46 冻结矩阵、ASan/UBSan；最终 Strict `lto-auto` 九架构零编译/LTO 告警、golden PASS、IANA/ARIN/AFRINIC 三起点 referral、Linux/QEMU/win32/win64 smoke `18/3/3` 且 alerts=0、三目录 `9/9` SHA（`out/artifacts/20260824-205103`，311s）；发布轮产物 `out/artifacts/20260825-101612`，tag `v3.3.1` 指向最终静态产物提交 `4357c6a0`。
	- Verification (2026-08-24/25): WP-phase 46/46 frozen matrices on three architectures and ASan/UBSan; the final Strict `lto-auto` nine-architecture builds show zero compile/LTO diagnostics, golden PASS, IANA/ARIN/AFRINIC referral starts, `18/3/3` smoke with zero alerts, and `9/9` SHA-256 across three directories (`out/artifacts/20260824-205103`, 311s); the release artifacts `out/artifacts/20260825-101612` and tag `v3.3.1` point at the final statics commit `4357c6a0`.

## 兼容性 / Compatibility

- 默认行为零变化：全部新能力 opt-in，默认运行输出与 v3.3.0 一致。
- stdout 仅业务输出、stderr 仅诊断/指标不变；标题/尾行/折叠行与 BusyBox 管道契约保持不变。
- DNS/重试策略（v3.2.8–v3.2.9 冻结）与权威判定、地址空间前置分类器行为未变。

English summary:
- Adds `--no-body`, `--print-meta`, `--print-chain`, and `--pick` (all opt-in; order frozen as title → grep → pick → fold/body).
- Adds batch-only `--stats` with a fixed 18-field summary and exact nearest-rank p50/p95.
- Fold performance: one reserve per token (1,417,000/1,420,000 → 26,000/29,000) plus a `fold-unique` UAF fix.
- Release tooling closure (WP-01 done): build/verify → statics sync/commit → tag → release with version injection, token scrubbing, and dry-run guards; real one-click rehearsal for v3.3.1 passed with no incidents.

## 获取与使用 / Get started

- 使用说明：`docs/USAGE_CN.md` | `docs/USAGE_EN.md`
- 快速体验：
```bash
# 批量查询并输出统计（仅批量模式）
printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B --stats

# 抽取标题字段并追加元信息（保持首尾行契约）
whois-x86_64 8.8.8.8 --pick netname,country --print-meta

# 查看逻辑跳转链
whois-x86_64 103.89.208.0 --print-chain
```

## 下载 / Downloads

- GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.3.1
	- GitHub release page with nine static binaries and checksums
- Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.3.1）
	- Gitee release page with mirrored links

## 文档 / Docs

- 使用说明 / Usage: `docs/USAGE_CN.md` | `docs/USAGE_EN.md`
- 发布说明 / Release notes: `RELEASE_NOTES.md#331`
- 操作与发布 / Operations: `docs/OPERATIONS_CN.md` | `docs/OPERATIONS_EN.md`

---

可将以上内容直接复制为置顶 issue 的正文；如需更精简版本，可仅保留“亮点”与“下载”两节。
You can copy the above as the pinned issue content; for a shorter version, keep only Highlights and Downloads.
