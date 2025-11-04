# whois v3.2.2 公告 / Announcement

本次版本聚焦“安全性与可观测性”，引入可选的安全日志并完成一轮系统加固；同时，按既定策略彻底移除了此前的 RDAP 试验特性，回归经典 WHOIS 纯文本工作流。

## 亮点 / Highlights

- 新增 `--security-log`（默认关闭）：将安全相关事件输出到 stderr，用于调试与审计；不改变 stdout 的既有“标题/尾行”契约。
- 内置限频防洪：约 20 条/秒，超额条目抑制并周期性输出汇总提示，避免在异常场景刷屏。
- 九大安全方向覆盖：
  1) 内存安全辅助（safe malloc/realloc/strdup 封装）
  2) 信号处理与清理（SIGINT/TERM/HUP/PIPE）
  3) 输入/查询校验（长度、字符集、可疑负载）
  4) 重定向与网络安全（目标校验、环路防护、注入/异常识别）
  5) 响应净化与校验（移除控制/ANSI 序列、结构一致性）
  6) 配置合法性检查（越界/非法值）
  7) 线程安全与缓存一致性（加锁与失效策略）
  8) 连接洪泛/速率监测
  9) 协议级异常检测与日志

## 兼容性 / Compatibility

- 移除 RDAP：删除此前所有 RDAP 相关开关与代码，避免语义分叉与维护负担；保持纯 WHOIS 文本语义与既有工作流。

## 其他改进 / Other changes

- 清理并修复部分编译警告（如 -Wsign-compare），若干计数改为 `size_t`；支持 `CFLAGS_EXTRA` 便于自定义构建。
- 文档（中/英）同步更新，补充安全日志使用与故障排查（含 ARIN:43 连通性提示）。

## 获取与使用 / Get started

- 使用说明：`docs/USAGE_CN.md` | `docs/USAGE_EN.md`
- 快速体验：
```bash
whois-x86_64 8.8.8.8
printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold
```

English summary:
- Add `--security-log` (off by default, rate-limited ~20 events/sec with suppression summaries).
- Security hardening across nine areas; keep stdout contract intact.
- Remove experimental RDAP; classic WHOIS-only.
- Docs updated; minor build cleanups.
