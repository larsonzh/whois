## workbuf 压力计划 / workbuf scratch stress plan

目的 / Goal：在长行与高密度续行场景下观察 workbuf 的扩容行为（fold/title/grep 流程），无需代码改动。

### 测试输入（按需生成） / Test inputs (generate on the fly)
- 长标题行（约 64 KiB）/ Long header line (~64 KiB)：
  - PowerShell: `"IPv4:" + ('A'*64000)`
- 高密度续行（1 行头 + 512 行缩进，每行 256 字符）/ Dense continuations: one header + 512 indented lines of 256 chars:
  - PowerShell: `"Owner: X"; 1..512 | ForEach-Object { '  ' + ('Y'*256) }`
- 长行 + 高续行组合（折叠/grep 重点）/ Long line plus dense continuations:
  - 头行 64 KiB + 256 条缩进行（每条 512 字符）/ head 64 KiB + 256 indented 512-char lines.
- 混合 CRLF / Mixed CRLF：将 `"\n"` 替换为 ``"`r`n"``。

### 手工运行示例 / Manual run recipes
- Fold unique（将 `<BODY>` 替换为生成文本 / replace `<BODY>` with generated text）：
  - `printf "<BODY>" | ./whois_x86_64 --fold --fold-unique --host whois.iana.org example.com`
- Grep 行/块模式（示例为行模式 / line-mode example）：
  - `printf "<BODY>" | ./whois_x86_64 --grep "^Owner" --grep-line --host whois.iana.org example.com`
- Grep 块模式 + 续行保留（覆盖大块、CRLF）/ Block-mode with continuations kept:
  - `printf "<BODY>" | ./whois_x86_64 --grep "Owner" --grep "Country" --grep-block --keep-continuation-lines --fold --host whois.iana.org example.com`

### 预期现象 / Expected observations
- workbuf 会扩容到最长行，输出不截断；fold unique 复用 scratch/视图，内存随输入线性 / expands to fit longest line; no truncation; fold unique uses scratch/view allocations.
- grep 块模式在大块/CRLF 下按行追加，保持续行保留契约；不会出现重复扩容峰值 / block-mode appends per line, keeps continuation contract, avoids extra peak allocations.
- 若编译时启用 `WC_WORKBUF_ENABLE_STATS`，可在运行前后调用 `wc_workbuf_stats_snapshot()` 读取 max_request/max_cap，以观察长行场景的扩容次数；默认构建无需关注 / when built with WC_WORKBUF_ENABLE_STATS, snapshot can reveal max_request/max_cap; defaults ignore stats.

### 备注 / Notes
- 仅供手工检查，不新增 golden/selftest；任意架构二进制均可，建议在可控环境运行 / manual checklist only, no golden/selftest; run on any binary (x86_64 recommended) in a controlled environment.
