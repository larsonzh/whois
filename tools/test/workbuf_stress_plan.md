## workbuf 压力计划 / workbuf scratch stress plan

目的 / Goal：在长行与高密度续行场景下观察 workbuf 的扩容行为（fold/title/grep 流程），无需代码改动。

### 测试输入（按需生成） / Test inputs (generate on the fly)
- 长标题行（约 64 KiB）/ Long header line (~64 KiB)：
  - PowerShell: `"IPv4:" + ('A'*64000)`
- 高密度续行（1 行头 + 512 行缩进，每行 256 字符）/ Dense continuations: one header + 512 indented lines of 256 chars:
  - PowerShell: `"Owner: X"; 1..512 | ForEach-Object { '  ' + ('Y'*256) }`
- 混合 CRLF / Mixed CRLF：将 `"\n"` 替换为 ``"`r`n"``。

### 手工运行示例 / Manual run recipes
- Fold unique（将 `<BODY>` 替换为生成文本 / replace `<BODY>` with generated text）：
  - `printf "<BODY>" | ./whois_x86_64 --fold --fold-unique --host whois.iana.org example.com`
- Grep 行/块模式（示例为行模式 / line-mode example）：
  - `printf "<BODY>" | ./whois_x86_64 --grep "^Owner" --grep-line --host whois.iana.org example.com`

### 预期现象 / Expected observations
- workbuf 会扩容到最长行，输出不截断；fold unique 复用 scratch，内存随输入线性 / expands to fit longest line; no truncation; fold unique reuses scratch with linear allocations.
- 开启 `--debug` 时，stderr reserve 次数应很少（初始 256 → 一次放大到最长行附近）/ with `--debug`, only a few reserve steps (256 → near longest line).

### 备注 / Notes
- 仅供手工检查，不新增 golden/selftest；任意架构二进制均可，建议在可控环境运行 / manual checklist only, no golden/selftest; run on any binary (x86_64 recommended) in a controlled environment.
