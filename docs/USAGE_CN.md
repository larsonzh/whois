# whois 客户端使用说明（中文）

本说明适用于项目内置的轻量级 whois 客户端（C 语言实现，静态编译，零外部依赖）。二进制覆盖多架构，例如 `whois-x86_64`、`whois-aarch64` 等，以下示例以 `whois-x86_64` 为例。

提示：自 3.2.5 起，界面输出统一为英文（English-only），避免在不支持中文的 SSH 终端出现乱码；原 `--lang` 与 `WHOIS_LANG` 已移除。

亮点：
- 智能重定向：非阻塞连接、超时、轻量重试，自动跟随转发（`-R` 上限，`-Q` 可禁用），带循环保护。
- 管道化批量输入：稳定头/尾输出契约；支持从标准输入读取（`-B`/隐式）；天然契合 BusyBox grep/awk。
- 条件输出引擎：标题投影（`-g`）→ POSIX ERE 正则筛查（`--grep*`，行/块 + 可选续行展开）→ 单行折叠（`--fold`）。

## 导航（发布与运维扩展）

若你需要“一键更新 Release（可选跳过打标签）”或“在普通远端主机用 Makefile 快速编译冒烟”能力，请查看《操作与发布手册》对应章节：

- VS Code 任务：One-Click Release（参数与令牌说明）
  - `docs/OPERATIONS_CN.md` → [One-Click Release 任务](./OPERATIONS_CN.md#vs-code-任务新增one-click-release)
- 新脚本：`one_click_release.ps1` 快速更新 GitHub/Gitee Release
  - `docs/OPERATIONS_CN.md` → 同上章节内脚本示例
- 简易远程 Makefile 快速编译与测试
  - `docs/OPERATIONS_CN.md` → [远程 Makefile 快速编译与测试](./OPERATIONS_CN.md#简易远程-makefile-快速编译与测试新增)

（如链接在某些渲染器中无法直接跳转，请打开 `OPERATIONS_CN.md` 手动滚动到对应标题。）

提示：
- 可选折叠输出 `--fold` 将筛选后的正文折叠为单行：`<query> <UPPER_VALUE_...> <RIR>`；
- `--fold-sep <SEP>` 指定折叠项分隔符（默认空格，支持 `\t`/`\n`/`\r`/`\s`）
- `--no-fold-upper` 保留原大小写（默认会转为大写）

## 一、核心特性（3.2.0）
- 批量标准输入：`-B/--batch` 或“无位置参数 + stdin 非 TTY”隐式进入
- 标题头与权威 RIR 尾行（默认开启；`-P/--plain` 纯净模式关闭）
  - 头：`=== Query: <查询项> via <起始服务器标识> @ <实际连通IP或unknown> ===`（例如 `via whois.apnic.net @ 203.119.102.24`），查询项位于标题行第 3 字段（`$3`）；标识会保留用户输入的别名或显示映射后的 RIR 主机名，`@` 段恒为首次连通的真实 IP
  - 尾：`=== Authoritative RIR: <权威RIR域名> @ <其IP或unknown> ===`，若最终服务器以 IP 字面量给出，客户端会自动映射回对应的 RIR 域名后再输出；折叠后位于最后一个字段（`$(NF)`）
- 非阻塞 connect + IO 超时 + 轻量重试（默认 2 次）；自动重定向（`-R` 上限，`-Q` 可禁用），循环防护

## 二、命令行用法

```
Usage: whois-<arch> [OPTIONS] <IP or domain>

元信息选项：
  -H, --help               显示帮助
  -v, --version            显示版本
  -l, --list               列出内置服务器别名
      --about              显示详细功能与模块说明
      --examples           显示更多示例
```

### 新增：安全日志（可选）

- `--security-log`：开启安全事件日志输出（stderr），默认关闭。用于调试/攻防校验，不改变标准输出（stdout）的既有“标题/尾行”契约。典型事件包含：输入校验拒绝、协议异常、重定向目标校验失败、响应净化与校验、连接洪泛检测等。
- 已内置限频防洪：安全日志在攻击/洪泛场景下会做限速（约 20 条/秒），超额条目会被抑制并在秒窗切换时汇总提示。
### 新增：调试 / 自检 / 折叠去重（3.2.4+）

- `-D, --debug`：开启“基础调试”与 TRACE（stderr）。默认关闭；推荐仅在排查问题时启用。
- `--debug-verbose`：开启“更详细的调试”（包含缓存/重定向等关键路径的附加日志），输出到 stderr。
- 说明：不再支持通过环境变量启用调试；请直接使用 `-D` 或 `--debug-verbose`。
- `--selftest`：运行内置自检并退出；覆盖项包含折叠基础与折叠去重行为验证（非 0 退出代表失败）。
  - 扩展（3.2.6+）：默认自测包含折叠、重定向（redirect）与查找（lookup）检查；lookup 检查包含 IANA 首跳、单跳权威与“空响应注入”路径验证。可通过 `--selftest-inject-empty` 显式触发“空响应注入”路径（需要网络）。如需额外启用 grep 与安全日志（seclog）自测，请在构建时加入编译宏并使用 CLI：
    - 编译：`-DWHOIS_GREP_TEST`、`-DWHOIS_SECLOG_TEST`
    - 运行：`--selftest-grep`、`--selftest-seclog`
  - 远程脚本示例（启用全部自测并执行）：
    ```bash
    ./tools/remote/remote_build_and_test.sh -r 1 -a "--selftest" -E "-DWHOIS_GREP_TEST -DWHOIS_SECLOG_TEST"
    # 或在 PowerShell 中：
    & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -a '--selftest' -E '-DWHOIS_GREP_TEST -DWHOIS_SECLOG_TEST'"
    ```
  - 典型输出片段：
    ```
    [SELFTEST] fold-basic: PASS
    [SELFTEST] fold-unique: PASS
    [SELFTEST] redirect-detect-0: PASS
    [SELFTEST] redirect-detect-1: PASS
    [SELFTEST] auth-indicators: PASS
    [SELFTEST] extract-refer: PASS
    [SELFTEST] lookup-iana-first: PASS
    [SELFTEST] lookup-single-hop: PASS
    [SELFTEST] lookup-empty-inject: PASS
    [SELFTEST] grep: PASS
    [SELFTEST] seclog: PASS
    ```
  - 注意：grep 与 seclog 自测默认不开启；仅在需要验证正则引擎与安全日志速率/限频逻辑时使用，生产构建可不加这些宏以缩短构建时间。
  - 版本注入策略（简化）：默认不再附加 `-dirty` 后缀；如需恢复严格模式，可在构建或调用脚本前设置环境变量 `WHOIS_STRICT_VERSION=1`（暂不建议启用，待模块拆分完成后再使用严格标记，以降低日常迭代噪声）。
- `--fold-unique`：在 `--fold` 折叠模式下去除重复 token，按“首次出现”保序输出。

### 新增：DNS/IP 家族偏好与负向缓存（3.2.6+）

- IP 家族偏好（解析与拨号顺序）：
  - `--ipv4-only` 强制仅 IPv4
  - `--ipv6-only` 强制仅 IPv6
  - `--prefer-ipv4` IPv4 优先，再 IPv6
  - `--prefer-ipv6` IPv6 优先，再 IPv4（默认）
- 负向 DNS 缓存（短 TTL）：
  - `--dns-neg-ttl <秒>` 设置负向缓存 TTL（默认 10 秒）
  - `--no-dns-neg-cache` 禁用负向缓存
- 说明：正向缓存保存“域名→IP”成功解析；负向缓存保存“解析失败”的临时记忆，用于在短时间内快速跳过重复失败的解析并降低阻塞时间。过期后自动清理，不影响后续成功解析。

示例：
```powershell
# 优先 IPv4；设定负向缓存 TTL 为 30 秒
whois-x86_64 --prefer-ipv4 --dns-neg-ttl 30 8.8.8.8

# 自测：模拟负向缓存路径（域名 selftest.invalid 会被标记为负向缓存）
whois-x86_64 --selftest-dns-negative --host selftest.invalid 8.8.8.8
```

### 新增：辅助脚本（Windows + Git Bash）

- `tools/remote/invoke_remote_plain.sh`：标准远程构建 + 冒烟 + Golden（不修改输出格式，验证契约）。
- `tools/remote/invoke_remote_demo.sh`：演示 `--fold --fold-unique -g ...` 的折叠输出（不跑 Golden）。
- `tools/remote/invoke_remote_selftest.sh`：仅运行 `--selftest`（不跑 Golden）。

> 以上脚本只是对 `tools/remote/remote_build_and_test.sh` 的参数封装，用于在 Windows 下可靠传递多词参数。

## 七、版本
版本号会在构建时自动注入（优先读取仓库根目录 `VERSION.txt`；远程构建时由脚本写入该文件），默认回退为 `3.2.6`。
- 3.2.3：输出契约细化——标题与尾行附带服务器 IP（DNS 失败显示 `unknown`），别名先映射再解析；折叠输出保持 `<query> <UPPER_VALUE_...> <RIR>` 不含服务器 IP。新增 ARIN 连通性提示（修正）：部分网络环境下，运营商可能对 ARIN 的 IPv4 whois 服务（whois.arin.net:43 的 A 记录）做端口屏蔽，导致 IPv4 无法连通；IPv6 访问正常。建议启用 IPv6 或使用公网出口。
- 3.2.4：模块化基线（wc_* 模块：title/grep/fold/output/seclog）；新增 grep 自测钩子（编译宏 + 环境变量）；改进块模式续行启发式（全局仅保留第一个 header-like 缩进行，后续同类需匹配正则）；远程构建诊断信息增强。新增 `--debug-verbose`、`--selftest`、`--fold-unique`。
- 3.2.2：九项安全性加固；新增 `--security-log` 调试日志开关（默认关闭，内置限频）。要点：内存安全包装、改进的信号处理、更严格的输入与服务器/重定向校验、连接洪泛监测、响应净化/校验、缓存加锁与一致性、协议异常检测等；同时彻底移除此前的 RDAP 实验功能与开关，保持经典 WHOIS 流程。
- 3.2.1：新增 `--fold` 单行折叠与 `--fold-sep`/`--no-fold-upper`；补充续行关键词命中技巧文档。
- 3.2.0：批量模式、标题/权威尾行、非阻塞连接与超时、重定向；默认重试节奏 interval=300ms/jitter=300ms。

- 3.2.6（版本号简化：默认不再附加 -dirty 后缀；保留 `WHOIS_STRICT_VERSION=1` 可回退严格行为）
- 3.2.0（Batch mode, headers+RIR tail, non-blocking connect, timeouts, redirects；默认重试节奏：interval=300ms, jitter=300ms）

## 八、远端构建与冒烟测试快速命令（Windows）

以下命令假设你已安装 Git Bash，并使用 Ubuntu 虚拟机作为交叉编译环境（详见 `tools/remote/README_CN.md`）。

- 在 Git Bash 中执行（默认联网冒烟测试，目标为 8.8.8.8）：

```bash
cd /d/LZProjects/whois
./tools/remote/remote_build_and_test.sh -r 1
```

- 同步产物到外部目录并仅保留 7 个架构二进制（将路径替换为你的目标目录）：

```bash
./tools/remote/remote_build_and_test.sh -r 1 -s "/d/Your/LZProjects/lzispro/release/lzispro/whois" -P 1
```

- 自定义冒烟目标（空格分隔）：

```bash
SMOKE_QUERIES="8.8.8.8 example.com 1.1.1.1" ./tools/remote/remote_build_and_test.sh -r 1
```

- 从 PowerShell 调用 Git Bash（注意路径与引号）：

```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -s /d/Your/LZProjects/lzispro/release/lzispro/whois -P 1"
```

### 产物存储与清理

下载链接风格（GitHub 直链 ↔ 仓库相对路径）的切换策略与脚本，见：`docs/RELEASE_LINK_STYLE.md`。

- 自 v3.2.0 起，`out/artifacts/` 已加入 `.gitignore`，不再纳入版本控制；CI 发布会在 GitHub Release 附带二进制资产。
- 如需清理本地历史产物，可使用 `tools/dev/prune_artifacts.ps1`（支持 `-DryRun`）。

## 九、与 lzispro 集成（交叉链接）

lzispro 的批量归类脚本 `release/lzispro/func/lzispdata.sh` 会直接调用本 whois 客户端并使用内置过滤，支持通过环境变量调整模式与关键词（有默认值，开箱即用）：

- WHOIS_TITLE_GREP：-g 标题前缀投影（例：`netname|mnt-|e-mail`）
- WHOIS_GREP_REGEXP：--grep 正则（POSIX ERE，例：`CNC|UNICOM|CHINANET|...`）
- WHOIS_GREP_MODE：`line` 或 `block`（默认 `line` 行模式）
- WHOIS_KEEP_CONT：行模式下是否展开续行到整个字段块（`1`/`0`，默认 `0`）

说明与示例请见 lzispro 项目 README“脚本环境变量（ISP 批量归类脚本）”一节：

- 本地（同工作区）：`../lzispro/README.md`
- GitHub：https://github.com/larsonzh/lzispro#%E8%84%9A%E6%9C%AC%E7%8E%AF%E5%A2%83%E5%8F%98%E9%87%8Fisp-%E6%89%B9%E9%87%8F%E5%BD%92%E7%B1%BB%E8%84%9A%E6%9C%AC

在 lzispro 中，默认采用“行模式 + 不展开续行”，便于 BusyBox awk 一行聚合；若需回退到旧的“块模式”输出，可设置 `WHOIS_GREP_MODE=block`。
折叠示例（与脚本 `func/lzispdata.sh` 风格一致）：

```sh
... | grep -Ei '^(=== Query:|netname|mnt-|e-mail|=== Authoritative RIR:)' \
  | awk -v count=0 '/^=== Query/ {if (count==0) printf "%s", $3; else printf "\n%s", $3; count++; next} \
      /^=== Authoritative RIR:/ {printf " %s", toupper($4)} \
      (!/^=== Query:/ && !/^=== Authoritative RIR:/) {printf " %s", toupper($2)} END {printf "\n"}'
# 注：折叠后 `$(NF)` 即为权威 RIR 域名（大写），即便原始尾行来自 IP 字面量也会输出映射后的域名，可用于 RIR 过滤
```

## 四、常用示例

```sh
# 单条（自动重定向）
whois-x86_64 8.8.8.8

# 指定起始 RIR 并禁止重定向
whois-x86_64 --host apnic -Q 103.89.208.0

# 批量（显式）：
cat ip_list.txt | whois-x86_64 -B --host apnic

# 纯净输出（无标题/尾行）
whois-x86_64 -P 8.8.8.8

# 标题筛选（-g），仅输出匹配标题及续行
# 注意：-g 为不区分大小写的“前缀匹配”，不支持正则表达式（例如不支持 `|`、`[]` 等正则语法）。
whois-x86_64 -g "Org|Net|Country" 8.8.8.8

# 块模式正则（默认，不区分大小写），匹配 route/origin/descr 开头的标题
whois-x86_64 --grep '^(route|origin|descr):' 1.1.1.1

# 块模式正则（区分大小写）
whois-x86_64 --grep-cs '^(Net(Name|Range)):' 8.8.8.8

# 与 -g 叠加：先按标题前缀缩小范围，再做正则
whois-x86_64 -g "Org|Net" --grep 'Google|Mountain[[:space:]]+View' 8.8.8.8

# 行模式：仅输出命中的行（保留头尾标识行）
whois-x86_64 --grep 'Google' --grep-line 8.8.8.8

# 行模式 + 续行展开：块内任一行命中则输出整个该“标题块”（标题+续行）
whois-x86_64 -g 'netname|e-mail' --grep 'cmcc' --grep-line --keep-continuation-lines 1.2.3.4

# 折叠输出（一行汇总），结合前述筛选结果：格式为
#   <query> <UPPER_VALUE_1> <UPPER_VALUE_2> ... <RIR>
# 适合 BusyBox 环境直接做聚合与判定
whois-x86_64 -g 'netname|mnt-|e-mail' --grep 'CNC|UNICOM' --grep-line --fold 1.2.3.4
```

### 续行关键词命中技巧（推荐策略与陷阱）

管线顺序固定为：先按标题前缀投影（`-g`）→ 再做正则筛选（`--grep*`，行/块）→ 最后折叠（`--fold`）。其中：

- `-g` 是“标题前缀”的不区分大小写匹配，并非正则；匹配成功会连带输出其续行（以空白开头直到下一个标题）。
- `--grep/--grep-cs` 为 POSIX ERE，支持两种模式：
  - 默认“块模式”：对“标题块”（标题+续行）整体命中与否；
  - `--grep-line` 行模式：仅匹配的行被选中（可用 `--keep-continuation-lines` 将命中行扩展成其所在“标题块”）。
- `--fold` 使用当前选区（应用 `-g/--grep*` 后的结果）折叠为单行：`<query> <UPPER_VALUE_...> <RIR>`。

推荐策略 A（稳定、易控）：

```sh
# 先用 -g 缩小到目标字段，再用块模式正则命中关键词，最后折叠
whois-x86_64 -g 'Org|Net|Country' \
  --grep 'Google|ARIN|Mountain[[:space:]]+View' \
  --fold 8.8.8.8
```

- 适合“关键词只出现在续行”的场景（例如地址、邮件在续行中），因为块模式只要块内任一行命中即可整块入选。
- 通过 `-g` 限定字段范围，避免把不相关块也带入，提升准确性。

可选策略 B（单正则合一，但存在过匹配风险）：

```sh
# 行模式使用 OR 正则，并用 --keep-continuation-lines 将命中行扩展为整个块
whois-x86_64 \
  --grep '^(Org|Net|Country)[^:]*:.*(Google|ARIN)|^[ \t]+.*(Google|ARIN)' \
  --grep-line --keep-continuation-lines --fold 8.8.8.8
```

- 优点：单个正则可同时覆盖“标题行”与“续行”关键词。
- 缺点：OR 正则容易命中通用续行从而把无关块“扩进来”，在数据较杂时需谨慎；若能先用 `-g` 缩小范围，建议优先用策略 A。

常见疑问与提示：

- 在行模式下，正则按“逐行”匹配，使用 `\n` 并不会跨行匹配；需要覆盖续行时请使用 `--keep-continuation-lines`。
- `--fold-sep` 可改分隔符（如 `,` 或 `\t`）：`--fold --fold-sep ,`、`--fold --fold-sep \t`；`--no-fold-upper` 可保留大小写。
- 折叠行首始终使用原始查询词 `<query>`（即便查询参数看起来像正则）。

## 五、退出码
- 0：成功（含批量模式下的局部失败，失败会逐条打印到 stderr）
- 非 0：参数错误 / 无输入 / 单条模式查询失败

## 六、提示
- 建议与 BusyBox 工具链配合：grep/awk/sed 排序、去重、聚合留给外层脚本处理
- 如需固定出口且避免跳转带来的不稳定，可使用 `--host <rir> -Q`
- 在自动重定向模式下，`-R` 过小可能拿不到权威信息；过大可能产生延迟，默认 5 足够
 - 重试节奏（连接级节流，3.2.6+）：默认开启；仅保留命令行参数，Release 不依赖任何运行时环境变量（调试构建向后兼容但不推荐）。
  - 默认值：interval=60 / jitter=40 / backoff=2 / max=400（对 p95 影响极小）
  - CLI：`--pacing-interval-ms N`、`--pacing-jitter-ms N`、`--pacing-backoff-factor N`、`--pacing-max-ms N`、`--pacing-disable`
  - 调试：`--retry-metrics`（输出 [RETRY-METRICS*]）、`--selftest-fail-first-attempt`（强制首轮失败）、`--selftest-inject-empty`、`--selftest-grep`、`--selftest-seclog`
  - 通用重试 CLI (`-i/-J`) 与连接级节流已彻底解耦。

  快速对比（默认开启 vs 关闭）：
  ```text
  # 默认：sleep_ms 为非 0（示例）
  [RETRY-METRICS] ... sleep_ms=87
  # 关闭：sleep_ms 恒为 0
  [RETRY-METRICS] ... sleep_ms=0
  ```

  示例（Windows PowerShell 远程冒烟 + 自定义节流）：
  ```powershell
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && \
    ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8 1.1.1.1' -a '--retry-metrics --selftest-fail-first-attempt --pacing-interval-ms 60 --pacing-jitter-ms 40 --pacing-backoff-factor 2 --pacing-max-ms 400' -P 1"
  ```

  示例（本地批量 + 临时关闭节流）：
  ```bash
  printf "8.8.8.8\n1.1.1.1\n" | ./whois-x86_64 --pacing-disable -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold
  ```

  可选自动断言（需要 `-r 1` 且 `--retry-metrics`）：`-M nonzero` / `-M zero`
  - 期望“禁用节流”为零睡眠：追加 `-M zero`
  示例：
  ```powershell
  # 默认节流应为非零
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8 1.1.1.1' -a '--retry-metrics --selftest-fail-first-attempt' -M nonzero"
  # 禁用节流应为零
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8 1.1.1.1' -a '--retry-metrics --selftest-fail-first-attempt --pacing-disable' -M zero"
  ```

### 服务器参数为 IPv4/IPv6 字面量

- `--host` 可接受别名、主机名，或“IP 字面量”（包括 IPv4 与 IPv6）。
- IPv6 请直接使用不带方括号的字面量；不要写成 `[2001:db8::1]`。如需自定义端口，请使用 `-p` 选项，不支持 `host:port` 语法。
- 大多数 shell 下无需对 IPv6 加引号；若遇到解释器歧义，可用引号包裹。
- 若以 IPv4/IPv6 字面量连接失败，客户端会自动对该地址做 PTR 反查：
  - 若反查结果映射到已知 RIR 域名，将提示并自动切换到对应 RIR 的主机继续查询；
  - 若反查结果不属于任何已知 RIR，将直接报错（退出）并提示“该地址不属于任何 RIR”。

示例：

```sh
# 指定服务器为 IPv4 字面量
whois-x86_64 --host 202.12.29.220 8.8.8.8

# 指定服务器为 IPv6 字面量（默认端口 43）
whois-x86_64 --host 2001:dc3::35 8.8.8.8

# 指定 IPv6 服务器并自定义端口（用 -p 指定，而不是 [ip]:port）
whois-x86_64 --host 2001:67c:2e8:22::c100:68b -p 43 example.com
```

### 连通性提示：ARIN（IPv4 可能被运营商屏蔽）

- 在部分仅有 IPv4 私网出口（NAT，未启用 IPv6）的环境中，无法连上 `whois.arin.net:43` 的常见原因并非 ARIN 针对私网的 ACL 拒绝，而是宽带运营商对 ARIN 的 IPv4 whois 服务（A 记录所指向的 IPv4 地址的 43 端口）进行了屏蔽。
- 现象：IPv4 到 ARIN:43 无法建立连接；官方 whois 客户端同样受影响。改用 IPv6 后可立即恢复。
- 建议：优先启用 IPv6；或确保出口为公网 IPv4 未被屏蔽。必要时可直接指定 ARIN 的 IPv6 字面量作为 `--host`，或临时选择固定起始服务器/禁用重定向以便排查。

### 故障排查：偶发“空响应”重试/回退告警（3.2.6+）

少见情况下，服务器端 TCP 连接已建立但返回体为空（或仅空白字符）。为避免出现“空正文 + 权威尾行”的误导性结果，客户端会检测这一异常并进行受控重试：

- 目标为 ARIN 时：基于 DNS 解析出的候选（优先 IPv6，再 IPv4）做最多 3 次回退重试；不增加跳数。
- 其他 RIR：基于 DNS 候选回退一次（若无可替换候选则重试同一主机）；不增加跳数。

在此过程中，会在合并输出中插入告警行以提示用户：

- `=== Warning: empty response from <host>, retrying via fallback host <host> ===`
- `=== Warning: empty response from <host>, retrying same host ===`
- 如所有回退均失败：`=== Warning: persistent empty response from <host> (giving up) ===`

说明：
- 告警属于标准输出（stdout），方便在批量管道中观察；重试不计入跳数，不影响既有“标题/尾行”契约。
- 可通过 `--selftest-inject-empty` 并运行 `--selftest` 复现该路径（需要网络）。

