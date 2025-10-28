# whois 客户端使用说明（中文）

本说明适用于项目内置的轻量级 whois 客户端（C 语言实现，静态编译，零外部依赖）。二进制覆盖多架构，例如 `whois-x86_64`、`whois-aarch64` 等，以下示例以 `whois-x86_64` 为例。

亮点 / Highlights：
- 智能重定向：非阻塞连接、超时、轻量重试，自动跟随转发（`-R` 上限，`-Q` 可禁用），带循环保护。
- 管道化批量输入：稳定头/尾输出契约；支持从标准输入读取（`-B`/隐式）；天然契合 BusyBox grep/awk。
- 条件输出引擎：标题投影（`-g`）→ POSIX ERE 正则筛查（`--grep*`，行/块 + 可选续行展开）→ 单行折叠（`--fold`）。

提示 / Notes：
- 可选折叠输出 `--fold` 将筛选后的正文折叠为单行：`<query> <UPPER_VALUE_...> <RIR>`；
  - `--fold-sep <SEP>` 指定折叠项分隔符（默认空格，支持 `\t`/`\n`/`\r`/`\s`）
  - `--no-fold-upper` 保留原大小写（默认会转为大写）

## 一、核心特性（3.2.0）
- 批量标准输入：`-B/--batch` 或“无位置参数 + stdin 非 TTY”隐式进入
- 标题头与权威 RIR 尾行（默认开启；`-P/--plain` 纯净模式关闭）
  - 头：`=== Query: <查询项> ===`，查询项在标题行第 3 字段（`$3`）
  - 尾：`=== Authoritative RIR: <server> ===`，折叠后位于最后一个字段（`$(NF)`）
- 非阻塞 connect + IO 超时 + 轻量重试（默认 2 次）；自动重定向（`-R` 上限，`-Q` 可禁用），循环防护

## 二、命令行用法

```
Usage: whois-<arch> [OPTIONS] <IP or domain>
## 七、版本

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
# 注：折叠后 `$(NF)` 即为权威 RIR 域名（大写），可用于 RIR 过滤
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
- 重试节奏：默认 `interval=300ms` 且 `jitter=300ms`，即每次重试等待区间约为 `[300, 600]ms`，能有效打散拥塞与抖动；可按需通过 `-i/-J` 调整。

### 服务器参数为 IPv4/IPv6 字面量

- `--host` 可接受别名、主机名，或“IP 字面量”（包括 IPv4 与 IPv6）。
- IPv6 请直接使用不带方括号的字面量；不要写成 `[2001:db8::1]`。如需自定义端口，请使用 `-p` 选项，不支持 `host:port` 语法。
- 大多数 shell 下无需对 IPv6 加引号；若遇到解释器歧义，可用引号包裹。

示例：

```sh
# 指定服务器为 IPv4 字面量
whois-x86_64 --host 202.12.29.220 8.8.8.8

# 指定服务器为 IPv6 字面量（默认端口 43）
whois-x86_64 --host 2001:dc3::35 8.8.8.8

# 指定 IPv6 服务器并自定义端口（用 -p 指定，而不是 [ip]:port）
whois-x86_64 --host 2001:67c:2e8:22::c100:68b -p 43 example.com
```

## 七、版本

## 八、远端构建与冒烟测试快速命令（Windows）

以下命令假设你已安装 Git Bash，并使用 Ubuntu 虚拟机作为交叉编译环境（详见 `tools/remote/README_CN.md`）。

## 九、与 lzispro 集成（交叉链接）

lzispro 的批量归类脚本 `release/lzispro/func/lzispdata.sh` 会直接调用本 whois 客户端并使用内置过滤，支持通过环境变量调整模式与关键词（有默认值，开箱即用）：

- WHOIS_TITLE_GREP：-g 标题前缀投影（例：`netname|mnt-|e-mail`）。注意：-g 为不区分大小写的“前缀匹配”，不支持正则表达式。
- WHOIS_GREP_REGEXP：--grep 正则（POSIX ERE，例：`CNC|UNICOM|CHINANET|...`）
- WHOIS_GREP_MODE：`line` 或 `block`（默认 `line` 行模式）
- WHOIS_KEEP_CONT：行模式下是否展开续行到整个字段块（`1`/`0`，默认 `0`）

说明与示例请见 lzispro 项目 README“脚本环境变量（ISP 批量归类脚本）”一节：

- 本地（同工作区）：`../lzispro/README.md`
- GitHub：https://github.com/larsonzh/lzispro#%E8%84%9A%E6%9C%AC%E7%8E%AF%E5%A2%83%E5%8F%98%E9%87%8Fisp-%E6%89%B9%E9%87%8F%E5%BD%92%E7%B1%BB%E8%84%9A%E6%9C%AC

在 lzispro 中，默认采用“行模式 + 不展开续行”，便于 BusyBox awk 一行聚合；若需回退到旧的“块模式”输出，可设置 `WHOIS_GREP_MODE=block`。

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
& 'C:\Program Files\Git\bin\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -s /d/Your/LZProjects/lzispro/release/lzispro/whois -P 1"
```
