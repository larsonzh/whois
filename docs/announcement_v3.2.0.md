# whois v3.2.0 公告 / Release Announcement

发布日期 / Date: 2025-10-28

## TL;DR
- 新增正则过滤：`--grep/--grep-cs`；支持“行/块”选择（`--grep-line`/`--grep-block`），行模式可选“续行展开”（`--keep-continuation-lines`）。
- 保持 `-g/--title` 为不区分大小写“前缀匹配”（非正则）；处理顺序为“先标题投影，再正则过滤”。
- BusyBox 友好默认不变；lzispro 默认改为“行模式 + 不展开续行”，可通过环境变量调整。
- 连接缓存更稳：使用 `getsockopt(SO_ERROR)` 校验存活并在异常时清理。
- 文档与流程完善：USAGE（中/英）与 Operations 更新；Gitee Release 支持 target_commitish，提供“手动补发”工作流。
- 产物：CI 动态 x86_64 + 七个全静态多架构；配套远程交叉编译与 QEMU 冒烟测试脚本。

## 下载 / Downloads
- GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.0
- Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.0）

## 文档 / Docs
- 使用说明：`docs/USAGE_CN.md` | `docs/USAGE_EN.md`
- 发布说明：`RELEASE_NOTES.md#320`
- 操作与发布：`docs/OPERATIONS_CN.md` | `docs/OPERATIONS_EN.md`

---

可将以上内容直接复制为置顶 issue 的正文；如需更精简版本，可仅保留 TL;DR 与“下载”两节。
