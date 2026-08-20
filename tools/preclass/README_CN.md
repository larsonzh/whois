# Preclass 表生成器

从地址空间快照生成 preclass 运行时表产物。

## 输入

- `docs/registry-snapshots/iana-ipv4-address-space.csv`
- `docs/registry-snapshots/iana-ipv6-address-space.csv`
- `docs/registry-snapshots/iana-ipv4-special-registry.csv`
- `docs/registry-snapshots/iana-ipv6-special-registry.csv`
- `docs/registry-snapshots/manifest.json`
- `tools/preclass/reason_code_map.json`

## 输出

- `include/wc/wc_preclass_table.h`
- `src/core/preclass_table.c`
- `out/generated/preclass_manifest.json`

## 运行

```powershell
python tools/preclass/gen_preclass_table.py
```

在重新生成表之前，请先刷新固定的 IANA CSV 快照：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/preclass/update_iana_registry_snapshots.ps1
```

更新器会在替换任何现有文件之前校验全部四个 CSV 的 schema，并写入 `docs/registry-snapshots/manifest.json`（包含 source 与 stored 的 SHA-256 值）。运行时代码不得通过网络访问 IANA；生成的 C 表消费这些固定的快照。

## 一键更新与校验流水线（24.23.3）

编排完整的 快照刷新 → 表重新生成 → 一致性门禁 流程：

```powershell
# 实际执行：刷新快照、重新生成表、运行 schema/table guard + 门禁，变更时输出评审记录
powershell -NoProfile -ExecutionPolicy Bypass -File tools/preclass/update_and_verify_preclass_table.ps1

# 预演（不执行下载/生成/门禁，仅校验编排）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/preclass/update_and_verify_preclass_table.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/preclass/update_and_verify_preclass_table.ps1 -DryRun -SimulateNoChange
```

关键行为：

- `-DryRun -SimulateNoChange` 验证无变更分支保持生成输出哈希稳定。
- 检测到变更时，流水线运行 `preclass_table_guard.ps1` 及所选门禁（`-GateProfile all|core|minimal|none` 或 `-Gates guard,p0,p1,...`），并在 `out/artifacts/preclass_table_review/` 下写入强制的 diff/评审记录（可用 `-ReviewRecordPath` 覆盖路径）。
- 无变更时默认跳过全量门禁（`-GatesOnNoChange` 可强制运行），并保持生成器输出的确定性。

## 备注

- Schema v2 将基础地址空间行与最长前缀特殊用途覆盖层合并。
- 生成行携带 `covering_rir`、registry、purpose、globally-reachable 与 reserved-by-protocol 元数据。
- 对同一快照 manifest，生成文件是确定性的。`SOURCE_DATE_EPOCH` 可覆盖生成时间戳，以实现可复现的外部构建。
- 运行时行为仍由 `--enable-preclass-early-converge` 门控；默认仍为关闭。
