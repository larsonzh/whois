# Preclass Table Generator

Generate preclass runtime table artifacts from address-space snapshots.

## Inputs

- `docs/registry-snapshots/iana-ipv4-address-space.csv`
- `docs/registry-snapshots/iana-ipv6-address-space.csv`
- `docs/registry-snapshots/iana-ipv4-special-registry.csv`
- `docs/registry-snapshots/iana-ipv6-special-registry.csv`
- `docs/registry-snapshots/manifest.json`
- `tools/preclass/reason_code_map.json`

## Outputs

- `include/wc/wc_preclass_table.h`
- `src/core/preclass_table.c`
- `out/generated/preclass_manifest.json`

## Run

```powershell
python tools/preclass/gen_preclass_table.py
```

Refresh the pinned IANA CSV snapshots before regenerating tables:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/preclass/update_iana_registry_snapshots.ps1
```

The updater validates all four CSV schemas before replacing any existing files and writes
`docs/registry-snapshots/manifest.json` with source and stored SHA-256 values. Runtime code
must not access IANA over the network; generated C tables consume these pinned snapshots.

## Notes

- Schema v2 merges base address-space rows with longest-prefix special-purpose overlays.
- Generated rows carry `covering_rir`, registry, purpose, globally-reachable, and reserved-by-protocol metadata.
- Generated files are deterministic for the same snapshot manifest. `SOURCE_DATE_EPOCH` may override the generated timestamp for reproducible external builds.
- Runtime behavior remains gated by `--enable-preclass-early-converge`; the default is still off.
