# Preclass Table Generator

Generate preclass runtime table artifacts from address-space snapshots.

## Inputs

- `docs/ipv4-address-space.txt`
- `docs/ipv6-address-space.txt`
- `tools/preclass/reason_code_map.json`

## Outputs

- `include/wc/wc_preclass_table.h`
- `src/core/preclass_table.c`
- `out/generated/preclass_manifest.json`

## Run

```powershell
python tools/preclass/gen_preclass_table.py
```

## Notes

- This is D0 scaffolding and does not switch runtime lookup behavior yet.
- Generated files are deterministic for the same inputs when `SOURCE_DATE_EPOCH` is set.
