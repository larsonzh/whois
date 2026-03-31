#!/usr/bin/env python3
"""Generate preclass runtime tables from IPv4/IPv6 address-space snapshots.

This is a D0 generator skeleton:
- Reads docs/ipv4-address-space.txt and docs/ipv6-address-space.txt
- Produces include/wc/wc_preclass_table.h and src/core/preclass_table.c
- Emits out/generated/preclass_manifest.json for traceability

The generator is intentionally conservative and does not change runtime behavior
until lookup wiring switches to these tables.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


CLASS_IDS: Dict[str, int] = {
    "unknown": 0,
    "allocated": 1,
    "legacy": 2,
    "reserved": 3,
    "special": 4,
    "unallocated": 5,
}

RIR_IDS: Dict[str, int] = {
    "unknown": 0,
    "none": 1,
    "apnic": 2,
    "arin": 3,
    "ripe": 4,
    "afrinic": 5,
    "lacnic": 6,
}

CONFIDENCE_IDS: Dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
}


@dataclass(frozen=True)
class Row:
    family: int
    prefix_len: int
    addr_hi: int
    addr_lo: int
    class_name: str
    rir_name: str
    reason_code: str
    confidence: str


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_generated_at() -> str:
    sde = os.environ.get("SOURCE_DATE_EPOCH")
    if sde:
        try:
            ts = int(sde)
            return dt.datetime.utcfromtimestamp(ts).replace(microsecond=0).isoformat() + "Z"
        except ValueError:
            pass
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def guess_rir_from_designation(designation: str) -> str:
    text = designation.upper()
    if "APNIC" in text:
        return "apnic"
    if "ARIN" in text:
        return "arin"
    if "RIPE" in text:
        return "ripe"
    if "AFRINIC" in text:
        return "afrinic"
    if "LACNIC" in text:
        return "lacnic"
    return "unknown"


def parse_ipv4(path: Path) -> List[Row]:
    rows: List[Row] = []
    # Example line:
    # 001/8  APNIC  2010-01 ... ALLOCATED
    pattern = re.compile(
        r"^\s*([0-9]{3})/8\s+(.+?)\s{2,}.*\b(ALLOCATED|LEGACY|RESERVED)\b",
        re.IGNORECASE,
    )

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = pattern.match(line)
        if not m:
            continue

        first_octet = int(m.group(1))
        designation = m.group(2).strip()
        status = m.group(3).upper()

        if status == "RESERVED":
            cls = "reserved"
            rir = "none"
            reason = "V4_RESERVED_REGISTRY"
            confidence = "high"
        elif status == "ALLOCATED":
            cls = "allocated"
            rir = guess_rir_from_designation(designation)
            reason = "V4_ALLOCATED_REGISTRY"
            confidence = "medium" if rir != "unknown" else "low"
        else:  # LEGACY
            cls = "legacy"
            rir = guess_rir_from_designation(designation)
            reason = "V4_LEGACY_REGISTRY"
            confidence = "medium" if rir != "unknown" else "low"

        addr_lo = first_octet << 24
        rows.append(
            Row(
                family=4,
                prefix_len=8,
                addr_hi=0,
                addr_lo=addr_lo,
                class_name=cls,
                rir_name=rir,
                reason_code=reason,
                confidence=confidence,
            )
        )

    return rows


def map_ipv6_allocation_to_fields(allocation: str) -> Tuple[str, str, str, str]:
    name = allocation.strip().lower()

    if name == "global unicast":
        return ("allocated", "unknown", "V6_GLOBAL_UNICAST_2000_3", "medium")
    if name == "unique local unicast":
        return ("special", "none", "V6_UNIQUE_LOCAL_FC00_7", "high")
    if name == "link-scoped unicast":
        return ("special", "none", "V6_LINK_LOCAL_FE80_10", "high")
    if name == "multicast":
        return ("special", "none", "V6_MULTICAST_FF00_8", "high")
    if "reserved by ietf" in name:
        return ("reserved", "none", "V6_RESERVED_IETF", "high")

    return ("unknown", "unknown", "V6_UNKNOWN_REGISTRY", "low")


def parse_ipv6(path: Path) -> List[Row]:
    rows: List[Row] = []
    # Example line:
    # 2000::/3    Global Unicast       [RFC...]
    pattern = re.compile(r"^\s*([0-9A-Fa-f:]+/[0-9]{1,3})\s+(.+?)\s{2,}.*$")

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = pattern.match(line)
        if not m:
            continue

        prefix_text = m.group(1).strip()
        allocation = m.group(2).strip()

        try:
            network = ipaddress.ip_network(prefix_text, strict=False)
        except ValueError:
            continue
        if network.version != 6:
            continue

        cls, rir, reason, confidence = map_ipv6_allocation_to_fields(allocation)
        net_int = int(network.network_address)
        hi = (net_int >> 64) & 0xFFFFFFFFFFFFFFFF
        lo = net_int & 0xFFFFFFFFFFFFFFFF
        rows.append(
            Row(
                family=6,
                prefix_len=int(network.prefixlen),
                addr_hi=hi,
                addr_lo=lo,
                class_name=cls,
                rir_name=rir,
                reason_code=reason,
                confidence=confidence,
            )
        )

    return rows


def sort_rows(rows: List[Row]) -> List[Row]:
    # Longest-prefix-first within same family to support LPM style lookups.
    return sorted(rows, key=lambda r: (r.family, -r.prefix_len, r.addr_hi, r.addr_lo))


def render_header(schema_version: int) -> str:
    return f"""// AUTO-GENERATED by tools/preclass/gen_preclass_table.py; DO NOT EDIT.
#ifndef WC_PRECLASS_TABLE_H_
#define WC_PRECLASS_TABLE_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern \"C\" {{
#endif

typedef struct wc_preclass_table_row_s {{
    uint8_t family;
    uint8_t prefix_len;
    uint8_t class_id;
    uint8_t rir_id;
    uint8_t confidence_id;
    uint16_t reason_id;
    uint64_t addr_hi;
    uint64_t addr_lo;
}} wc_preclass_table_row_t;

typedef struct wc_preclass_table_meta_s {{
    uint32_t schema_version;
    uint32_t record_count_v4;
    uint32_t record_count_v6;
    const char* source_ipv4_sha256;
    const char* source_ipv6_sha256;
    const char* generated_at;
}} wc_preclass_table_meta_t;

#define WC_PRECLASS_TABLE_SCHEMA_VERSION ({schema_version}u)

extern const wc_preclass_table_row_t wc_preclass_table[];
extern const size_t wc_preclass_table_count;
extern const wc_preclass_table_meta_t wc_preclass_table_meta;

#ifdef __cplusplus
}}
#endif

#endif // WC_PRECLASS_TABLE_H_
"""


def row_to_c_initializer(row: Row, reason_map: Dict[str, int]) -> str:
    class_id = CLASS_IDS[row.class_name]
    rir_id = RIR_IDS[row.rir_name]
    confidence_id = CONFIDENCE_IDS[row.confidence]
    reason_id = reason_map[row.reason_code]
    return (
        "    {"
        f"{row.family}u, {row.prefix_len}u, {class_id}u, {rir_id}u, "
        f"{confidence_id}u, {reason_id}u, 0x{row.addr_hi:016X}ULL, 0x{row.addr_lo:016X}ULL"
        "}"
    )


def render_source(rows: List[Row], reason_map: Dict[str, int], ipv4_sha: str, ipv6_sha: str, generated_at: str) -> str:
    v4_count = sum(1 for r in rows if r.family == 4)
    v6_count = sum(1 for r in rows if r.family == 6)

    lines = [
        "// AUTO-GENERATED by tools/preclass/gen_preclass_table.py; DO NOT EDIT.",
        "#include \"wc/wc_preclass_table.h\"",
        "",
        "const wc_preclass_table_row_t wc_preclass_table[] = {",
    ]
    for row in rows:
        lines.append(row_to_c_initializer(row, reason_map) + ",")
    lines.extend(
        [
            "};",
            "",
            "const size_t wc_preclass_table_count = sizeof(wc_preclass_table) / sizeof(wc_preclass_table[0]);",
            "",
            "const wc_preclass_table_meta_t wc_preclass_table_meta = {",
            "    WC_PRECLASS_TABLE_SCHEMA_VERSION,",
            f"    {v4_count}u,",
            f"    {v6_count}u,",
            f"    \"{ipv4_sha}\",",
            f"    \"{ipv6_sha}\",",
            f"    \"{generated_at}\"",
            "};",
            "",
        ]
    )
    return "\n".join(lines)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate preclass table artifacts")
    parser.add_argument("--ipv4", type=Path, default=Path("docs/ipv4-address-space.txt"))
    parser.add_argument("--ipv6", type=Path, default=Path("docs/ipv6-address-space.txt"))
    parser.add_argument("--reason-map", type=Path, default=Path("tools/preclass/reason_code_map.json"))
    parser.add_argument("--out-header", type=Path, default=Path("include/wc/wc_preclass_table.h"))
    parser.add_argument("--out-source", type=Path, default=Path("src/core/preclass_table.c"))
    parser.add_argument("--out-manifest", type=Path, default=Path("out/generated/preclass_manifest.json"))
    parser.add_argument("--schema-version", type=int, default=1)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    reason_map = json.loads(args.reason_map.read_text(encoding="utf-8"))
    ipv4_sha = sha256_file(args.ipv4)
    ipv6_sha = sha256_file(args.ipv6)
    generated_at = normalize_generated_at()

    rows = sort_rows(parse_ipv4(args.ipv4) + parse_ipv6(args.ipv6))

    header_text = render_header(args.schema_version)
    source_text = render_source(rows, reason_map, ipv4_sha, ipv6_sha, generated_at)

    write_text(args.out_header, header_text)
    write_text(args.out_source, source_text)

    manifest = {
        "schema_version": args.schema_version,
        "generated_at": generated_at,
        "source_ipv4": str(args.ipv4).replace("\\", "/"),
        "source_ipv6": str(args.ipv6).replace("\\", "/"),
        "source_ipv4_sha256": ipv4_sha,
        "source_ipv6_sha256": ipv6_sha,
        "record_count_v4": sum(1 for r in rows if r.family == 4),
        "record_count_v6": sum(1 for r in rows if r.family == 6),
        "record_count_total": len(rows),
        "outputs": {
            "header": str(args.out_header).replace("\\", "/"),
            "source": str(args.out_source).replace("\\", "/"),
        },
    }
    args.out_manifest.parent.mkdir(parents=True, exist_ok=True)
    args.out_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")

    print(f"[preclass-gen] rows={len(rows)} v4={manifest['record_count_v4']} v6={manifest['record_count_v6']}")
    print(f"[preclass-gen] header={args.out_header}")
    print(f"[preclass-gen] source={args.out_source}")
    print(f"[preclass-gen] manifest={args.out_manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
