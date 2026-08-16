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
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


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

REGISTRY_IDS: Dict[str, int] = {
    "none": 0,
    "iana": 1,
    "rir": 2,
}

TRISTATE_IDS: Dict[str, int] = {
    "na": 0,
    "false": 1,
    "true": 2,
}


@dataclass(frozen=True)
class Row:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    class_name: str
    rir_name: str
    covering_rir_name: str
    registry_name: str
    purpose: str
    globally_reachable: str
    reserved_by_protocol: str
    reason_code: str
    confidence: str


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_generated_at(snapshot_generated_at: str) -> str:
    sde = os.environ.get("SOURCE_DATE_EPOCH")
    if sde:
        try:
            ts = int(sde)
            return dt.datetime.utcfromtimestamp(ts).replace(microsecond=0).isoformat() + "Z"
        except ValueError:
            pass
    return snapshot_generated_at


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


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def make_row(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    class_name: str,
    rir_name: str,
    reason_code: str,
    confidence: str,
    *,
    covering_rir_name: str | None = None,
    registry_name: str = "rir",
    purpose: str = "none",
    globally_reachable: str = "na",
    reserved_by_protocol: str = "na",
) -> Row:
    return Row(
        network=network,
        class_name=class_name,
        rir_name=rir_name,
        covering_rir_name=covering_rir_name or rir_name,
        registry_name=registry_name,
        purpose=purpose,
        globally_reachable=globally_reachable,
        reserved_by_protocol=reserved_by_protocol,
        reason_code=reason_code,
        confidence=confidence,
    )


def parse_ipv4(path: Path) -> List[Row]:
    rows: List[Row] = []
    for record in read_csv_rows(path):
        prefix = record.get("Prefix", "").strip()
        if not re.fullmatch(r"\d{3}/8", prefix):
            raise ValueError(f"invalid IPv4 address-space prefix: {prefix!r}")
        first_octet = int(prefix[:3])
        designation = record.get("Designation", "").strip()
        status = record.get("Status [1]", "").strip().upper()

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
        elif status == "LEGACY":
            cls = "legacy"
            rir = guess_rir_from_designation(designation)
            reason = "V4_LEGACY_REGISTRY"
            confidence = "medium" if rir != "unknown" else "low"

        elif status == "UNALLOCATED":
            cls, rir, reason, confidence = "unallocated", "none", "V4_UNKNOWN_REGISTRY", "high"
        else:
            raise ValueError(f"unsupported IPv4 address-space status: prefix={prefix} status={status!r}")

        rows.append(make_row(
            ipaddress.ip_network(f"{first_octet}.0.0.0/8"),
            cls,
            rir,
            reason,
            confidence,
            registry_name="rir" if rir not in {"none", "unknown"} else "iana",
            purpose=cls,
        ))

    return rows


def map_ipv6_allocation_to_fields(allocation: str) -> tuple[str, str, str, str]:
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
    for record in read_csv_rows(path):
        prefix_text = record.get("IPv6 Prefix", "").strip()
        allocation = record.get("Allocation", "").strip()

        try:
            network = ipaddress.ip_network(prefix_text, strict=False)
        except ValueError:
            raise ValueError(f"invalid IPv6 address-space prefix: {prefix_text!r}")
        if network.version != 6:
            raise ValueError(f"non-IPv6 prefix in IPv6 address-space registry: {prefix_text!r}")

        cls, rir, reason, confidence = map_ipv6_allocation_to_fields(allocation)
        rows.append(make_row(
            network,
            cls,
            rir,
            reason,
            confidence,
            registry_name="rir" if rir not in {"none", "unknown"} else "iana",
            purpose=re.sub(r"[^a-z0-9]+", "-", allocation.lower()).strip("-") or "unknown",
        ))

    return rows


def read_snapshot_manifest(manifest_path: Path) -> Dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if manifest.get("schema") != "IANA_REGISTRY_SNAPSHOT_MANIFEST_V1":
        raise ValueError(f"unsupported snapshot manifest schema: {manifest.get('schema')!r}")
    return manifest


def is_active_special_record(termination: str, snapshot_date: dt.date) -> bool:
    value = termination.strip()
    if not value or value.upper() == "N/A":
        return True
    terminated_month = dt.datetime.strptime(value, "%Y-%m").date().replace(day=1)
    snapshot_month = snapshot_date.replace(day=1)
    return terminated_month > snapshot_month


def normalize_purpose(name: str) -> str:
    value = name.strip().strip('"')
    if value.lower().startswith("documentation"):
        return "documentation"
    token = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not token:
        raise ValueError(f"special-purpose Name cannot be normalized: {name!r}")
    return token


def parse_tristate(value: str) -> str:
    normalized = re.sub(r"\s*\[\d+\]\s*$", "", value.strip()).lower()
    if normalized in {"true", "false"}:
        return normalized
    if normalized in {"", "n/a"}:
        return "na"
    raise ValueError(f"unsupported special-purpose tristate value: {value!r}")


def parse_address_blocks(value: str) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw_block in value.split(","):
        block = re.sub(r"\s*\[\d+\]\s*$", "", raw_block.strip())
        if not block:
            continue
        networks.append(ipaddress.ip_network(block, strict=False))
    if not networks:
        raise ValueError(f"special-purpose Address Block is empty: {value!r}")
    return networks


def find_covering_rir(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    base_rows: List[Row],
) -> str:
    candidates = [
        row for row in base_rows
        if row.network.version == network.version and network.subnet_of(row.network)
    ]
    if not candidates:
        return "unknown"
    return max(candidates, key=lambda row: row.network.prefixlen).rir_name


def parse_special_registry(
    path: Path,
    family: int,
    base_rows: List[Row],
    snapshot_date: dt.date,
) -> List[Row]:
    rows: List[Row] = []
    reason = "V4_SPECIAL_PURPOSE" if family == 4 else "V6_SPECIAL_PURPOSE"
    reserved_reason = "V4_RESERVED_SPECIAL" if family == 4 else "V6_RESERVED_SPECIAL"
    for record in read_csv_rows(path):
        if not is_active_special_record(record.get("Termination Date", ""), snapshot_date):
            continue
        name = record.get("Name", "").strip().strip('"')
        purpose = normalize_purpose(name)
        class_name = "reserved" if purpose == "reserved" else "special"
        for network in parse_address_blocks(record.get("Address Block", "")):
            if network.version != family:
                raise ValueError(f"special-purpose family mismatch: path={path} block={network}")
            rows.append(make_row(
                network,
                class_name,
                "none",
                reserved_reason if class_name == "reserved" else reason,
                "high",
                covering_rir_name=find_covering_rir(network, base_rows),
                registry_name="iana",
                purpose=purpose,
                globally_reachable=parse_tristate(record.get("Globally Reachable", "")),
                reserved_by_protocol=parse_tristate(record.get("Reserved-by-Protocol", "")),
            ))
    return rows


def sort_rows(rows: List[Row]) -> List[Row]:
    # Longest-prefix-first; special-purpose overlays win equal-prefix ties.
    return sorted(rows, key=lambda row: (
        row.network.version,
        -row.network.prefixlen,
        int(row.network.network_address),
        0 if row.reason_code in {
            "V4_SPECIAL_PURPOSE",
            "V4_RESERVED_SPECIAL",
            "V6_SPECIAL_PURPOSE",
            "V6_RESERVED_SPECIAL",
        } else 1,
    ))


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
    uint8_t covering_rir_id;
    uint8_t registry_id;
    uint8_t confidence_id;
    uint8_t globally_reachable;
    uint8_t reserved_by_protocol;
    uint16_t reason_id;
    const char* purpose;
    uint64_t addr_hi;
    uint64_t addr_lo;
}} wc_preclass_table_row_t;

typedef struct wc_preclass_table_meta_s {{
    uint32_t schema_version;
    uint32_t record_count_v4;
    uint32_t record_count_v6;
    const char* source_ipv4_sha256;
    const char* source_ipv6_sha256;
    const char* source_ipv4_special_sha256;
    const char* source_ipv6_special_sha256;
    const char* snapshot_manifest_sha256;
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
    covering_rir_id = RIR_IDS[row.covering_rir_name]
    registry_id = REGISTRY_IDS[row.registry_name]
    confidence_id = CONFIDENCE_IDS[row.confidence]
    globally_reachable = TRISTATE_IDS[row.globally_reachable]
    reserved_by_protocol = TRISTATE_IDS[row.reserved_by_protocol]
    reason_id = reason_map[row.reason_code]
    net_int = int(row.network.network_address)
    addr_hi = (net_int >> 64) & 0xFFFFFFFFFFFFFFFF if row.network.version == 6 else 0
    addr_lo = net_int & 0xFFFFFFFFFFFFFFFF
    purpose = json.dumps(row.purpose)
    return (
        "    {"
        f"{row.network.version}u, {row.network.prefixlen}u, {class_id}u, {rir_id}u, "
        f"{covering_rir_id}u, {registry_id}u, {confidence_id}u, "
        f"{globally_reachable}u, {reserved_by_protocol}u, {reason_id}u, {purpose}, "
        f"0x{addr_hi:016X}ULL, 0x{addr_lo:016X}ULL"
        "}"
    )


def render_source(
    rows: List[Row],
    reason_map: Dict[str, int],
    source_hashes: Dict[str, str],
    generated_at: str,
) -> str:
    v4_count = sum(1 for row in rows if row.network.version == 4)
    v6_count = sum(1 for row in rows if row.network.version == 6)

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
            f"    \"{source_hashes['ipv4']}\",",
            f"    \"{source_hashes['ipv6']}\",",
            f"    \"{source_hashes['ipv4_special']}\",",
            f"    \"{source_hashes['ipv6_special']}\",",
            f"    \"{source_hashes['snapshot_manifest']}\",",
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
    parser.add_argument("--ipv4", type=Path, default=Path("docs/registry-snapshots/iana-ipv4-address-space.csv"))
    parser.add_argument("--ipv6", type=Path, default=Path("docs/registry-snapshots/iana-ipv6-address-space.csv"))
    parser.add_argument("--ipv4-special", type=Path, default=Path("docs/registry-snapshots/iana-ipv4-special-registry.csv"))
    parser.add_argument("--ipv6-special", type=Path, default=Path("docs/registry-snapshots/iana-ipv6-special-registry.csv"))
    parser.add_argument("--snapshot-manifest", type=Path, default=Path("docs/registry-snapshots/manifest.json"))
    parser.add_argument("--reason-map", type=Path, default=Path("tools/preclass/reason_code_map.json"))
    parser.add_argument("--out-header", type=Path, default=Path("include/wc/wc_preclass_table.h"))
    parser.add_argument("--out-source", type=Path, default=Path("src/core/preclass_table.c"))
    parser.add_argument("--out-manifest", type=Path, default=Path("out/generated/preclass_manifest.json"))
    parser.add_argument("--schema-version", type=int, default=2)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    reason_map = json.loads(args.reason_map.read_text(encoding="utf-8-sig"))
    source_hashes = {
        "ipv4": sha256_file(args.ipv4),
        "ipv6": sha256_file(args.ipv6),
        "ipv4_special": sha256_file(args.ipv4_special),
        "ipv6_special": sha256_file(args.ipv6_special),
        "snapshot_manifest": sha256_file(args.snapshot_manifest),
    }
    snapshot_manifest = read_snapshot_manifest(args.snapshot_manifest)
    snapshot_generated_at = str(snapshot_manifest["generated_at_utc"])
    generated_at = normalize_generated_at(snapshot_generated_at)
    snapshot_date = dt.datetime.fromisoformat(snapshot_generated_at).date()

    base_rows = parse_ipv4(args.ipv4) + parse_ipv6(args.ipv6)
    special_rows = (
        parse_special_registry(args.ipv4_special, 4, base_rows, snapshot_date) +
        parse_special_registry(args.ipv6_special, 6, base_rows, snapshot_date)
    )
    rows = sort_rows(base_rows + special_rows)

    header_text = render_header(args.schema_version)
    source_text = render_source(rows, reason_map, source_hashes, generated_at)

    write_text(args.out_header, header_text)
    write_text(args.out_source, source_text)

    manifest = {
        "schema_version": args.schema_version,
        "generated_at": generated_at,
        "source_ipv4": str(args.ipv4).replace("\\", "/"),
        "source_ipv6": str(args.ipv6).replace("\\", "/"),
        "source_ipv4_special": str(args.ipv4_special).replace("\\", "/"),
        "source_ipv6_special": str(args.ipv6_special).replace("\\", "/"),
        "snapshot_manifest": str(args.snapshot_manifest).replace("\\", "/"),
        "source_ipv4_sha256": source_hashes["ipv4"],
        "source_ipv6_sha256": source_hashes["ipv6"],
        "source_ipv4_special_sha256": source_hashes["ipv4_special"],
        "source_ipv6_special_sha256": source_hashes["ipv6_special"],
        "snapshot_manifest_sha256": source_hashes["snapshot_manifest"],
        "record_count_v4": sum(1 for row in rows if row.network.version == 4),
        "record_count_v6": sum(1 for row in rows if row.network.version == 6),
        "record_count_special": len(special_rows),
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
