#!/usr/bin/env python3
"""Generate a read-only manifest for the locally available C.49/C.50 trees."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


C49_DEFAULT = Path("/home/ameya/Realme1/C49_extracted")
C50_DEFAULT = Path(
    "/home/ameya/Realme1/C50_research/"
    "CPH1861EX_11_OTA_0500_all_fLuS0Ipoe93t"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_type(path: Path) -> str:
    try:
        result = subprocess.run(
            ["file", "-b", str(path)], capture_output=True, text=True, check=False
        )
        description = result.stdout.strip()
    except OSError as exc:
        description = f"file(1) unavailable: {exc}"
    lower = description.lower()
    if "android bootimg" in lower:
        return "android_boot_image"
    if "android sparse" in lower or "sparse image" in lower:
        return "android_sparse_image"
    if "zip archive" in lower:
        return "zip_archive"
    if "shell script" in lower:
        return "shell_script"
    if path.name in {"scatter.txt", "MT6771_Android_scatter.txt"}:
        return "partition_scatter"
    if path.name.endswith(".transfer.list"):
        return "block_update_transfer_list"
    if path.name.endswith(".dat.br"):
        return "brotli_block_update_payload"
    if path.name.endswith(".sig"):
        return "partition_signature_blob"
    if path.name.endswith(".apk"):
        return "android_package"
    if "xml" in lower:
        return "xml"
    if path.name.endswith((".img", ".bin", ".auth")):
        return "firmware_binary"
    return "text_or_metadata" if "text" in lower or "ascii" in lower else "data"


def file_entry(root: Path, path: Path, package: str) -> dict[str, Any]:
    stat = path.stat()
    return {
        "package": package,
        "relative_path": str(path.relative_to(root)),
        "absolute_path": str(path),
        "size_bytes": stat.st_size,
        "sha256": sha256(path),
        "identified_type": file_type(path),
    }


def c49_partitions(scatter: Path) -> list[dict[str, Any]]:
    text = scatter.read_text(errors="replace")
    blocks = re.split(r"\n(?=- partition_index:)", text)
    entries: list[dict[str, Any]] = []
    for block in blocks:
        name = re.search(r"partition_name:\s*(\S+)", block)
        if not name:
            continue
        def value(pattern: str) -> str | None:
            match = re.search(pattern, block)
            return match.group(1) if match else None
        entries.append({
            "partition_name": name.group(1),
            "file_name": value(r"file_name:\s*(\S+)"),
            "linear_start_addr": value(r"linear_start_addr:\s*(\S+)"),
            "partition_size": value(r"partition_size:\s*(\S+)"),
            "region": value(r"region:\s*(\S+)"),
        })
    return entries


def c50_partitions(scatter: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in scatter.read_text(errors="replace").splitlines():
        match = re.match(r"(\S+)\s+(0x[0-9a-fA-F]+)$", line.strip())
        if match:
            entries.append({"partition_name": match.group(1), "offset": match.group(2)})
    return entries


def build_manifest(c49: Path, c50: Path) -> dict[str, Any]:
    c49_files = sorted(p for p in c49.rglob("*") if p.is_file())
    c50_files = sorted(p for p in c50.rglob("*") if p.is_file())
    return {
        "manifest_version": 1,
        "generated_by": "scripts/generate_firmware_inventory.py",
        "scope": {
            "c49": {
                "label": "C.49 extracted reference; project provenance identifies CPH1859",
                "root": str(c49),
                "partition_metadata": c49_partitions(c49 / "MT6771_Android_scatter.txt"),
            },
            "c50": {
                "label": "C.50 OTA reference explicitly named CPH1861; not exact-device CPH1859 proof",
                "root": str(c50),
                "partition_metadata": c50_partitions(c50 / "scatter.txt"),
            },
        },
        "firmware_fingerprints": {
            "c49": {
                "android": "9 / API 28",
                "security_patch_from_system_build_prop": "2020-05-05",
                "kernel": "4.4.146+",
                "board": "oppo6771_17065 / MT6771",
            },
            "c50_reference": {
                "kernel_from_boot_image": "4.4.146+",
                "build_timestamp_from_kernel": "2020-10-16 23:57:58 CST",
                "board_from_bootloader_strings": "oppo6771_17065",
                "model_scope": "CPH1861-targeted OTA reference",
            },
        },
        "files": [
            *[file_entry(c49, path, "c49") for path in c49_files],
            *[file_entry(c50, path, "c50_reference") for path in c50_files],
        ],
        "availability_summary": {
            "c49_file_count": len(c49_files),
            "c50_reference_file_count": len(c50_files),
            "available_components": [
                "preloader", "lk", "boot", "recovery", "system", "vendor", "odm",
                "odmdtbo", "tee", "scp", "spmfw", "sspm", "md1img", "camera VPU",
                "configuration and partition metadata", "C.50 OTA system/vendor block payloads",
            ],
            "missing_or_not_exact": [
                "model-authenticated CPH1859 C.50 package",
                "exact installed CPH1859 C.50 lk/preloader/recovery/boot/system/vendor images",
                "vbmeta image and complete C.50 extracted filesystem trees",
                "kernel .config and source tree",
                "physical BootROM/preloader runtime trace",
            ],
        },
    }


def markdown(manifest: dict[str, Any]) -> str:
    lines = [
        "# Firmware Inventory",
        "",
        "Generated from the local extracted trees with SHA-256 hashing. The C.50 tree is an OTA reference named for CPH1861; it is not treated as the installed CPH1859 C.50 image.",
        "",
        "## Scope and fingerprints",
        "",
        "| Set | Provenance | Android / patch | Kernel | Files |",
        "|---|---|---|---|---:|",
        f"| C.49 | CPH1859 project reference | Android 9 / 2020-05-05 | 4.4.146+ | {manifest['availability_summary']['c49_file_count']} |",
        f"| C.50 reference | CPH1861-targeted OTA | OTA reference; exact CPH1859 patch not established | 4.4.146+ | {manifest['availability_summary']['c50_reference_file_count']} |",
        "",
        "Available image classes include preloader, LK, boot, recovery, system/vendor/ODM, modem and auxiliary firmware, trust images, partition metadata, and C.50 compressed block-update payloads. The exact-device CPH1859 C.50 partitions, vbmeta, complete extracted C.50 filesystems, kernel config, and source are absent.",
        "",
        "## Partition mapping",
        "",
        "C.49 mapping is parsed from `MT6771_Android_scatter.txt`; C.50 mapping is parsed from the OTA `scatter.txt` and provides offsets only.",
        "",
        "## File manifest",
        "",
        "| Set | Relative path | Size (bytes) | SHA-256 | Identified type |",
        "|---|---|---:|---|---|",
    ]
    for entry in manifest["files"]:
        lines.append(
            f"| {entry['package']} | `{entry['relative_path']}` | {entry['size_bytes']} | `{entry['sha256']}` | {entry['identified_type']} |"
        )
    lines += [
        "",
        "## Reproduction",
        "",
        "```text",
        "PYTHONPATH=src:scripts python3 scripts/generate_firmware_inventory.py",
        "```",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--c49-root", type=Path, default=C49_DEFAULT)
    parser.add_argument("--c50-root", type=Path, default=C50_DEFAULT)
    parser.add_argument("--json-out", type=Path, default=Path("artifacts/firmware_inventory.json"))
    parser.add_argument("--markdown-out", type=Path, default=Path("artifacts/firmware_inventory.md"))
    args = parser.parse_args()
    manifest = build_manifest(args.c49_root, args.c50_root)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(manifest, indent=2) + "\n")
    args.markdown_out.write_text(markdown(manifest))
    print(f"Wrote {len(manifest['files'])} file entries")


if __name__ == "__main__":
    main()
