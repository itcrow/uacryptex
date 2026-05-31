#!/usr/bin/env python3
"""Extract Cryptonite atest DES/MD5 vectors into Rust modules (LE hex, like sha1_vectors.rs)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DES_C = ROOT / "cryptonite/src/cryptoniteAtest/c/atest_des.c"
MD5_C = ROOT / "cryptonite/src/cryptoniteAtest/c/atest_md5.c"
OUT = Path(__file__).resolve().parents[1] / "crates/uacryptex-core/tests/intl_kat"


def be_hex_to_le_hex(s: str) -> str:
    """Reverse byte pairs (Cryptonite `ba_alloc_from_be_hex_string` storage)."""
    s = s.strip()
    if len(s) % 2:
        s = "0" + s
    pairs = [s[i : i + 2] for i in range(0, len(s), 2)]
    return "".join(reversed(pairs)).lower()


def c_le_hex(s: str) -> str:
    """Cryptonite `ba_alloc_from_le_hex_string` — hex pairs are LSB-first."""
    s = s.strip()
    if len(s) % 2:
        s = "0" + s
    return s.lower()


def extract_des_array(text: str, name: str) -> list[tuple[str, str, str]]:
    m = re.search(rf"static DesTestHelper {name}\[\] = \{{(.*?)\}};", text, re.S)
    if not m:
        raise SystemExit(f"{name} not found")
    return re.findall(r'\{\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]*)"\s*\}', m.group(1))


def extract_md5_array(text: str) -> list[tuple[str, str]]:
    m = re.search(r"HashTestCtx md5_data\[\] = \{(.*?)\};", text, re.S)
    if not m:
        raise SystemExit("md5_data not found")
    return re.findall(r'\{\s*"([^"]*)",\s*"([^"]*)"\s*\}', m.group(1))


def write_des_vectors(path: Path, name: str, entries: list[tuple[str, str, str]]) -> None:
    lines = [
        f"//! Auto-extracted from cryptonite `atest_des.c` {name} (LE hex).",
        "pub struct DesVector { pub key: &'static str, pub data: &'static str, pub exp: &'static str }",
        f"pub const {name}: &[DesVector] = &[",
    ]
    for key, data, exp in entries:
        lines.append(
            "    DesVector { "
            f'key: "{c_le_hex(key)}", '
            f'data: "{c_le_hex(data)}", '
            f'exp: "{c_le_hex(exp)}", '
            "},"
        )
    lines.append("];")
    path.write_text("\n".join(lines) + "\n")


def write_md5_vectors(path: Path, entries: list[tuple[str, str]]) -> None:
    lines = [
        "//! Auto-extracted from cryptonite `atest_md5.c` md5_data (LE hex).",
        "pub struct HashVector { pub data: &'static str, pub hash: &'static str }",
        "pub const MD5_TEST_DATA: &[HashVector] = &[",
    ]
    for data, h in entries:
        lines.append(
            f'    HashVector {{ data: "{c_le_hex(data)}", hash: "{c_le_hex(h)}" }},'
        )
    lines.append("];")
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    des_text = DES_C.read_text()
    des_entries = extract_des_array(des_text, "DES_ECB_DATA")
    tdes_entries = extract_des_array(des_text, "TDES_ECB_DATA")
    md5_entries = extract_md5_array(MD5_C.read_text())

    OUT.mkdir(parents=True, exist_ok=True)
    write_des_vectors(OUT / "des_vectors.rs", "DES_ECB_DATA", des_entries)
    # TDES in same file
    tdes_path = OUT / "des_vectors.rs"
    tdes_lines = [
        "",
        "/// TDES-EDE3 ECB vectors from `atest_des.c` TDES_ECB_DATA.",
        "pub const TDES_ECB_DATA: &[DesVector] = &[",
    ]
    for key, data, exp in tdes_entries:
        tdes_lines.append(
            "    DesVector { "
            f'key: "{c_le_hex(key)}", '
            f'data: "{c_le_hex(data)}", '
            f'exp: "{c_le_hex(exp)}", '
            "},"
        )
    tdes_lines.append("];")
    tdes_path.write_text(tdes_path.read_text() + "\n".join(tdes_lines) + "\n")

    write_md5_vectors(OUT / "md5_vectors.rs", md5_entries)

    print(f"DES_ECB_DATA: {len(des_entries)} vectors -> {OUT / 'des_vectors.rs'}")
    print(f"TDES_ECB_DATA: {len(tdes_entries)} vectors")
    print(f"MD5_TEST_DATA: {len(md5_entries)} vectors -> {OUT / 'md5_vectors.rs'}")


if __name__ == "__main__":
    main()
