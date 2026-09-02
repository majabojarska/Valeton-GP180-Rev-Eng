#!/usr/bin/env python3
"""Verify cached native NAMB CRCs and the controlled NAMB-to-BMAN projection.

This is a read-only corpus verifier.  The projection is intentionally limited
to the 17 controlled HELLBERT WaveNet transfers; it is not a general BMAN
serializer and must not be used to construct device writes.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from gp180_file_formats import decode_capture
from gp180_namb import CRC_OFFSET, NAMB_SIZE, namb_crc32

BMAN_SIZE = 8123
TRANSFER_PREFIX_SIZE = 35
CONTROLLED_DELETIONS = (
    0x53,
    0xCB,
    0x141,
    0x1EF,
    *range(0x22F, 0x1F02, 119),
)
CONTROLLED_TRAILER_SIZE = 210


def project_controlled_namb_to_bman(namb: bytes) -> bytes:
    """Apply the exact edit relation observed in all 17 controlled pairs."""
    if len(namb) != NAMB_SIZE or namb[:4] != b"BMAN":
        raise ValueError("expected a 7980-byte native NAMB record")
    deleted = set(CONTROLLED_DELETIONS)
    return bytes(value for index, value in enumerate(namb) if index not in deleted) + (
        b"\0" * CONTROLLED_TRAILER_SIZE
    )


def verify_namb_crc(path: Path) -> int:
    data = path.read_bytes()
    if len(data) != NAMB_SIZE or data[:4] != b"BMAN":
        raise ValueError(f"{path}: not a {NAMB_SIZE}-byte BMAN/NAMB record")
    stored = int.from_bytes(data[CRC_OFFSET : CRC_OFFSET + 4], "little")
    calculated = namb_crc32(data)
    if stored != calculated:
        raise ValueError(f"{path}: CRC32 {stored:08x} != {calculated:08x}")
    return stored


def _controlled_namb(namb_dir: Path, capture: str) -> Path:
    match = re.search(r"HELLBERT-(\d{2})-(.+)\.pcapng$", capture)
    if not match:
        raise ValueError(f"not a controlled HELLBERT capture: {capture}")
    suffix = re.sub(r"[^a-z0-9]", "", match.group(2).lower())
    prefix = f"HELLBERT{match.group(1)}{suffix}"
    matches = sorted(namb_dir.glob(prefix + "*.namb"))
    if not matches:
        raise ValueError(f"no cached NAMB matches {capture}: {prefix}")
    return matches[0]


def verify_controlled_pairs(corpus: Path, namb_dir: Path) -> list[dict[str, object]]:
    namb_paths = sorted(namb_dir.glob("*.namb"))
    for namb_path in namb_paths:
        verify_namb_crc(namb_path)

    with corpus.open() as stream:
        captures = sorted(
            {
                row["capture"]
                for row in map(json.loads, stream)
                if "bman-diff-variants" in row.get("capture", "")
            }
        )
    if len(captures) != 17:
        raise ValueError(f"expected 17 controlled captures, found {len(captures)}")

    results = []
    for capture in captures:
        namb_path = _controlled_namb(namb_dir, capture)
        namb = namb_path.read_bytes()
        crc = verify_namb_crc(namb_path)
        decoded = decode_capture(corpus, capture)
        if len(decoded) != TRANSFER_PREFIX_SIZE + BMAN_SIZE:
            raise ValueError(f"{capture}: unexpected decoded transfer length")
        bman = decoded[TRANSFER_PREFIX_SIZE:]
        if bman != project_controlled_namb_to_bman(namb):
            raise ValueError(f"{capture}: NAMB-to-BMAN projection mismatch")
        if bman[0x18 : 0x1C] != namb[0x18 : 0x1C]:
            raise ValueError(f"{capture}: BMAN CRC field was not inherited")
        results.append({"capture": capture, "namb": str(namb_path), "crc32": f"{crc:08x}"})
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("namb_dir", type=Path)
    args = parser.parse_args()
    results = verify_controlled_pairs(args.corpus, args.namb_dir)
    print(
        json.dumps(
            {
                "verified_namb_count": len(list(args.namb_dir.glob("*.namb"))),
                "verified_controlled_pairs": len(results),
                "deletion_count": len(CONTROLLED_DELETIONS),
                "zero_trailer_size": CONTROLLED_TRAILER_SIZE,
                "results": results,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
