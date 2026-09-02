#!/usr/bin/env python3
"""Build a same-shape GP-180 native NAMB candidate from a NAM model."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from gp180_bman import load_weights

NAMB_SIZE = 7980
WEIGHT_OFFSET = 0x1F0
WEIGHT_COUNT = 1871
CRC_OFFSET = 0x18


def namb_crc32(data: bytes) -> int:
    """Return the native NAMB CRC32, excluding the header CRC field."""
    crc = 0xFFFFFFFF
    for index, value in enumerate(data):
        if CRC_OFFSET <= index < CRC_OFFSET + 4:
            continue
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    return (~crc) & 0xFFFFFFFF


def build_namb(nam: Path, template: bytes) -> bytes:
    if len(template) != NAMB_SIZE or template[:4] != b"BMAN":
        raise ValueError("template must be a 7980-byte native NAMB record")
    output = bytearray(template)
    weights = load_weights(nam)
    output[WEIGHT_OFFSET : WEIGHT_OFFSET + WEIGHT_COUNT * 4] = struct.pack(
        f"<{WEIGHT_COUNT}f", *weights
    )
    struct.pack_into("<I", output, CRC_OFFSET, namb_crc32(output))
    return bytes(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nam", type=Path)
    parser.add_argument("template", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()
    output = build_namb(args.nam, args.template.read_bytes())
    args.output.write_bytes(output)
    print("wrote native NAMB candidate")


if __name__ == "__main__":
    main()
