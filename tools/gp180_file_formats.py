#!/usr/bin/env python3
"""Extract and validate GP-180 BMAN/VTSI file records from SysEx captures.

This tool deliberately handles the proven conversion/transport boundary only:
it does not invent BMAN tensor semantics or a device write transaction.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from gp180_codec import decode_nibbles


def decode_capture(corpus: Path, capture: str) -> bytes:
    with corpus.open() as stream:
        rows = [row for row in map(json.loads, stream) if row["capture"] == capture]
    rows = [row for row in rows if row["family"] == "0x24" and row["length"] >= 40]
    rows.sort(key=lambda row: row["frame"])
    if not rows:
        raise ValueError(f"no file-transfer messages found for {capture!r}")
    return b"".join(decode_nibbles(bytes.fromhex(row["raw"])[11:-1]) for row in rows)


def describe(data: bytes) -> dict[str, object]:
    if len(data) != 8158:
        raise ValueError(f"expected 8158 decoded bytes, got {len(data)}")
    transfer_prefix = data[:8]
    marker_offset = next(
        (offset for offset in (data.find(b"BMAN"), data.find(b"VTSI")) if offset >= 0),
        -1,
    )
    if marker_offset < 0:
        raise ValueError("no BMAN or VTSI marker found")
    record = data[marker_offset:]
    marker = record[:4].decode("ascii")
    result: dict[str, object] = {
        "marker": marker,
        "transfer_prefix": transfer_prefix.hex(),
        "record_size": len(record),
    }
    if marker == "BMAN":
        result["version"] = struct.unpack_from("<H", record, 4)[0]
        result["reserved"] = struct.unpack_from("<H", record, 6)[0]
        result["header_fields"] = [
            struct.unpack_from("<I", record, offset)[0]
            for offset in (8, 12, 16, 20, 24)
        ]
    else:
        result["model_region_size"] = struct.unpack_from("<I", record, 4)[0]
        result["integrity_field"] = struct.unpack_from("<I", record, 8)[0]
        result["fixed_field_14"] = struct.unpack_from("<I", record, 20)[0]
        result["scale"] = struct.unpack_from("<f", record, 28)[0]
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("capture")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    data = decode_capture(args.corpus, args.capture)
    info = describe(data)
    if args.output:
        args.output.write_bytes(data[8:])
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
