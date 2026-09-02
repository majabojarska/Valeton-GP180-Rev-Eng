#!/usr/bin/env python3
"""Extract and validate GP-180 BMAN/VTSI file records from SysEx captures.

This tool deliberately handles the proven conversion/transport boundary only:
it does not invent BMAN tensor semantics or a device write transaction.
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from gp180_codec import decode_nibbles


@dataclass(frozen=True)
class FileTransferChunk:
    frame: int
    outer_check: int
    kind: int
    offset: int
    transfer_id: int
    chunk_index: int
    integrity_nibbles: tuple[int, int]
    payload: bytes

    @property
    def expected_offset(self) -> int:
        return 119 * self.chunk_index

    @property
    def offset_valid(self) -> bool:
        return self.offset == self.expected_offset

    @property
    def is_full(self) -> bool:
        return len(self.payload) == 118


def parse_transfer(corpus: Path, capture: str) -> dict[str, object]:
    """Parse a family-0x24 transfer without attempting to generate one.

    The 7-bit offset rule and 118-byte segmentation are corpus-proven.  The
    two nibble fields and byte 2 are returned as observations only: their
    checksum algorithm and scope remain unresolved.
    """
    with corpus.open() as stream:
        rows = [
            row
            for row in map(json.loads, stream)
            if row["capture"] == capture
            and row["family"] == "0x24"
            and row.get("direction", "host-to-device") == "host-to-device"
        ]
    rows.sort(key=lambda row: row["frame"])
    if not rows:
        raise ValueError(f"no family-0x24 host transfer found for {capture!r}")

    chunks: list[FileTransferChunk] = []
    for row in rows:
        raw = bytes.fromhex(row["raw"])
        # Family 0x24 also carries short control messages.  Only subtype 0x40
        # with the proven upload wire lengths belongs to this parser.
        if len(raw) < 5:
            raise ValueError(f"invalid family-0x24 framing at frame {row['frame']}")
        if raw[4] != 0x40:
            continue
        if len(raw) not in (44, 248):
            raise ValueError(f"invalid family-0x24 framing at frame {row['frame']}")
        if (
            len(raw) < 12
            or raw[:2] != b"\xf0\x7f"
            or raw[3] != 0x24
            or raw[-1] != 0xF7
        ):
            raise ValueError(f"invalid family-0x24 framing at frame {row['frame']}")
        if raw[5] > 0x7F or raw[6] > 0x7F:
            raise ValueError(f"offset is not 7-bit encoded at frame {row['frame']}")
        if any(value > 0x0F for value in raw[9:11]):
            raise ValueError(f"chunk integrity fields are not nibbles at frame {row['frame']}")
        chunks.append(
            FileTransferChunk(
                frame=row["frame"],
                outer_check=raw[2],
                kind=raw[4],
                offset=(raw[5] & 0x7F) | ((raw[6] & 0x7F) << 7),
                transfer_id=raw[7],
                chunk_index=raw[8],
                integrity_nibbles=(raw[9], raw[10]),
                payload=decode_nibbles(raw[11:-1]),
            )
        )

    if not chunks:
        raise ValueError(f"no family-0x24 host transfer found for {capture!r}")

    indexes = [chunk.chunk_index for chunk in chunks]
    offsets_valid = all(chunk.offset_valid for chunk in chunks)
    sequential = indexes == list(range(len(chunks)))
    transfer_id_stable = len({chunk.transfer_id for chunk in chunks}) == 1
    kind_stable = len({chunk.kind for chunk in chunks}) == 1
    data = b"".join(chunk.payload for chunk in chunks)
    if any(len(chunk.payload) not in (16, 118) for chunk in chunks):
        raise ValueError("family-0x24 upload contains an unexpected chunk size")
    if len(chunks) > 1 and any(not chunk.is_full for chunk in chunks[:-1]):
        raise ValueError("short family-0x24 chunk precedes the final chunk")

    # A device-to-host family-0x00 message immediately following the transfer
    # is the only completion indication present in the corpus.  It carries the
    # transfer id as a four-byte, zero-extended value and a zero status byte.
    completion_acks: list[dict[str, object]] = []
    transfer_id = chunks[0].transfer_id
    last_frame = chunks[-1].frame
    with corpus.open() as stream:
        for row in map(json.loads, stream):
            if row["capture"] != capture or row["family"] != "0x00":
                continue
            raw = bytes.fromhex(row["raw"])
            if (
                row["direction"] == "device-to-host"
                and len(raw) >= 10
                and row["frame"] > last_frame
                and raw[4:8] == bytes((0, 0, 0, transfer_id))
            ):
                completion_acks.append(
                    {"frame": row["frame"], "status": raw[8], "raw": raw.hex()}
                )

    return {
        "kind": chunks[0].kind,
        "transfer_id": transfer_id,
        "chunk_count": len(chunks),
        "full_chunk_count": sum(chunk.is_full for chunk in chunks),
        "final_chunk_size": len(chunks[-1].payload),
        "decoded_size": len(data),
        "transfer_prefix": data[:8].hex() if len(data) >= 8 else data.hex(),
        "indexes_sequential": sequential,
        "offsets_valid": offsets_valid,
        "transfer_id_stable": transfer_id_stable,
        "kind_stable": kind_stable,
        "chunks": chunks,
        "completion_acks": completion_acks,
        "per_chunk_integrity": "observed-nibbles-unverified",
        "outer_integrity": "observed-byte-unverified",
    }


def decode_capture(corpus: Path, capture: str) -> bytes:
    return b"".join(chunk.payload for chunk in parse_transfer(corpus, capture)["chunks"])


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
    transfer = parse_transfer(args.corpus, args.capture)
    data = b"".join(chunk.payload for chunk in transfer["chunks"])
    info = describe(data)
    info["transfer"] = {
        key: value for key, value in transfer.items() if key != "chunks"
    }
    if args.output:
        args.output.write_bytes(data[8:])
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
