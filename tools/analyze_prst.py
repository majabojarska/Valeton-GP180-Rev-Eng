#!/usr/bin/env python3
"""Analyze GP-180 .prst files and correlate family-0x70 corpus transfers."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path

from gp180_codec import decode_nibbles


def ranges(values: list[int]) -> list[list[int]]:
    result: list[list[int]] = []
    for value in values:
        if not result or value != result[-1][1] + 1:
            result.append([value, value])
        else:
            result[-1][1] = value
    return result


def printable_name(data: bytes) -> str:
    field = data[0x2C:0x74]
    return field.split(b"\0", 1)[0].decode("ascii", "replace")


def crc16_ccitt(data: bytes) -> int:
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = (
                ((value << 1) ^ 0x1021) & 0xFFFF
                if value & 0x8000
                else (value << 1) & 0xFFFF
            )
    return value


def transfer_report(corpus: Path, presets: list[tuple[Path, bytes]]) -> list[dict]:
    if not corpus.exists():
        return []
    records = [
        json.loads(line) for line in corpus.read_text().splitlines() if line.strip()
    ]
    groups: dict[tuple[str, str], list[dict]] = {}
    for record in records:
        if record.get("family") == "0x70":
            key = (record["capture"], record["direction"])
            groups.setdefault(key, []).append(record)
    reports = []
    for (capture, direction), messages in sorted(groups.items()):
        decoded = bytearray()
        valid = True
        for message in messages:
            raw = bytes.fromhex(message["raw"])
            try:
                # The seven-byte transfer header is itself nibble-coded from
                # offset 9. Its first eight decoded bytes are transfer metadata;
                # the following 1128 bytes are the .prst payload.
                decoded.extend(decode_nibbles(raw[9:-1]))
            except ValueError:
                valid = False
                break
        item = {
            "capture": capture,
            "direction": direction,
            "messages": len(messages),
            "message_lengths": Counter(m["length"] for m in messages),
            "decoded_length": len(decoded) if valid else None,
            "nibble_payload_offset": 9,
            "valid_nibble_stream": valid,
        }
        # Short status exchanges are not file transfers; only compare streams
        # large enough to plausibly contain a preset.
        is_file_capture = any(
            token in capture.lower()
            for token in ("patch-file", "import-patch", "export-slot")
        )
        if valid and len(decoded) >= 500 and is_file_capture:
            candidates = [bytes(decoded[8:])] if len(decoded) >= 8 else []
            best = None
            for path, data in presets:
                payload = candidates[0] if candidates else bytes(decoded)
                match = SequenceMatcher(
                    None, payload, data, autojunk=False
                ).find_longest_match(0, len(payload), 0, len(data))
                candidate = {
                    "file": path.name,
                    "longest_exact_run": match.size,
                    "decoded_offset": match.a + 8,
                    "file_offset": match.b,
                    "name": printable_name(data),
                }
                if (
                    best is None
                    or candidate["longest_exact_run"] > best["longest_exact_run"]
                ):
                    best = candidate
            item["best_preset_match"] = best
            item["decoded_prefix_hex"] = bytes(decoded[:16]).hex()
            item["payload_length"] = max(0, len(decoded) - 8)
        reports.append(item)
    return reports


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path, help="directory containing .prst files")
    parser.add_argument("--corpus", type=Path, default=Path("sysex-corpus.jsonl"))
    parser.add_argument("-o", "--output", type=Path, help="write JSON report")
    args = parser.parse_args()

    files = sorted(args.directory.glob("*.prst"))
    data = [path.read_bytes() for path in files]
    sizes = Counter(len(blob) for blob in data)
    invariant = [
        i
        for i in range(min(map(len, data), default=0))
        if len({blob[i] for blob in data}) == 1
    ]
    variant = [
        i
        for i in range(min(map(len, data), default=0))
        if len({blob[i] for blob in data}) > 1
    ]
    byte_cardinality = {str(i): len({blob[i] for blob in data}) for i in variant}
    names = [
        {"file": path.name, "name": printable_name(blob)}
        for path, blob in zip(files, data)
    ]
    report = {
        "files": len(files),
        "sizes": dict(sorted(sizes.items())),
        "sha256": {
            "unique": len({hashlib.sha256(blob).hexdigest() for blob in data}),
            "duplicates": len(data)
            - len({hashlib.sha256(blob).hexdigest() for blob in data}),
        },
        "invariant_ranges": [
            {"start": a, "end": b, "value_hex": data[0][a : b + 1].hex()}
            for a, b in ranges(invariant)
        ],
        "variant_ranges": [{"start": a, "end": b} for a, b in ranges(variant)],
        "variant_byte_cardinality": byte_cardinality,
        "header": {
            "magic_hex": data[0][:4].hex() if data else None,
            "constant_ranges": [
                {"start": a, "end": b}
                for a, b in ranges([i for i in range(0x84) if i in invariant])
            ],
            "name_offset": "0x2c",
            "name_size": 0x48,
            "index_offset": "0x04",
            "bpm_offset": "0x24",
            "volume_offset": "0x26",
            "chain_order_offset": "0x78",
            "chain_order_size": 12,
            "undetermined_bytes_0e_0f": {
                "distinct": len({blob[0x0E:0x10] for blob in data}),
                "values_first": [blob[0x0E:0x10].hex() for blob in data[:10]],
            },
        },
        "names": names,
        "module_layout": {
            "offset": "0x84",
            "block_size": "0x44",
            "blocks": 12,
            "footer_offset": "0x3b4",
            "footer_size": "0xb4",
        },
        "crc16_ccitt_candidates": {
            "field_0e_0f_le_matches_file_10_1128": sum(
                int(
                    int.from_bytes(blob[0x0E:0x10], "little")
                    == crc16_ccitt(blob[0x10:])
                )
                for blob in data
            ),
            "field_0e_0f_be_matches_file_10_1128": sum(
                int(int.from_bytes(blob[0x0E:0x10], "big") == crc16_ccitt(blob[0x10:]))
                for blob in data
            ),
        },
        "family_0x70_transfers": transfer_report(args.corpus, list(zip(files, data))),
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
