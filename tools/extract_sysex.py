#!/usr/bin/env python3
"""Extract Wireshark-reassembled MIDI SysEx messages from pcapng captures."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
from typing import Iterable

FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "usb.endpoint_address",
    "usb.src",
    "usb.dst",
    "usbaudio.sysex.reassembled.in",
    "usbaudio.sysex.reassembled.length",
    "usbaudio.sysex.fragment.count",
    "usbaudio.sysex.reassembled.data",
)
TRANSFER_FAMILIES = {0x10, 0x24, 0x70}


def capture_paths(inputs: Iterable[str]) -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for value in inputs:
        path = pathlib.Path(value)
        if path.is_dir():
            paths.extend(sorted(path.glob("*.pcapng")))
        elif path.is_file():
            paths.append(path)
        else:
            raise ValueError(f"capture path does not exist: {value}")
    return sorted(set(paths))


def integer(value: str) -> int | None:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return None


def message_record(capture: pathlib.Path, row: list[str]) -> dict[str, object]:
    (
        frame,
        timestamp,
        endpoint,
        source,
        destination,
        reassembled_in,
        reassembled_length,
        fragment_count,
        raw,
    ) = row
    raw = raw.strip().lower()
    data = bytes.fromhex(raw)
    family = data[3] if len(data) > 3 and data[:2] == b"\xf0\x7f" else None
    record: dict[str, object] = {
        "capture": capture.name,
        "frame": integer(frame),
        "timestamp": timestamp or None,
        "endpoint": endpoint or None,
        "direction": (
            "host-to-device"
            if endpoint and (int(endpoint, 0) & 0x80) == 0
            else "device-to-host"
            if endpoint
            else None
        ),
        "usb_source": source or None,
        "usb_destination": destination or None,
        "family": f"0x{family:02x}" if family is not None else None,
        "length": len(data),
        "raw": raw,
        "reassembled_in": integer(reassembled_in),
        "fragment_count": integer(fragment_count),
    }
    # All observed GP-180 messages put the four-byte transaction ID directly
    # after F0 7F <checksum> <family>. Keep transfer headers raw because their
    # interpretation differs between families and captures.
    if len(data) >= 8 and data[:2] == b"\xf0\x7f":
        record["transaction_id"] = data[4:8].hex()
    else:
        record["transaction_id"] = None
    if family in TRANSFER_FAMILIES and len(data) >= 12:
        record["chunk_header"] = data[8:12].hex()
    else:
        record["chunk_header"] = None
    record["tshark_reassembled_length"] = integer(reassembled_length)
    return record


def extract(capture: pathlib.Path, tshark: str) -> list[dict[str, object]]:
    command = [
        tshark,
        "-n",
        "-r",
        str(capture),
        "-Y",
        "usbaudio.sysex.reassembled.data",
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
    ]
    for field in FIELDS:
        command.extend(["-e", field])
    try:
        completed = subprocess.run(
            command,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"tshark executable not found: {tshark}") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip().splitlines()[-1:] or ["unknown tshark error"]
        raise RuntimeError(f"{capture}: {detail[0]}") from exc
    records = []
    for line_number, line in enumerate(completed.stdout.splitlines(), 1):
        row = line.split("|")
        if len(row) != len(FIELDS):
            raise RuntimeError(f"{capture}: malformed tshark row {line_number}")
        try:
            records.append(message_record(capture, row))
        except ValueError as exc:
            raise RuntimeError(
                f"{capture}: invalid SysEx row {line_number}: {exc}"
            ) from exc
    return records


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract reassembled MIDI SysEx messages from pcapng files using tshark."
    )
    parser.add_argument("captures", nargs="+", help="pcapng files or directories")
    parser.add_argument("-o", "--output", help="JSONL output path (default: stdout)")
    parser.add_argument("--tshark", default="tshark", help="tshark executable")
    args = parser.parse_args()
    try:
        paths = capture_paths(args.captures)
        if not paths:
            raise ValueError("no .pcapng captures found")
        output = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
        count = 0
        try:
            for path in paths:
                for record in extract(path, args.tshark):
                    output.write(json.dumps(record, separators=(",", ":")) + "\n")
                    count += 1
        finally:
            if args.output:
                output.close()
        print(f"captures={len(paths)} messages={count}", file=sys.stderr)
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
