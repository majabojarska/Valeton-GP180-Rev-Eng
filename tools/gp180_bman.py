#!/usr/bin/env python3
"""Build a GP-180 BMAN candidate from a NAM v0.7 model.

The BMAN metadata schema and integrity field are not fully recovered. This
writer therefore requires a captured BMAN of the same architecture as a
template and replaces the currently identified weight region. Its output
is an analysis artifact, not a hardware-safe file.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

BMAN_SIZE = 8123
WEIGHT_OFFSET = 0x1EC
WEIGHT_COUNT = 1871
WEIGHT_SIZE = WEIGHT_COUNT * 4


def load_weights(path: Path) -> list[float]:
    document = json.loads(path.read_text())
    if document.get("version") != "0.7.0":
        raise ValueError("only NAM version 0.7.0 is supported")
    if document.get("architecture") != "SlimmableContainer":
        raise ValueError("only SlimmableContainer NAM files are supported")
    submodels = document.get("config", {}).get("submodels", [])
    if not submodels:
        raise ValueError("NAM has no submodels")
    model = submodels[0].get("model", {})
    if model.get("architecture") != "WaveNet":
        raise ValueError("only WaveNet NAM models are supported")
    if model.get("sample_rate") != 48000.0:
        raise ValueError("only 48 kHz NAM models are supported")
    weights = model.get("weights")
    if not isinstance(weights, list) or len(weights) != WEIGHT_COUNT:
        raise ValueError(f"expected {WEIGHT_COUNT} weights in first submodel")
    return [float(value) for value in weights]


def build_candidate(nam: Path, template: bytes) -> bytes:
    if len(template) != BMAN_SIZE or template[:4] != b"BMAN":
        raise ValueError("template must be an 8123-byte BMAN record")
    output = bytearray(template)
    weights = load_weights(nam)
    output[WEIGHT_OFFSET : WEIGHT_OFFSET + WEIGHT_SIZE] = struct.pack(
        f"<{WEIGHT_COUNT}f", *weights
    )
    return bytes(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nam", type=Path)
    parser.add_argument("template", type=Path, help="captured 8123-byte BMAN record")
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()
    candidate = build_candidate(args.nam, args.template.read_bytes())
    args.output.write_bytes(candidate)
    print(
        f"wrote {len(candidate)} bytes; integrity field at 0x18 "
        "was preserved from the template and is not recomputed; do not upload"
    )


if __name__ == "__main__":
    main()
