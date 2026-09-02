#!/usr/bin/env python3
"""Generate controlled NAM v0.7 variants for BMAN differential captures."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path


def variants(document: dict) -> list[tuple[str, str, dict]]:
    result: list[tuple[str, str, dict]] = [("00-baseline", "unchanged baseline", document)]

    def weight_variant(name: str, submodel: int, index: int, delta: float) -> None:
        item = copy.deepcopy(document)
        weights = item["config"]["submodels"][submodel]["model"]["weights"]
        weights[index] += delta
        result.append((name, f"submodel {submodel} weight[{index}] += {delta}", item))

    weight_variant("01-s0-weight-first", 0, 0, 1.0)
    weight_variant("02-s0-weight-middle", 0, 935, 1.0)
    weight_variant("03-s0-weight-last", 0, 1870, 1.0)
    weight_variant("04-s1-weight-first", 1, 0, 1.0)
    weight_variant("05-s1-weight-middle", 1, 6073, 1.0)
    weight_variant("06-s1-weight-last", 1, 12145, 1.0)
    weight_variant("07-s0-weight-sign", 0, 100, -2.0 * document["config"]["submodels"][0]["model"]["weights"][100])
    weight_variant("08-s1-weight-sign", 1, 100, -2.0 * document["config"]["submodels"][1]["model"]["weights"][100])

    for name, submodel, field, delta in (
        ("09-s0-gain", 0, "gain", 0.1),
        ("10-s0-loudness", 0, "loudness", 1.0),
        ("11-s1-gain", 1, "gain", 0.1),
        ("12-s1-loudness", 1, "loudness", 1.0),
    ):
        item = copy.deepcopy(document)
        metadata = item["config"]["submodels"][submodel]["model"]["metadata"]
        metadata[field] += delta
        result.append((name, f"submodel {submodel} metadata.{field} += {delta}", item))

    for name, submodel, value in (
        ("13-s0-max-value", 0, 0.75),
        ("14-s1-max-value", 1, 0.875),
    ):
        item = copy.deepcopy(document)
        item["config"]["submodels"][submodel]["max_value"] = value
        result.append((name, f"submodel {submodel} max_value = {value}", item))

    for name, submodel in (("15-s0-head-scale", 0), ("16-s1-head-scale", 1)):
        item = copy.deepcopy(document)
        model = item["config"]["submodels"][submodel]["model"]
        model["config"]["head_scale"] *= 1.1
        result.append((name, f"submodel {submodel} head_scale *= 1.1", item))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("-o", "--output-dir", type=Path, required=True)
    args = parser.parse_args()
    document = json.loads(args.source.read_text())
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name, change, item in variants(document):
        path = args.output_dir / f"HELLBERT-{name}.nam"
        path.write_text(json.dumps(item, separators=(",", ":")) + "\n")
        manifest.append({"file": path.name, "change": change})
    (args.output_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(manifest)} NAM variants to {args.output_dir}")


if __name__ == "__main__":
    main()
