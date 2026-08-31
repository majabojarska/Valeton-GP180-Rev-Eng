#!/usr/bin/env python3
"""Generate a GP-180 effect-variant/parameter coverage matrix."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def parameter_text(parameter: dict) -> str:
    name = parameter.get("name") or parameter.get("title") or "?"
    value_range = parameter.get("valueRange", "")
    choices = parameter.get("showValue", "")
    if choices:
        return f"{name} ({choices})"
    return f"{name} [{value_range}]".rstrip()


def captured_names(capture_dir: Path) -> list[str]:
    return [norm(path.stem) for path in capture_dir.glob("*.pcapng")]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("module_data", type=Path)
    parser.add_argument("capture_dir", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument(
        "--json-output",
        type=Path,
        help="also write a machine-readable metadata/wire-schema projection",
    )
    args = parser.parse_args()

    modules = json.loads(args.module_data.read_text())["modules"]
    capture_names = captured_names(args.capture_dir)
    lines = [
        "# GP-180 effect variant and parameter matrix",
        "",
        "Generated from Suite `module_data.json`. This is the UI-side contract: "
        "each variant exposes only the parameters listed on its row. Ranges "
        "and enum labels are copied from the Suite metadata.",
        "",
        "| Module | Variant | `fxid` | Parameters | Capture evidence |",
        "|---|---|---:|---|---|",
    ]
    missing_variants = []
    missing_parameters = []
    variant_count = parameter_count = 0

    for module in modules:
        module_name = module["name"]
        for effect in module["module"]:
            variant = effect.get("name") or effect.get("fxtitle") or "?"
            parameters = effect.get("alg", [])
            parameter_count += len(parameters)
            variant_count += 1
            row_text = " ; ".join(parameter_text(item) for item in parameters)
            variant_key = norm(variant)
            module_key = norm(module_name)
            matching_captures = [
                name
                for name in capture_names
                if module_key in name and variant_key in name
            ]
            variant_seen = bool(matching_captures)
            covered = []
            for parameter in parameters:
                name = parameter.get("name") or parameter.get("title") or ""
                if norm(name) and any(
                    norm(name) in capture for capture in matching_captures
                ):
                    covered.append(name)
                elif name:
                    missing_parameters.append((module_name, variant, name))
            if not variant_seen:
                missing_variants.append((module_name, variant))
            evidence = (
                "variant filename found" if variant_seen else "MISSING variant capture"
            )
            if covered:
                evidence += "; parameters: " + ", ".join(sorted(set(covered)))
            lines.append(
                f"| {module_name} | {variant} | {effect.get('fxid', '')} | "
                f"{row_text} | {evidence} |"
            )

    lines += [
        "",
        "## Coverage summary",
        "",
        f"- Variants in metadata: **{variant_count}**",
        f"- Parameters in metadata: **{parameter_count}**",
        f"- Variants without a matching capture filename: **{len(missing_variants)}**",
        f"- Parameters without a matching variant/parameter filename: **{len(missing_parameters)}**",
        "",
        "## Missing variant captures",
        "",
    ]
    for module_name, variant in missing_variants:
        lines.append(f"- `{module_name}` / `{variant}`")
    lines += ["", "## Missing parameter captures", ""]
    for module_name, variant, parameter in missing_parameters:
        lines.append(f"- `{module_name}` / `{variant}` / `{parameter}`")

    output = "\n".join(lines) + "\n"
    if args.output:
        args.output.write_text(output)
    else:
        print(output, end="")

    if args.json_output:
        schema = []
        for module in modules:
            for effect in module["module"]:
                fxid = int(effect.get("fxid", 0))
                parameters = []
                for parameter in effect.get("alg", []):
                    parameters.append(
                        {
                            "name": parameter.get("name") or parameter.get("title"),
                            "algId": parameter.get("algId"),
                            "sync": parameter.get("sync"),
                            "defaultValue": parameter.get("defaultValue"),
                            "valueRange": parameter.get("valueRange"),
                            "min": parameter.get("min"),
                            "max": parameter.get("max"),
                            "step": parameter.get("step"),
                            "code": parameter.get("code"),
                            "widgetType": parameter.get("widgetType"),
                            "show": parameter.get("show", []),
                            "wire": {
                                "family": "0x18",
                                "moduleFamilyOffset": 34,
                                "variantSelector": {"offset": 39, "length": 2},
                                "value": {
                                    "offset": 45,
                                    "length": 8,
                                    "encoding": "nibble-word-byte-swapped-float32",
                                },
                                "confidence": "captured-common-layout; parameter discriminator pending",
                            },
                        }
                    )
                schema.append(
                    {
                        "module": module["name"],
                        "moduleId": module.get("moduleId"),
                        "variant": effect.get("name") or effect.get("fxtitle"),
                        "fxid": fxid,
                        "fxidHex": f"0x{fxid:08x}",
                        "fxidModuleFamily": (fxid >> 24) & 0xFF,
                        "fxidLocal": fxid & 0xFFFFFF,
                        "parameters": parameters,
                    }
                )
        args.json_output.write_text(json.dumps(schema, indent=2) + "\n")


if __name__ == "__main__":
    main()
