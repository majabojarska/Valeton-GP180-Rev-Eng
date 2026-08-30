# GP-180 Reverse-Engineering History

This document records the reverse-engineering work completed so far on the
Valeton GP-180, its firmware, and Valeton Suite. It is intended as historical
context; current priorities and actionable tasks are maintained in `plan.md`.

## Scope and safety

The work covers:

- Valeton Suite installer and extracted Windows, Android, macOS, and iOS assets.
- GP-180 firmware V1.0.0 and V1.1.1.
- USBPcap captures of Suite/device traffic.
- Preset, NAM, IR, firmware-update, global-setting, and effect traffic.
- Static analysis of native libraries and the Flutter/Dart AOT snapshot.

No firmware update, factory reset, destructive device write, or hardware
modification was performed.

## Initial artifact analysis

The supplied Suite installer was extracted into the session workspace and its
executables, DLLs, native libraries, Flutter assets, and data files were
inventoried and hashed. The firmware files were treated as immutable raw
artifacts. `analysis-manifest.md` contains the artifact inventory and source
references.

The Suite includes two effect metadata assets:

| Asset | Variants | Parameters |
|---|---:|---:|
| `module_data.json` | 209 | 825 |
| `module150_data.json` | 348 | 1,701 |

The richer `module150_data.json` became the primary source for the effect
variant matrix. It contains module IDs, packed effect IDs, parameter algorithm
IDs, ranges, steps, defaults, enum/display values, and conversion metadata.
`effect-variant-matrix.md` and `tools/effect_matrix.py` document and regenerate
this UI-side catalog.

## USB transport and framing

USB MIDI traffic uses:

- Host-to-device endpoint `0x03`.
- Device-to-host endpoint `0x83`.
- Four-byte USB MIDI event packets.
- SysEx messages fragmented across packet boundaries.

USBPcap transfer boundaries do not reliably correspond to SysEx boundaries.
Analysis therefore reassembles complete SysEx messages before interpreting
payloads.

The common framing begins with:

```text
F0 7F <integrity/check byte> ...
```

The native Suite library exports generic transport helpers including
`EncodeToMIDSysEx`, `DecodeToMIDSysEx`, `calcCRC`, and
`HTDevice::addSendMessage`. The native layer queues already-built messages;
effect-specific semantics are constructed in the Dart/AOT application layer.

The recovered nibble codec encodes each byte as high nibble followed by low
nibble. CRC-8 uses polynomial `0x07` with zero initialization and high nibble
followed by low nibble. Exact command-specific CRC scope remains contextual
for some families.

## Message-family classification

The major observed families are:

| Family | Observed purpose |
|---:|---|
| `0x00` | ACK and handshake |
| `0x0c` | Global EQ/settings |
| `0x0f` | Preset selection/export requests |
| `0x10` | Module/parameter operations and firmware traffic |
| `0x14` | Variant selectors, drums, and metronome operations |
| `0x18` | Live parameter writes/reports and chain reorder |
| `0x1c` | Input/output, USB settings, and metadata |
| `0x20` | Rename, tuner, and status |
| `0x22` | MIDI settings |
| `0x24` | File and global-setting transfers |
| `0x2c` | Device-triggered preset save |
| `0x30` | Footswitch events/settings |
| `0x5c` | Drum/metronome responses |
| `0x70` | Patch/file transfer |
| `0x7c` | EXP target/state |

## Global controls and device state

Captures mapped input/output settings, USB levels and modes, MIDI channels and
clock settings, EXP/footswitch assignments, display brightness and timeout,
tap synchronization, Auto Save, factory-reset selectors, module toggles,
preset selection, drums, tuner, preset saving, chain reordering, and several
device-triggered state reports.

Important mappings include:

- Module bypass: family `0x10`, full offset `36`; generally `00=off`,
  `01=on`.
- Common module selector: often full offset `31`.
- Chain reorder: family `0x18`, permutation values at full offsets
  `36,38,...,56`.
- Drum volume: family `0x14`, full offset `38`.
- Drum enable: family `0x14`, full offset `46`.
- Drum BPM: family `0x14` and mirrored family `0x5c`, full offset `33:35`.
- Auto Save: family `0x24`, full offset `78`.

Global EQ packed fields were solved as nibble-coded little-endian IEEE-754
floats:

- Low cut: `57:65`
- High cut: `35:43`
- Band 4 frequency: `209:217`
- Band 4 Q: `217:225`
- Band 4 gain: `225:233`
- Global EQ level: `45:53`

Global EQ position was intentionally deferred because it must be distinguished
from moving an EQ item in the preset signal chain. USB routing/modes,
Bluetooth routing/volume, display language, and generic display mode were also
recorded as deferred scopes in `deferred-captures.md`. Bluetooth enable/disable
was confirmed to be device-local rather than a USB/MIDI operation.

## Firmware update analysis

Both supplied firmware files are `HTFW` containers with seven region IDs.
Raw USB parsing correlated 69,510 host family-`0x10` update messages with the
V1.1.1 image.

The transfer contains 1,986 page groups of 35 records:

- 34 records decode to 118 bytes.
- The final record decodes to 65 bytes.
- Total decoded transfer size is 8,096,922 bytes.

The seven regions match 4 KiB-ceiling group boundaries:

```text
b = 0..1300
c = 1301..1383
d = 1384..1686
e = 1687..1759
f = 1760..1823
g = 1824..1981
h = 1982..1985
```

Packet sizing, sequence counters, ACK polarity, CRC behavior, lifecycle
commands, and the modulo-128 group counter were characterized. The counter
skips two values at region transitions alongside extra family-`0x08` replies.
The omitted 19-byte/page representation, update-header bytes 5..6, error
codes, and final ACK/reboot behavior remain unresolved.

## Preset, NAM, and IR transfers

Preset import/export traffic was reconstructed sufficiently to correlate
family-`0x70` streams with `.prst` files. Preset names appear in transfer
metadata and are duplicated in save-related streams. The complete preset
schema and direct slot-number field remain incomplete.

The supplied NAM was identified as standard Neural Amp Modeler Core `0.7.0`.
Converted NAM output uses the `BMAN` marker and native serializer symbols.
NAM and IR transfers use family `0x24`; IR imports are converted to a fixed
device representation. Complete BMAN serialization, IR quantization, and
normalization remain to be recovered.

## Effect captures and metadata

Effect coverage was built incrementally across NR, PRE, AMP, DST, CAB, WAH,
EQ, MOD, DLY, RVB, and N→S modules. Variant selectors commonly use family
`0x14` with selector bytes at full offsets `33:35`, but selector values are
contextual and are not globally unique.

Numeric effect edits use family `0x18` and generally place an eight-nibble
value block at full offsets `45:53`. Many values use a word/byte-swapped
float representation:

```python
b = [
    (n[0] << 4) | n[1],
    (n[2] << 4) | n[3],
    (n[4] << 4) | n[5],
    (n[6] << 4) | n[7],
]
value = struct.unpack(">f", bytes([b[1], b[0], b[3], b[2]]))[0]
```

The neighboring effect-state bytes vary by algorithm and parameter, so a
universal discriminator was not inferred from captures alone.

G-Chorus demonstrated an important mode-dependent exception:

- Sync off: Rate is free-running `0.10–10.00 Hz`.
- Sync on: Rate represents subdivisions relative to BPM.

Therefore parameter decoding must retain synchronization state and BPM rather
than interpreting Rate using one universal unit.

## Static Suite analysis

Standard Ghidra analysis located binding strings but did not recover ordinary
cross-references because the Flutter application is a generated Dart AOT ELF.
Relevant names include:

- `getFxIdByModuleIdAndTypeName`
- `getAlgsByModuleIdAndFxId`
- `parseParameters`
- `writeParameter`
- `getParameterTypes`
- `fxidList`
- `AlgParamValueStruct`

The native ARM64/Windows protocol libraries were compared and found to share
protocol behavior while differing mainly in MIDI backend details.

## AOTopsy recovery

The `BroNils/aotopsy` tool was built and successfully recognized the Suite
snapshot:

- Dart `3.5.0`
- x86-64
- Product build
- Uncompressed 8-byte pointers
- Snapshot hash
  `80a49c7111088100a233b2ae788e1f48`

AOTopsy recovered 23,330 code entries and useful method metadata. Important
recovered methods include:

| Method | Address |
|---|---:|
| `Module150Provider.getAlgsByModuleIdAndFxId` | `0x543098` |
| `Device150DataProvider.switchAlgValue` | `0x664fa0` |
| `AlgParamValueStruct.toBytes` | `0x66599c` |
| `AlgParamValueStruct.fromBytes` | `0x916140` |

`switchAlgValue` is called by the effect parameter widget closures. It creates
an `AlgParamValueStruct`, serializes it, and passes the result to
`HTMidiDataProtocol.sendMessage`. The device-report path calls
`fromBytes`, confirming a shared application-side representation for outgoing
and incoming algorithm values.

The serializer allocates a 32-byte little-endian record. The meaningful fields
are:

| Bytes | Current interpretation |
|---:|---|
| `0:2` | Magic `0x3033` |
| `2:4` | 16-bit structure/type field |
| `4:8` | 32-bit identifier, adjacent-byte-swapped on serialization |
| `8:12` | IEEE-754 float32 value |
| `12:13` | Auxiliary byte |
| `13:14` | Auxiliary byte |
| `14:16` | Zero/reserved |
| `16:32` | Zero-initialized padding |

This is the first static bridge between Suite effect metadata and the
captured family-`0x18` numeric value block. Exact semantic names for the
identifier, type, and auxiliary fields remain to be recovered.

New DLY, RVB, and VOL captures then confirmed the shared numeric layout:
family-`0x18` full offset `34` carries the module-family byte, offsets
`39:41` carry the contextual variant selector, and offsets `45:53` carry the
word/byte-swapped float value. The decoded values reproduce DLY Mix/Time/Feed,
RVB Mix/Decay/Pre-Delay, and VOL values within normal Suite quantization.
DLY and RVB do not expose a Volume parameter; the cross-module Volume
comparison used PRE, AMP, CAB, and VOL. The separate parameter-persistence
capture was intentionally skipped because it is outside the current live
parameter scope.

Further inspection of `updateAlgValue` shows that the two auxiliary bytes are
used as context/index values while walking effect-chain and parameter lists;
the float is the actual received value. Their exact module/effect/parameter
roles remain unresolved because Dart field names were not preserved.

The recovered effect-dropdown callbacks convert enum selections from integer
to `double` and use the same `switchAlgValue` serializer as sliders. Thus enum
meaning is supplied by variant metadata, while the wire value remains a
common typed numeric field.

The subsequent capture batch completed the planned mode-dependent coverage:
DLY synchronized, Sweep Echo, and Dual Echo timing controls; C-Chorus modes;
Hammy WAH range/harmony; DST mode, attack, drive, boost, fat, and air
controls; AMP Bright/Char controls; N→S EV53 CH1 numeric controls; a second
CAB variant; and Guitar EQ 2. None introduced a new live-parameter transport
family or serializer. The remaining effect-side task is therefore
correlation and schema normalization rather than more broad capture sweeps.

Cross-correlation of DLY/RVB selector captures shows that family `0x14` full
offset `12` carries the module-family byte (`0x0b` for DLY and `0x0c` for
RVB), matching the high byte of their metadata `fxid` values. The selector at
full offsets `33:35` is a separate contextual local encoding, not the raw
metadata low word; for example, DLY `999 Echo` metadata ID `0x12` is sent as
selector `0102`.

`Module150Provider.getAudioChannelByModuleIdAndFxId` was then recovered. It
looks up a module/effect pair in the nested metadata lists and returns the
effect's `audioChannel` property. `switchAlgValue` stores that result in the
record field serialized at bytes `12:13`, establishing that field as an
audio-channel/context value. The adjacent byte stores the first integer
context argument; the remaining distinction between effect and parameter
identifiers is still under investigation.

`Alg.fromMap`/`toMap` also recovered the parameter metadata field order:
`+0x0f` is `algId`, while `+0x17` is the default-value string and `+0x1f`
is the display range. The other fields are min, max, step, conversion code,
widget type, and display values. Consequently, an AOT access to `Alg+0x0f`
is the direct parameter ID; accesses to `Alg+0x17` must not be interpreted as
an ID.

The widget construction path stores the selected `Alg` object in widget field
`+0x0f`; adjacent widget fields retain the parameter and chain context used by
the callbacks. This provides a concrete anchor for tracing the callback to
`Alg+0x0f` rather than guessing from nearby raw bytes.

AOTopsy's complete Dart export currently crashes in its decompiler. Targeted
raw assembly and function metadata remain usable and are preferred for
continued analysis.

## Windows native CRC tracing

Static disassembly of the exported `checkCrc` routine in `5868USB.dll` resolved
the native 16-bit validation primitive. It initializes a reflected CRC-16 state
to `0xffff`, processes the supplied range beginning at native pointer offset
`+6`, and uses polynomial `0xa001`. The routine compares the result in the
DLL's table-byte order, represented by `tools/gp180_codec.crc16_native()`.
This is distinct from the one-byte outer SysEx CRC-8. Captured family-`0x24`
per-chunk integrity bytes do not match simple applications of this CRC, so the
write-side envelope remains intentionally offline-only.

## Tooling and documentation produced

- `analysis-manifest.md`: artifact inventory and hashes.
- `usbcap-analysis.md`: primary protocol evidence report.
- `plan.md`: current milestones and priorities.
- `deferred-captures.md`: intentionally postponed capture scopes.
- `effect-capture-plan.md`: controlled effect-capture methodology.
- `effect-variant-matrix.md`: generated UI-side effect/parameter matrix.
- `effect-wire-schema.json`: generated machine-readable projection combining
  effect metadata with the currently confirmed family-`0x18` wire layout.
- `tools/gp180_codec.py`: CRC, nibble, SysEx, and selected payload helpers.
- `tools/effect_matrix.py`: effect-matrix generator.
- `tools/ghidra_binding_report.java`: repeatable AOT string/reference scan.

## Current conclusion

The transport layer, major command families, firmware transfer structure,
global controls, and a large portion of the effect catalog are understood.
The strongest remaining protocol task is to finish the AOT binding trace:
assign semantic meaning to the typed parameter record fields, correlate them
with known captures, and generate a normalized wire schema for every supported
module variant. Broad additional capture campaigns should wait until that
static path identifies specific ambiguities.
