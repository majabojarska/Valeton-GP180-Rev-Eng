# GP-180 Reverse-Engineering Plan

## Current position

- USB MIDI transport, message families, transaction behavior, and device-triggered
  reports are documented in `usbcap-analysis.md`.
- Android Suite native symbols were recovered.
- The native nibble codec and CRC-8 primitive are implemented in
  `tools/gp180_codec.py`.
- Exact command-specific payload boundaries and file-transfer layouts remain
  unresolved. Native `getMidiMessage` now confirms CRC covers its four-byte
  logical header plus payload; command-family field mapping is still pending.
- NAM conversion is confirmed to be native and separate from transport; the
  decoded stream contains a versioned `BMAN` binary output.
- Three independent IR imports now confirm a fixed 8,158-byte converted
  representation and a shared transport envelope.
- The firmware capture does contain an update stream; raw USB bulk parsing finds
  69,518 large host-to-device SysEx messages that Wireshark did not expose via
  its reassembled SysEx field.
- Decoded update data contains long exact byte runs from the supplied v1.1.1
  image at piecewise offsets, confirming region/page records rather than a
  false-positive synchronization stream.
- The v1.1.1 header's seven declared region lengths sum to 8,131,192 bytes,
  explaining the approximately 8.1 MB decoded update stream.
- Native `HTSubFirmware::pushMidiMessage` now establishes 42-byte regular
  packets, 19-byte final packets, a `0xff` logical command byte, an advancing
  transfer counter, and CRC over the logical header plus payload.
- Static ACK handlers establish zero as success and nonzero as resend/error;
  firmware ACKs are dispatched while device state is `2`.
- `HTSubFirmware::getHead` now exposes a 12-byte outer header with a
  sub-firmware identifier and two explicit little-endian 32-bit fields tied to
  the source limit and transfer state.
- The fixed outer-header template bytes are confirmed as `0x11, 0x61`;
  constructor and firmware-list initialization paths are identified.
- Lifecycle command templates are confirmed for start (`11 60`), data/header
  (`11 61`), per-region end (`11 6e`), and all-regions end (`11 6e` with
  aggregate checksums).
- `sendJump` (`11 6f`) and the separate wrapping firmware checksum
  (`sum(bytes) + length`, modulo 256) are identified.
- `analysisFile` now resolves the 16-byte firmware-list records, validates each
  region with CRC16, and proves the `11 61` header fields are packet count and
  cumulative source length. It also confirms optional decompression before
  record parsing.
- Suite `module_data.json` provides 209 effects and 825 named/ranged
  parameters across 10 module groups; transport-byte correlation remains
  separate.
- `HTDevice::addSendMessage` is identified as the native dispatch boundary;
  it queues family-specific arrays, suppresses duplicates, and controls ACK
  waiting/retry behavior.
- Windows `5868USB.dll` export tracing recovered `checkCrc`: it uses an
  initial `0xffff` reflected CRC-16 with polynomial `0xa001`, processing the
  caller range from native offset `+6`. The native comparison stores the CRC
  bytes in reversed integer order, now implemented as `crc16_native()` in
  `tools/gp180_codec.py`.
- This CRC-16 is a file/message validation primitive, not yet the unidentified
  one-byte family-`0x24` per-chunk header value. Direct tests against captured
  upload chunks do not match simple CRC scopes, so generated writes remain
  disabled.
- Suite drum metadata contains 129 patterns across 14 groups, while native
  playback exposes BPM, velocity, transpose, looping, mute, and playback APIs;
  device CC `73`/`74` and `92`–`96` remain capture/PDF-defined.
- The Flutter snapshot exposes all requested Device Global Settings subpages:
  Input/Output, USB, Global EQ, Tap, Footswitch, Bluetooth, Auto Save,
  Display, and EXP/FS/MIDI. Their model fields and update entry points are
  documented; exact SysEx payload offsets still require caller/capture
  correlation.
- Native inspection confirms these settings are Dart/AOT-side wrappers around
  the generic `HTDevice::addSendMessage` boundary; no separate native C++
  setters expose their wire payloads. Recovering offsets now requires Dart AOT
  call-site decoding or controlled captures for each setting.
- Full Suite page inventory completed: connection/init, Edit, patch/IR/NAM/
  SnapTone/Tone Capture management, drum/metronome, tuner, looper, firmware
  update, About/software settings, and shared file dialogs are mapped in the
  report. Separate 150/300 widgets indicate model-specific feature variants.
- The controlled Global EQ off/on capture confirms family `0x0c` message offset
  `0x22` as the Global EQ enable flag (`0,1,0,1` across the capture); band
  values and EQ position still need value-changing captures.
- Added a reproducible capture matrix covering all unresolved global controls,
  effect parameters, file operations, tuner/drums, device identity, and the
  remaining firmware lifecycle questions. First priority is Global EQ bands,
  input/output, USB routing, EXP, and MIDI routing.
- New controlled corpus analyzed: 121 captures and 3,827 complete SysEx
  messages. Confirmed offsets now cover Global EQ fields, I/O, USB levels and
  modes, display, tap, Auto Save, MIDI channels/clock, EXP/FS assignments,
  module toggles, factory-reset selectors, patch selection, and device-side
  BPM/drum/footswitch reports. Remaining work is packed numeric decoding,
  complete effect-ID mapping, and preset/global-state schema reconstruction.
- Remaining capture needs are now prioritized in `usbcap-analysis.md`: P1
  global-setting gaps (EQ position/band 4 gain, USB routing/modes, display
  language/mode, Bluetooth modes, remaining MIDI clock paths, EXP calibration,
  and drum tap sync); P2 complete effect/preset/drum schemas; P3 NAM/IR
  round-trips and GP-180/GP-300 capability comparison.
- Follow-up packed-EQ captures solved the numeric representation: eight
  nibble bytes reconstruct little-endian IEEE-754 float32 values. Low/high
  cut, band-4 frequency/Q/gain fields are mapped to exact SysEx ranges; only
  Suite display quantization formulas remain.
- User correction recorded: GP-180 has no controllable display-language
  setting; generic Suite `displayMode` is not confirmed as a device control.
  Bluetooth enable/disable is device-local and produces no USB/MIDI traffic.
- Latest device-triggered captures map drum volume/time-signature/tap tempo,
  Auto Save, preset chain reorder permutations, tuner template state, and
  manual-save name encoding. New AMP captures confirm family `0x18` live
  parameter blocks at full offsets `45:53`; conversion remains effect-specific
  until more modules are captured.
- Fresh NR/PRE captures map NR and PRE variant selectors on family `0x14`,
  decode family-`0x18` numeric values from the `45:53` word-swapped float
  block (including split NR release), and identify NR toggle offset `0x24`
  (`00=off`, `01=on`). COMP4 and OD-9 parameter discriminators are now
  confirmed.
- New effect captures extend representative coverage to DST, CAB, and WAH:
  family-`0x14` variant selector pairs were recorded for the available DST
  and WAH algorithms, while family-`0x18` numeric edits confirm the shared
  `45:53` block for DST parameters, CAB Volume/High Cut/Low Cut/Precision,
  and V-Wah Range/Q/Volume/Position. Their effect-specific discriminators
  remain to be normalized.
- The latest batch completes focused enum/mode coverage for Hammy WAH,
  Force/Flex OD/Black Bass/Bass Hammer/Boost/Scream OD, and four AMP Bright
  variants plus Foxy 30TB Char. It also adds the first complete N→S live
  numeric calibration (EV53 CH1 Gain, Bass, Treble, VOL, Middle, Presence),
  a second CAB variant (LUX 1x12), and Guitar EQ 2 band/Volume edits.
- `patches-dump/` now contains 200 raw `.prst` files, each 1,128 bytes,
  including names and repeated GP-180 factory/user-preset structures. This is
  sufficient for differential preset-field analysis before requesting more
  preset captures. Initial comparison confirms the name region near offset
  `0x2c`, a stable structured body with sparse algorithm/state deltas, and
  distinct per-preset header/check fields near offsets `0x0e`–`0x0f`.
- Direct comparison with `GP150_PRST_FORMAT.md` confirms that the GP-180 dump
  shares the complete 1,128-byte header/module/footer geometry, 12-slot chain
  table, AMP-at-position-zero rule, and position/type-dependent engine tags.
  The GP-150 schema is now the working GP-180 baseline; only GP-180-specific
  effect-code/parameter differences and the 11-byte import wrapper remain.
- Static Suite metadata can now extrapolate the complete effect vocabulary:
  209 effects and 825 parameters with `fxid`, `algId`, ranges, steps, and
  display-conversion codes. This is sufficient to build an offline catalog,
  but wire encoding still needs calibration per algorithm to map metadata
  identifiers to the changing family-`0x18` state bytes.
- New EQ/MOD captures map EQ variant selectors and bypass, Guitar EQ 1 band
  gains/Volume, and 18 MOD selectors. G-Chorus confirms that Rate is
  mode-dependent: Sync off uses `0.10–10.00 Hz`, while Sync on uses timing
  subdivisions (`1/1`, `1/2`, dotted/triplet `1/2`, `1/4`, dotted `1/4`,
  `1/16`) derived from BPM rather than Hz.
- `effect-variant-matrix.md` now enumerates every UI variant and parameter
  from `module_data.json`, with ranges/enums and conservative filename-based
  capture evidence. Its missing-variant and missing-parameter sections are
  the current capture backlog; aliases such as `VOL`/`Volume` require manual
  reconciliation before recording duplicates.
- New DLY/RVB selector captures reveal additional device/Suite variants absent
  from `module_data.json`, including BBD/Digital Delay S, 999 Echo, Vintage
  Rack, Dual Echo, Tube Spring, Concert, and Shimmer. Selector `0003` is
  contextual rather than globally unique. These variants still need
  parameter-subset and range captures.
- The richer shared Suite asset `module150_data.json` contains 348 variants
  and 1,701 parameter definitions, including those DLY/RVB/MOD/WAH entries.
  AOT strings expose `getFxIdByModuleIdAndTypeName`, `getAlgsByModuleIdAndFxId`,
  `parseParameters`, and `writeParameter`, confirming a recoverable
  UI-to-wire binding path. Static tracing of `writeParameter` is now higher
  value than blind parameter sweeps.
- ARM64 disassembly confirms `EncodeToMIDSysEx`/`DecodeToMIDSysEx` are generic
  nibble transforms and `HTDevice::addSendMessage` queues an already-built
  message. Effect semantics are therefore in the AOT serializer/data path,
  not the native codec; remaining captures should validate that recovered
  path rather than duplicate metadata coverage.
- A headless Ghidra pass locates the AOT binding strings but cannot recover
  ordinary cross-references because the Flutter Dart AOT ELF uses generated
  snapshot code rather than conventional ELF functions. Recovering
  `writeParameter` now requires Dart AOT snapshot/loader support.
- The AOT string table additionally exposes `model150/alg_sequence_struct.dart`,
  `effect150_setting_slider.dart`, `getParameterTypes`, and `fxidList`.
  These corroborate structured parameter objects. AOTopsy now provides
  targeted snapshot recovery; its whole-project Dart decompiler remains
  unreliable, so raw assembly is used for the serializer and binding path.
- AOTopsy now parses the x86-64 Dart 3.5.0 snapshot and recovers
  `Module150Provider.getAlgsByModuleIdAndFxId`, `Device150DataProvider.switchAlgValue`,
  and `AlgParamValueStruct.toBytes`/`fromBytes`. The latter defines a
  32-byte typed record with magic `0x3033`, a 16-bit type field, a 32-bit
  identifier, float32 value, and two auxiliary bytes; `switchAlgValue`
  serializes it through `HTMidiDataProtocol.sendMessage`. This provides the
  first static bridge to the captured family-`0x18` parameter envelope.
- `reverse-engineering-history.md` now preserves the complete investigation
  history, including artifact analysis, transport findings, firmware updates,
  preset/NAM/IR work, effect captures, and AOTopsy recovery.
- USB routing/modes, Bluetooth routing/volume, and Global EQ position are
  deferred and recorded in `deferred-captures.md`; Global EQ position must not
  be confused with moving an EQ block in the preset chain.
- Effect coverage is now specified in `effect-capture-plan.md`, beginning with
  representative effects across all ten module groups, followed by complete
  `module_data.json` parameter coverage. Parameter-persistence capture was
  intentionally skipped because live parameter serialization is the current
  scope; preset-transfer work remains separate.
- The firmware capture now maps exactly 69,510 host family-`0x10` messages to
  1,986 page groups of 35 records (34×118 decoded bytes plus a 65-byte final
  record), for 8,096,922 decoded bytes. Header counters recover the
  intra-group packet index and a modulo-128 group counter.
- Group boundaries independently match the seven `analysisFile` regions after
  4 KiB ceiling: `b=0..1300`, `c=1301..1383`, `d=1384..1686`,
  `e=1687..1759`, `f=1760..1823`, `g=1824..1981`, `h=1982..1985`.
  The group counter skips two values at each region transition, coincident
  with extra family-`0x08` control replies.
- `tools/extract_sysex.py` now invokes tshark's
  `usbaudio.sysex.reassembled.data` field for every `usbcap/*.pcapng` file and
  emits JSONL records with capture, frame, endpoint/direction, family, length,
  raw bytes, transaction ID, transfer chunk header, and tshark reassembly
  metadata. The corpus run covered 205 captures (204 containing messages) and
  produced 6,790 messages in `sysex-corpus.jsonl` (4,076,278 bytes). Family
  counts are `0x00`: 2,410, `0x0c`: 1,295, `0x18`: 832, `0x24`: 614,
  `0x2c`: 406, `0x70`: 394, `0x14`: 212, `0x20`: 205, `0x10`: 122,
  `0x5c`: 102, `0x1c`: 72, `0x7c`: 50, `0x22`: 31, `0x30`: 18,
  `0x0f`: 16, `0x08`: 10, and `0x4c`: 1. Directions are 3,610
  host-to-device and 3,180 device-to-host. The extractor intentionally uses
  tshark's reassembled field; raw bulk-only firmware packets that Wireshark
  does not expose as `usbaudio` are not silently treated as reassembled
  messages.

## Next milestones

1. **Recover effect wire semantics**: trace the four
   `Effect150ModuleParameterItemWidget` callback closures and
   `Device150DataProvider.switchAlgValue` arguments to assign semantic names
   to the 32-byte `AlgParamValueStruct` fields. Correlate the identifier and
   auxiliary bytes with one known DLY, RVB, MOD, and enum capture each.
   Initial G-Chorus comparison rules out treating the nearby low-valued wire
   bytes as a direct `algId`; those bytes vary with the selected value and
   parameter kind.
   DLY/RVB selector captures do confirm that family `0x14` offset `12`
   carries the module-family byte (`0x0b`/`0x0c`), while offsets `33:35`
   carry a separate contextual local selector.
   `getAudioChannelByModuleIdAndFxId` confirms that the typed-record field at
   bytes `12:13` is the selected effect's `audioChannel`; the adjacent
   byte is the first integer context argument.
   `Alg.fromMap`/`toMap` confirms that `Alg+0x0f` is the direct metadata
   `algId`; `Alg+0x17` is `defaultValue`, avoiding a misleading field match
   in the widget closure.
   The widget constructor stores the selected `Alg` object at widget
   `+0x0f`, giving the callback trace a concrete path to the direct ID.
   The static pass now proves the metadata-side ID and audio-channel lookup,
   and the slider callback call site at `0x666588` is traced through the
   provider/context objects into record fields `+0x2f` and `+0x17`; the
   primitive wire IDs represented by those objects remain unresolved. Fresh
   DLY/RVB/VOL numeric captures are now available and confirm family `0x18`
   module byte `34`, variant selector `39:41`, and the shared float block
   `45:53`, resolving the previous capture gap.
2. **Normalize the effect schema**: extend `tools/effect_matrix.py` to emit a
   machine-readable schema containing module, variant, `fxid`, parameter
   `algId`, conversion/widget type, range or enum values, and confirmed wire
   field/encoding information. Keep unverified metadata-to-wire mappings
   explicitly marked as hypotheses.
   The generator now emits `effect-wire-schema.json`; its common family
   `0x18` layout is recorded with confidence metadata while the parameter
   discriminator remains pending.
3. **Validate mode-dependent parameters**: complete. The new captures cover
   G-Chorus and DLY synchronization, DLY A/B and dual sync controls, C-Chorus
   modes, Hammy WAH range/harmony, DST enum/toggle controls, AMP Bright/Char,
   N→S numeric controls, and second-variant CAB/EQ numeric controls.
4. **Build the capture corpus**: complete. `tools/extract_sysex.py` extracts
   every tshark-reassembled SysEx message with direction, capture name, frame,
   family, length, raw bytes, and transaction/chunk metadata. The generated
   JSONL corpus is `sysex-corpus.jsonl`; rerun with
   `python3 tools/extract_sysex.py usbcap -o sysex-corpus.jsonl`.
5. **Recover command boundaries**: compare native encoder/decoder call sites and
   message families to identify which regions use nibble encoding.
6. **Recover integrity fields**: validate the native CRC scope against all
   command families and identify any family-specific wrapper fields.
7. **Trace BMAN fields**: disassemble `getNamOutput` and
   `convert_nam_to_namb`; identify section sizes, integrity fields, and weight
   layout. The serializer entry point and primitive writers are now identified;
   exact field labels still require comparing multiple converted NAM outputs.
   The available native ARM64 image has been located for direct tracing.
8. **Decode patch transfers**: reconstruct `0x70` streams and compare them with
   `targets/001-New GEN.prst`.
9. **Decode asset transfers**: reconstruct `0x24` NAM and IR streams and compare
   them with the supplied `.nam` and `.wav` files. The transfer boundary and
   fixed converted sizes are confirmed; conversion field labeling remains.
10. **Trace IR conversion**: `getConvertNormalWav` is now identified as the
   source-WAV/resampling stage; trace `getCloneData` for normalization,
   quantization, and the fixed-output layout. Three 8,158-byte converted IR
   streams confirm a shared output size. The ARM64 `libapp.so` containing the
   conversion pipeline is available for this trace. `getCloneData` copies a
   fixed `0x2288` (8,840) bytes from its clone buffer and reports that
   capacity; it does not measure the USB payload. The captured IR transfer is
   independently 69×118 plus a final 16 decoded bytes, with an eight-byte
   transfer prefix, 1,348 signed big-endian 16-bit samples at record offset
   `0x28`, and zero padding. Only the native scratch-buffer relationship
   remains to be explained.
11. **Decode firmware update**: map family-`0x10`/outer transfer headers,
   region boundaries, payload expansion, and acknowledgements to the HTFW image.
   Native packet sizing, CRC scope, sequence counter, ACK polarity, and the
   complete 12-byte header layout and lifecycle command templates are
   characterized; page-group/region correlation and the family-`0x08`
   transition exchange are now documented. Remaining work is recovering the
   omitted 19-byte/page representation, identifying header bytes 5..6, plus
   error codes and final ACK/reboot behavior.
12. **Document a read-only protocol**: publish byte layouts and confidence levels
   before attempting writes or firmware operations.
13. **Standalone BMAN writer and file sender**: port the recovered native
   `convert_nam_to_namb` serializer (including tensor/count back-patching) and
   implement family-`0x24` chunk framing. The transport envelope is known, but
   this remains write-blocked until the complete BMAN field semantics and
   device ACK/lifecycle behavior are proven.

## Highest-value additional evidence

The most useful optional captures are a Suite patch export/import involving
`001-New GEN.prst`, a NAM import using the supplied `.nam`, and an IR import using
`Modern HIGH GAIN - Mix Ready.wav`. A successful firmware-update capture is not
required for the preset and asset protocol.
