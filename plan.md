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
- USB routing/modes, Bluetooth routing/volume, and Global EQ position are
  deferred and recorded in `deferred-captures.md`; Global EQ position must not
  be confused with moving an EQ block in the preset chain.
- Effect coverage is now specified in `effect-capture-plan.md`, beginning with
  representative effects across all ten module groups, followed by complete
  `module_data.json` parameter coverage and separate preset-persistence tests.
- The firmware capture now maps exactly 69,510 host family-`0x10` messages to
  1,986 page groups of 35 records (34×118 decoded bytes plus a 65-byte final
  record), for 8,096,922 decoded bytes. Header counters recover the
  intra-group packet index and a modulo-128 group counter.
- Group boundaries independently match the seven `analysisFile` regions after
  4 KiB ceiling: `b=0..1300`, `c=1301..1383`, `d=1384..1686`,
  `e=1687..1759`, `f=1760..1823`, `g=1824..1981`, `h=1982..1985`.
  The group counter skips two values at each region transition, coincident
  with extra family-`0x08` control replies.

## Next milestones

1. **Build the capture corpus**: extract every reassembled SysEx message with
   direction, capture name, family, length, and transaction/chunk identifiers.
2. **Recover command boundaries**: compare native encoder/decoder call sites and
   message families to identify which regions use nibble encoding.
3. **Recover integrity fields**: validate the native CRC scope against all
   command families and identify any family-specific wrapper fields.
4. **Trace BMAN fields**: disassemble `getNamOutput` and
   `convert_nam_to_namb`; identify section sizes, integrity fields, and weight
   layout. The serializer entry point and primitive writers are now identified.
5. **Decode patch transfers**: reconstruct `0x70` streams and compare them with
   `targets/001-New GEN.prst`.
6. **Decode asset transfers**: reconstruct `0x24` NAM and IR streams and compare
   them with the supplied `.nam` and `.wav` files.
7. **Trace IR conversion**: `getConvertNormalWav` is now identified as the
   source-WAV/resampling stage; trace `getCloneData` for normalization,
   quantization, and the fixed-output layout.
8. **Decode firmware update**: map family-`0x10`/outer transfer headers,
   region boundaries, payload expansion, and acknowledgements to the HTFW image.
   Native packet sizing, CRC scope, sequence counter, ACK polarity, and the
   complete 12-byte header layout and lifecycle command templates are
   characterized; page-group/region correlation and the family-`0x08`
   transition exchange are now documented. Remaining work is recovering the
   omitted 19-byte/page representation, identifying header bytes 5..6, plus
   error codes and final ACK/reboot behavior.
9. **Document a read-only protocol**: publish byte layouts and confidence levels
   before attempting writes or firmware operations.

## Highest-value additional evidence

The most useful optional captures are a Suite patch export/import involving
`001-New GEN.prst`, a NAM import using the supplied `.nam`, and an IR import using
`Modern HIGH GAIN - Mix Ready.wav`. A successful firmware-update capture is not
required for the preset and asset protocol.
