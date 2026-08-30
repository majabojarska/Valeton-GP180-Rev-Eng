# USBPcap capture analysis

Analyzed 167 Wireshark/USBPcap captures in `usbcap/`, yielding 5,657 reassembled SysEx messages. Wireshark decodes the device as USB Audio/MIDI bulk transport on endpoint `0x03` (host to device) and `0x83` (device to host). SysEx is carried as USB MIDI Event Packets and must be reassembled before protocol decoding.

## Common packet framing

All observed messages use:

```text
F0 7F CC ... F7
```

where `CC` is a varying byte immediately after the universal SysEx manufacturer ID. The captures strongly suggest this is a checksum or integrity byte: it changes when the payload changes, while the following operation-family byte and transaction fields remain structured. This must be verified against a larger corpus before naming the algorithm.

The next byte identifies broad message families observed in the captures:

| Byte | Observed use |
|---:|---|
| `0x0C` | global/settings payloads |
| `0x0F` | preset selection/export request |
| `0x10` | parameter/preset edit payload |
| `0x14` | metronome/drums operation |
| `0x18` | parameter or preset-comp/rvb-mix operation |
| `0x20` | NAM/SnapTone rename or related slot operation |
| `0x24` | large file upload/download chunks |
| `0x5C` | device-to-host metronome/drums response |
| `0x70` | patch file upload/download chunks |
| `0x1C` | device-originated input/output and cab-mode status |
| `0x2C` | device-originated save-patch transfer |
| `0x30` | device-originated footswitch event/status |

These values are message families, not yet confirmed command IDs. Device replies generally contain a short ten-byte message with the same four-byte transaction identifier as the request, for example:

```text
F0 7F <reply-checksum> 06 00 00 00 <transaction-id> 00 F7
```

## Confirmed operation patterns

- Parameter edits (`noise-reduction-threshold`, compressor, reverb mix, and EQ enable) use short `0x18` or `0x10` requests followed by a ten-byte acknowledgement.
- Preset selection sends a `0x0F` request, receives an acknowledgement, then the device returns `0x14`, `0x18`, and/or `0x70` messages containing preset data. The capture includes host acknowledgements for those replies.
- Patch export sends a short `0x0F` request followed by an acknowledgement and multiple `0x70` messages from device to host.
- Patch import sends multiple `0x70` messages from host to device, followed by acknowledgements.
- NAM and IR imports use multiple `0x24` messages of 248 bytes each. The first eight bytes after the family byte contain a changing transaction/chunk structure; subsequent messages increment a chunk index. The final message is shorter or terminates with the same `F7` framing.
- NAM/SnapTone and IR slot renames use a single `0x20` request of 74 bytes followed by a ten-byte acknowledgement.
- Global EQ changes use `0x0C` messages, including a 248-byte first message and a shorter continuation message, followed by an acknowledgement.
- Metronome/drum start and style changes use a `0x14` request and a `0x5C` device response, followed by a short host acknowledgement.
- USB connection begins with ten-byte `0x00` handshake messages, then a device-identification exchange and longer preset/state reads.
- Captures prefixed `device-triggered-` were initiated by physical device controls, not by Suite commands. They show unsolicited device-to-host reports: parameter movements use repeated `0x18` messages, BPM changes use `0x14` messages with `0x5C` status responses, and footswitch A/B/C events use `0x30`.
- Device-side tuner activation produces a continuing status stream, including repeated `0x20` messages, rather than a one-shot Suite request/response.
- Device-side input/output and cab-mode changes use `0x1C`; device-side mode changes use `0x24`; device-side patch saving uses `0x2C` followed by a large device-to-host transfer.
- These device-originated transactions are acknowledged by the host with ten-byte family-`0x00` messages. This is distinct from Suite-initiated edits, where the host sends the substantive request and the device returns the acknowledgement.

## Important transport detail

USB MIDI Event Packet payloads are four bytes each: one cable/code byte followed by up to three MIDI bytes. A single USB transfer can therefore contain many packet fragments. The `usbaudio.sysex.reassembled.data` Wireshark field is the correct input for protocol analysis; raw USB transfer boundaries are not SysEx message boundaries.

## Windows Suite behavior inferred from captures

The Flutter AOT snapshot contains a dedicated protocol package rather than assembling raw MIDI inline:

- `package:ht_midi_data_protocol/src/core/protocol/receive/receive_assembler.dart`
- `handleSysexData`
- `encodeToMIDSysEx2`
- `decodeToMIDSysEx2`
- `partialSysExBuffer`

This matches the captures: the application receives arbitrary USB MIDI fragments, accumulates partial SysEx data, then decodes complete messages. The corresponding encoder is responsible for the transformed bytes seen after `F0 7F`; the first varying byte should therefore be investigated in `encodeToMIDSysEx2`/`decodeToMIDSysEx2`, not assumed to be a conventional checksum.

The transfer direction and family matrix also reveals that the Suite treats file operations as protocol transactions, not generic MIDI files:

- `0x24` is predominantly host-to-device for NAM/IR import.
- `0x70` is predominantly device-to-host for patch export, and host-to-device for patch import.
- Each large transfer is accompanied by a short acknowledgement transaction, allowing the Suite to retry or abort individual operations.
- The Suite explicitly warns that third-party IR, SnapTone, and NAM assets embedded in patch files are not imported/exported with the patch, indicating that patch payloads reference or omit external assets rather than embedding them blindly.

## Current limitations

The captures establish message families, transaction correlation, acknowledgements, and file-transfer chunking, but do not yet prove the checksum algorithm or the semantic layout of every payload field. Initial tests of simple 7-bit XOR and sum checksums over obvious payload ranges do not match the first post-manufacturer byte, so that byte should remain unnamed until the firmware/Suite checksum routine is traced. The next decoding step should:

1. Extract every reassembled message into a corpus with direction, filename, frame, length, family byte, transaction ID, and chunk index.
2. Compare messages differing by exactly one UI operation to isolate slot/index/value/name fields.
3. Test candidate checksum ranges and algorithms against the first byte after `F0 7F`.
4. Decode the `0x24` and `0x70` payload streams as separate file-transfer formats and compare their reconstructed bytes with the source patch/IR/NAM files.

## Firmware-upgrade capture check

`usbcap/firmware-upgrade-to-1.1.1.pcapng` contains 151,632 USB frames but only
98 messages recognized by Wireshark's `usbaudio.sysex.reassembled.data` field
over 579 seconds. That field is incomplete for this capture: the update stream
is carried as raw USB bulk payloads on endpoint `0x03`, which Wireshark leaves
under `usb` rather than reassembling as `usbaudio`.

Re-parsing the raw USB MIDI Event Packets finds 69,518 large host-to-device
SysEx messages between frames 91 and 151,629. Their family distribution is:

```text
0x10: 69,510 messages
0x24: 7 messages
0x4c: 1 message
```

Most are 248-byte wire messages, with 1,986 shorter final/continuation messages.
After removing the seven-byte transfer header and applying the native
hi-nibble/low-nibble decoder, the family-`0x10` stream is 8,096,922 bytes.
It contains firmware-related strings such as `GP-180`, `RMT_MIDI`, and
`Firmware`, and is clearly the previously missed update payload. It does not
contain the literal `HTFW` container header, so the updater is sending a
region/payload representation rather than the supplied firmware file verbatim.

The earlier conclusion that the capture contained no firmware update was
incorrect and has been corrected here. The remaining firmware task is to map
the per-message `0x10` headers and determine how the 8.1 MB decoded payload
corresponds to the seven HTFW regions and the 5.0 MB v1.1.1 image.

The decoded stream has now been checked against the firmware image rather than
only searched for signatures. Long exact byte runs from the v1.1.1 image occur
at multiple mapped positions in the update stream. For example, 32-byte
samples at firmware offsets `0x20000`, `0x50000`, `0xb0000`, `0x130000`,
`0x1d0000`, `0x270000`, `0x3e0000`, and `0x4c0000` all occur verbatim in the
decoded stream. The mapping is piecewise rather than one global offset:
additional bytes are inserted between region/page groups. This is consistent
with region headers, alignment/padding, and transfer metadata, and rules out
the stream being an unrelated preset synchronization burst.

The update stream therefore has three distinct layers:

```text
HTFW image region bytes
  -> update-region/page records and padding
  -> family-0x10 transfer headers
  -> nibble-encoded USB MIDI SysEx
```

The supplied capture is sufficient to recover the transmitted image payload,
and the page/group boundaries now correlate with all seven HTFW region records.
The remaining parser work is explaining the 19-byte/page difference and the
two unknown transfer-header nibbles. The device-to-host traffic during the
long host stream is sparse, so this capture does not independently expose a
negative per-page ACK, retry payload, or complete error-state machine.

The native firmware packet builder resolves the CRC scope. `getMidiMessage`
(`0x33cda4`) constructs an internal buffer whose first four bytes are:

```text
byte 0: zero placeholder, replaced by calcCRC
byte 1: command/family argument
byte 2: subcommand/sequence argument
byte 3: payload length
```

The payload is copied immediately after those four bytes. `calcCRC` is then
called over the complete `4 + payload_length` internal bytes, and the result is
stored at byte zero. Thus the CRC covers the logical packet header and payload,
not the USB framing or the `F7` terminator. The builder optionally passes this
buffer through `encodeToSysExPvl`, which emits high-nibble then low-nibble
values and is the native source of the encoded update payload.

`HTSubFirmware::pushMidiMessage` uses `getPackDataSize`: non-final packets have
an internal data size of `0x2a` (42), while final packets use `0x13` (19).
The call site supplies command byte `0xff`, the current transfer counter at
object offset `0x10`, the selected data slice, and the packet length. After
building the message, the counter is advanced by that packet length. The
source buffer is at object offset `0x20`, and the source cursor is at offset
`0x14`. Consequently, the logical update packet before outer USB/MIDI framing
is:

```text
CRC, 0xff, transfer_counter, packet_length, packet_data...
```

This establishes the updater's native packet sizing, sequence/counter field,
and CRC path; remaining firmware work is mapping the outer transfer-header
fields to region offsets and the final-packet case.

The ACK path is also partially resolved statically. `HTDevice::reciveACKData`
(`0x3337a8`) forwards acknowledgements to `HTFirmware::reciveACKData`
(`0x33747c`) while the device is in firmware-update state (`state == 2`).
The firmware handler decodes the received ACK body and examines its first
logical byte: zero clears the resend flag, while a nonzero value calls
`reSendMidiMessage`. For ordinary queued messages, a zero ACK advances the
message queue through `readyNextMessage`; a nonzero ACK sets the message state
to zero instead. This confirms the success/error polarity and retry entry
point, although the capture does not expose enough ACK traffic to enumerate
all error codes.

`HTSubFirmware::getHead` (`0x3358c8`) constructs a separate 12-byte outer
header before calling `getMidiMessage(1, 0, header, header_length, encode)`.
The header fields recovered directly from the stores are:

```text
byte 0      sub-firmware identifier (object + 0x03)
byte 1      zero
byte 2      0x11
byte 3      0x61
bytes 4..7  little-endian object field +0x18
bytes 8..11 little-endian object field +0x2c
```

The template bytes are not dynamic: `getAddrMessageData(0x61, 0x11)` writes
`0x11, 0x61` in that order. The constructor initializes the transfer counter
(`+0x10`), field `+0x18`, and source buffer/cursor (`+0x20`/`+0x14`) to zero;
`setFirm` copies the firmware-list metadata used to populate the sub-object.

The 32-bit fields are written explicitly byte-by-byte, so they are not
endianness artifacts from the host ABI. Object field `+0x2c` is also used by
`pushMidiMessage` as the total source limit, while `+0x14` is the source
cursor. This provides the first concrete outer-header relationship to the
captured page stream; the meanings of the two 32-bit values still need
confirmation against region transitions.

The `analysisFile` parser resolves those meanings. Each 16-byte firmware-list
record is read as four little-endian words:

```text
record +0x00: CRC16 of the region data
record +0x04: region metadata word (preserved in HTSubFirmware +0x04)
record +0x08: offset of region data from the decompressed data base
record +0x0c: region data length
```

The parser validates `CRC16(region_data)` before creating an
`HTSubFirmware`. It copies the region data into the sub-firmware source buffer,
sets `+0x2c` to the cumulative source length, and sets `+0x18` to the
ceiling of that length divided by the regular/final packet size. Therefore the
dynamic 12-byte data header is now exact:

```text
byte 0      sub-firmware identifier
byte 1      0
byte 2      0x11
byte 3      0x61
bytes 4..7  packet count, little-endian
bytes 8..11 source data length, little-endian
```

The parser also confirms that the on-disk HTFW payload may be decompressed
before records are read: the record table begins at decompressed offset
`0x38 + (header_byte_0x7b << 4)`, and each record's `+0x08` offset is relative
to that same decompressed data base. This explains why the update transfer
does not contain the literal physical HTFW container layout.

The updater lifecycle command templates are now visible in the same code:

| Method | `getAddrMessageData` arguments | Resulting fixed bytes |
|---|---|---|
| `sendStart` (`0x3367bc`) | `(0x60, 0x11)` | `11 60` |
| `getHead` (`0x3358c8`) | `(0x61, 0x11)` | `11 61` |
| `sendSubEnd` (`0x336af8`) | `(0x6e, 0x11)` | `11 6e` |
| `sendAllEnd` (`0x336e24`) | `(0x6e, 0x11)` | `11 6e` |
| `sendJump` (`0x337c18`) | `(0x6f, 0x11)` | `11 6f` |

`sendStart` sends its command through `getMidiMessage(1, 0, ...)` and sets
update state `1`. `sendSubEnd` selects the current firmware-list entry and
appends that entry's byte at offset `+3` of the command body, providing a
per-region completion marker. `sendAllEnd` sends the same `11 6e` template
after calculating aggregate checksums over the firmware-list entries. This
confirms distinct start, per-region-end, and all-regions-end stages even though
the capture does not expose their complete ACK exchange.

`checkSumFirmware` (`0x338270`) is not the CRC-8 routine. It copies the
specified bytes and computes an 8-bit wrapping sum equivalent to:

```text
checksum = (sum(input bytes) + input length) & 0xff
```

The SIMD implementation subtracts the bitwise complement of the accumulator,
which is equivalent to adding each byte and one. `sendAllEnd` uses aggregate
values from firmware-list entries (including fields at entry offsets `+0x10`
and `+0x18`) in its final callback/command preparation. `sendJump` is a
separate post-update command using the fixed `11 6f` template.

## Firmware capture record mapping

The raw USB-MIDI reassembly can now be mapped to the firmware-list lengths
without relying on Wireshark's incomplete `usbaudio` reassembly. The
host-to-device family-`0x10` data stream runs from frame 91 through frame
151115 and contains exactly 69,510 messages. Every logical page/group has 35
messages:

```text
34 regular messages: 248-byte SysEx, 236 nibble bytes, 118 decoded bytes
 1 final message:    142-byte SysEx, 130 nibble bytes,  65 decoded bytes
per-group decoded payload: 4,077 bytes
```

There are 1,986 such groups, so the decoded family-`0x10` payload is exactly
`1,986 × 4,077 = 8,096,922` bytes. This is a record structure, not merely an
arbitrary concatenation of 118-byte chunks. The seven bytes between the
family byte and the nibble-coded body are stable enough to recover the
intra-group counters:

```text
header[0] = 0x20
header[1..2] = (119 × packet_index), split into 7-bit little-endian bytes
header[3] = group counter, normally incremented modulo 128
header[4] = packet_index, 0..34
header[5..6] = two 4-bit values whose meaning is not yet identified
```

The `119 × packet_index` rule and `packet_index` field hold for all 69,510
records. The group counter advances by one within a region, wraps from `0x7f`
to `0x00`, and advances by three at each region transition. The six `+3`
jumps occur exactly at the boundaries implied by the seven parsed
HTFW regions; two intervening counter values are absent from the
family-`0x10` payload stream, consistent with control traffic or omitted
records. This is a capture correlation, not proof that the skipped values
identify a particular command.

The page/group ranges inferred from the declared region lengths are:

| Region | Group range (zero-based) | Groups |
|---|---:|---:|
| `b` | `0..1300` | 1,301 |
| `c` | `1301..1383` | 83 |
| `d` | `1384..1686` | 303 |
| `e` | `1687..1759` | 73 |
| `f` | `1760..1823` | 64 |
| `g` | `1824..1981` | 158 |
| `h` | `1982..1985` | 4 |

These are the ceilings of the cumulative region lengths divided by 4,096,
so the grouping is independently predicted by `analysisFile`, rather than
chosen from the observed counter values. A padded 4,096-byte page would be
19 bytes larger than the 4,077-byte family-`0x10` payload. The numerical
coincidence with the native final packet size (`0x13`) is notable, but the
capture does not establish whether those 19 bytes are padding, metadata
represented by another message, or source bytes omitted by the payload-only
extraction.

Device traffic confirms a page-level control exchange. Family-`0x08`
messages are 26-byte status/reply records and are followed by host
family-`0x00` acknowledgements of the form
`F0 7F <crc> 00 00 00 <sequence> 00 F7`. Two additional family-`0x08`
records appear at each of the six region transitions, with distinct payload
type fields.
The regular family-`0x08` sequence also wraps without emitting sequence
value zero (`0x7f` is followed by `0x01`). This matches the native ACK
dispatcher: the host ACK body has a zero result byte, while a nonzero result
would select the resend path. The capture contains no negative ACK, so no
error-code table or retry payload can be recovered.

This mapping explains the earlier piecewise image matches: the transfer is
organized as region-aligned page records, with control records at region
boundaries, rather than as one global offset into the physical HTFW file.
It still does not recover the decompressed bytes for every region or prove
the semantic role of `header[5..6]`; writes, retries, and final reboot
behavior remain unverified.

The v1.1.1 image header provides the expected seven region records despite its
different packing from the GP50 layout. Their declared update-region lengths
are:

| ID | Load address | Declared length |
|---|---:|---:|
| `b` | `0x00038000` | `0x00514f4c` (5,328,716) |
| `c` | `0x00740000` | `0x00053000` (339,968) |
| `d` | `0x00800000` | `0x0012e3f0` (1,238,000) |
| `e` | `0x009c0000` | `0x00049000` (299,008) |
| `f` | `0x00a80000` | `0x00040000` (262,144) |
| `g` | `0x00000000` | `0x0009df7c` (647,036) |
| `h` | `0x00000000` | `0x00003fc0` (16,320) |

These lengths sum to `8,131,192`, close to the `8,096,922` bytes recovered
from family `0x10`; the difference is consistent with update framing,
alignment, and records not included in the family-`0x10` payload-only stream.
This resolves the apparent contradiction between the 5,036,421-byte container
and the roughly 8.1 MB update transfer: the container stores packed/expanded
region metadata whose declared update payload is larger than the physical
download file.

The official GP-180 MIDI control PDF has been reviewed and its CC/Program Change
mapping is now incorporated into `analysis-manifest.md` and the device-triggered
capture interpretation.

## Suite control metadata

The extracted Flutter asset `module_data.json` contains the Suite's editable
GP-180 effect model, not only display text. It defines 10 module groups, 209
effect entries, and 825 algorithm/parameter entries. Each parameter record
contains a symbolic name, algorithm ID, default value, minimum, maximum, step,
widget type, and display conversion rule.

| Module ID | Group | Effects | Parameters |
|---:|---|---:|---:|
| 0 | `NR` | 1 | 1 |
| 1 | `PRE` | 10 | 36 |
| 2 | `DST` | 10 | 28 |
| 3 | `AMP` | 32 | 181 |
| 4 | `CAB` | 40 | 40 |
| 5 | `EQ` | 5 | 29 |
| 6 | `MOD` | 11 | 31 |
| 7 | `DLY` | 10 | 45 |
| 8 | `RVB` | 10 | 34 |
| 9 | `N→S` | 80 | 400 |

This is the authoritative Suite-side parameter vocabulary and range source
for a control specification. The remaining correlation is mapping each
`fxid`/`algId` pair to the corresponding GP-180 preset/SysEx parameter byte;
the asset itself does not contain that transport mapping.

The native outbound queue entry point is
`HTDevice::addSendMessage(unsigned char, Array<unsigned char>&, unsigned char)`
(`0x332b3c`). It copies the caller's byte array into an `HTMessage`, preserves
the supplied family byte, and enables ACK waiting when the family is not
`0x30` and the device ACK-mode flag is set. Pending messages are compared
before insertion to suppress duplicates, and accepted entries receive a
monotonically increasing queue sequence number. This localizes the remaining
control-spec gap to the callers that construct family-specific arrays; the
native queue itself handles ACK/retry scheduling and duplicate suppression.

## Drum and metronome controls

The extracted `gp5D.json` asset contains 14 drum-pattern groups with 129
entries total, including six metronome patterns. Each entry provides a file name,
display name, time signature, and default tempo. The group counts are:

```text
Ambient 6       Breakbeat 10   Country 7   Dance 7
Drum&Bass 9     Funk 8         Jazz 10     Latin 5
Metal 10        Metronome 6    Pop 13      R&B 4
Rock 24         Trip hop 10
```

The native Android library exposes the corresponding drum engine operations:
`setBpm/getBpm`, `setVelocity/getVelocity`, `setTranspose`, loop control,
play/pause/stop, track mute, and separate accompaniment playback controls.
These are Suite playback/preview controls; the GP-180 device MIDI control
surface separately exposes drum controls on CC `92`–`96`, with tempo on
CC `73`/`74`. The asset and native drum engine do not encode the device CC
mapping, so the CC meanings remain capture/PDF-derived rather than inferred
from the app's local playback implementation.

## Firmware comparison and GP50 reference

The newly added `targets/GP-180 Firmware V1.0.0.bin` makes version comparison possible. Both images use the same `HTFW` container family, model identifier, region IDs (`b` through `h`), and load-address map used by the GP50 research. However, the v1.1.1 header's payload-size field is inconsistent with the physical file size and its region lengths appear to describe a different packing scheme; the GP50 parser must not be applied blindly. The v1.0.0 image has the expected 0xA8 payload base and internally consistent region lengths.

Version-specific strings are informative:

- v1.0.0 contains verbose MIDI diagnostics: `RMT_MIDI`, `DataRmtCmdMidiInit Ok`, `midi write read fail, no init`, and `midi write malloc fail`. It also exposes explicit `MIDI IN/EXP`, `MIDI OUT/FS`, `Footswitch MIDI`, `EXP/FS/MIDI`, and `User IR 1` through `User IR 20` labels.
- v1.1.1 is much more stripped/packed, retaining `RmtCmdMidi`, `midi write r`, `NAM Slot %d`, `Firmware Version`, and `User IR`.

The GP50 `re/` reference changes the recommended approach. Its strongest result is not static decompilation but a proven wire codec: CRC-8 polynomial `0x07`, zero initialization, hi-first nibble expansion, `F0..F7` framing, and a reassembly-first capture workflow. GP50 captures also show that the first pre-nibble byte is a CRC. The GP-180 messages do not visibly use that same nibble-expanded representation—the captured bytes after `F0 7F` include values above `0x0F`—so the GP50 codec is a hypothesis to test, not a direct decoder. The next implementation should port the GP50 CRC/reassembly probes and compare both raw and transformed GP-180 messages against them before pursuing a custom Ghidra processor.

## Native codec result

The Android v2.1.0 ARM64 library provides a direct implementation of the CRC:
`calcCRC(unsigned char *, unsigned int)` initializes the accumulator to zero,
XORs each input byte, and indexes a 256-byte table at `0x15115c1`. This is the
same table-driven CRC-8 shape used by the GP50 tooling, but the GP-180 call-site
input range still needs to be established.

`DecodeToMIDSysEx` confirms a two-byte-per-byte transformation: it combines
adjacent source values as `(first << 4) | second`, with optimized 32-byte and
8-byte loops. It also validates output capacity and rejects malformed/odd input.
The capture representation therefore includes a protocol/header portion that
must be separated from the nibble-coded region before applying this decoder;
feeding the complete Wireshark reassembled message directly is incorrect.

## Supplied NAM, IR, and preset transfer captures

The new captures establish the transfer boundary for the large file messages.
For full-size `0x24` and `0x70` chunks, bytes `F0 7F <CRC> <family>` are
followed by a seven-byte transfer header; nibble-coded data begins at byte
offset `0x0B` in the reassembled SysEx and ends before `F7`. Each 248-byte
message therefore carries 118 decoded bytes. The first chunk has the same
fixed boundary, with its initial transfer-header values differing from later
chunk indices.

The NAM import contains 70 full chunks and reconstructs 8,158 decoded bytes.
Its decoded stream begins:

```text
2c20200101901050101c200100000050101c205052534d20415243204c44204761696e
424d414e010000002c1f0000f00100004f0700009d010000...
```

The `BMAN` marker and compact binary metadata prove that the Suite converts the
294 KB JSON `.nam` source into a device-specific binary representation before
transmission. The transmitted stream is not the source JSON and is not simply
the WAV/NAM file compressed as-is. The IR import similarly reconstructs 8,158
bytes and begins with slot/name metadata followed by binary model data; it does
not contain the WAV RIFF header.

The Android native library exposes the conversion pipeline directly. The
`namConverterCloData` implementation calls `getNamOutput` for NAM input,
`getConvertNormalWav` for WAV input, and `getCloneData` to produce the final
device data. The relevant native symbols are:

```text
getNamOutput       0x29af80
getConvertNormalWav 0x2938d8
getCloneData       0x29e2cc
```

The library also contains the actual JSON-to-BMAN serializer:

```text
convert_nam_to_namb 0x2a0a58
BinaryWriter::write_u32 0x2a0f78
BinaryWriter::write_u16 0x2a1054
BinaryWriter::write_f32 0x2a74e4
BinaryWriter::write_f64 0x2aa348
```

Its first writes are unambiguous: little-endian magic `0x4e414d42`
(`BMAN`), version `uint16 = 1`, reserved `uint16 = 0`, followed by
zero-initialized `uint32` header placeholders. It then writes model metadata,
arrays, and weights using explicit `u16`, `u32`, and `f32` writer methods,
before filling size/count fields. This explains why the captured header has
multiple size-like values that cannot be interpreted independently without
following the later back-patching code.

This separates conversion from transport: `0x24` only carries the output of
these converters. The BMAN header begins at stream offset `0x23` with:

```text
42 4d 41 4e 01
```

(`BMAN`, version 1). The preceding bytes contain the slot/name and command
metadata. The first visible BMAN fields include a back-patched header/data
length value of `0x2c`, several little-endian size/count values, and a
four-byte nonzero integrity-related value. The serializer confirms these are
generated metadata rather than arbitrary obfuscation. Exact field names still
require following the back-patching stores or comparing a second conversion.

The supplied NAM is canonical NeuralAmpModelerCore format version 0.7.0:
Core 0.4.1 is the first version documented as fully supporting that version.
Its `SlimmableContainer`/WaveNet structure is therefore standard NAM input;
`BMAN` is the GP-180 conversion output, not a new NAM file-version variant.

## Additional IR conversion captures

Three additional IR imports were decoded:

| Source | Messages | Decoded transfer |
|---|---:|---:|
| `VOX AC30 BLUE 1.wav` | 70 full `0x24` chunks | 8,158 bytes |
| `TWIN REVERB __ MIDS.wav` | 70 full `0x24` chunks | 8,158 bytes |
| `Ampeg 8x10 57 A107.wav` | 70 full `0x24` chunks | 8,158 bytes |

All three streams use the same fixed-size converted representation and carry
the slot/name metadata followed by binary audio data. The names appear in the
decoded prefix (`VOX AC30 BLUE`, `TWIN REVER`, and `Ampeg 8x10`), while the
original RIFF headers do not. Their differing waveform regions demonstrate
that the Suite conversion is deterministic in structure but content-dependent
in the audio section. This strongly supports tracing `getConvertNormalWav`
as the remaining route to an exact IR codec; the USB/SysEx layer itself is
already identical across the samples.

Static tracing of `getConvertNormalWav(const char *, double, int, int)` shows
that it is a normal JUCE WAV conversion stage, not the final GP-180 packer. It:

1. Opens the source through `WavAudioFormat`.
2. Allocates a floating-point `AudioBuffer`.
3. Reads the source samples.
4. Calls `convertSampleRate(AudioBuffer<float> *, float source, float target)`.
5. Writes a temporary WAV using the requested target sample rate, channel count,
   and bit depth.

The final fixed 8,158-byte device representation is therefore produced later
by `getCloneData`, after this temporary WAV exists. The IR specification now
needs `getCloneData` tracing; source WAV conversion and SysEx transport are
separate stages.

## Complete Suite page and control inventory

The AOT snapshot contains the following functional page groups beyond the
global-settings subpages. This is an application-surface inventory; controls
listed here are confirmed by page/model names and user-facing strings, while
their exact device payloads remain subject to protocol correlation.

| Page group | Extracted functionality |
|---|---|
| Connect / device initialization | USB-MIDI device scan/connect/disconnect, device availability/state, firmware/device identification, and connection error handling. |
| Edit | Effect-chain editing, module reorder/drag, module bypass, algorithm/effect selection, parameter knobs/sliders, value display conversion, quick knobs, and expression assignment. |
| Manage patches | Patch/preset list, slot selection, load/save, rename, delete, import, export, backup, and preset metadata/details. |
| Manage IR | User-IR list, slot selection, import/export, rename, delete, and IR metadata. |
| Manage NAM / clones | NAM import, clone list, clone rename/delete, clone metadata, and transfer progress. The GP-180-side converted representation is the documented BMAN path. |
| Manage SnapTone / Tone Capture | SnapTone import/delete and Tone Capture import/delete workflows, including file validation and progress reporting. |
| Drum / metronome | Drum style/category selection, pattern selection, BPM, volume, drum on/off, tap/drum sync, and local MIDI-file playback. |
| Tuner | Tuner view and tuner state/image widget, with device tuner data handled separately from local drum playback. |
| Looper | Looper view/state for the supported device variant. |
| Global settings | Input/output, USB, Global EQ, tap, footswitch, Bluetooth, auto-save, display, and EXP/FS/MIDI controls documented above. |
| Firmware update | Online update discovery, firmware metadata/version display, download, validation, update progress, and device-update lifecycle handling. |
| About / software settings | About Valeton, general/software settings, version updates, language selection, release notes, and application update dialogs. |
| File/dialog infrastructure | Shared import/export, save, rename, delete, reset, progress, update, and failure/success dialogs used by the functional pages. |

The page tree also contains separate `150`/`300` device variants for drum,
IR, patch, tuner, display, USB, footswitch, MIDI, and EXP widgets. This
indicates feature differences are selected by device model rather than being
independent protocol families. The principal device-control surfaces are the
Edit, Global Settings, Drum/Tuner/Looper, and Manage pages; the remaining
pages are connection, maintenance, or file-management workflows.

## Device Global Settings subpages

The Flutter AOT snapshot contains separate widgets/models for all nine
requested subpages. Their native/Dart model field names provide a reliable
control vocabulary, although they do not by themselves prove the encoded
SysEx byte offsets. The extracted functionality is:

| Subpage | Controls recovered from the Suite |
|---|---|
| Input / Output | Input gain, microphone/input level, left/right input mode, output mode, and left/right input/output channel selection. |
| USB Settings | USB mode for left/right paths, USB monitor volume, USB recording volume, USB reverse-charge option, and USB channel routing (`USB1/2`, `USB3/4`, `USB5/6`, `USB7/8`). |
| GLOBAL EQ | Global EQ enable/position and four bands, each with frequency, gain, Q, and band enable state (`band1` through `band4`). |
| TAP Settings | Tap-tempo synchronization for delay, modulation, pre-effects, and drums (`dlyTapSync`, `modTapSync`, `preTapSync`, `drumSync`), plus global tempo behavior. |
| Footswitch | Footswitch mode and switch assignments; the 180-specific widget is separate from the larger-device footswitch/MIDI widget. |
| BT Settings | Bluetooth audio volume, Bluetooth recording volume, and Bluetooth routing/control modes (`BT Only`, `BT Controlled`, `BT And PD`). Bluetooth radio enable/disable is device-local and produces no observed USB/MIDI traffic. |
| Auto Save | Automatic-save state and the Suite’s auto-function handling for device changes. |
| Display | Brightness/light level and display timeout (`displayLight`, `displayTime`). `displayLanguage` and `displayMode` are Suite/UI fields, not confirmed GP-180 device controls. |
| EXP/FS/MIDI | EXP1/EXP2 mode and A/B selection, expression calibration/control ranges, footswitch MIDI assignments, MIDI input source/channel, MIDI output channels, and MIDI clock source/output for DIN, USB, and Bluetooth. |

The corresponding model/update entry points are
`setGlobalParamsInOutput`, `setGlobalParamsUsbSetting`,
`setGlobalParamsEQSetting`, `setGlobalParamsGeneral`,
`setGlobalParamsMidiSetting`, `setFootSwitchMidi`, and `updateExpCtrl`.
The native queue accepts these as family-specific messages through
`HTDevice::addSendMessage`; the exact payload layouts still require caller
tracing and capture correlation. The field names and subpage boundaries are
Suite-confirmed, while the transport mapping remains unverified.

The native library exports only the generic queue boundary for these settings;
the global-setting methods are Dart/AOT-side wrappers and do not appear as
separate native C++ entry points. Static inspection therefore identifies the
models and their fields but cannot recover the byte arrays passed to
`addSendMessage` without decoding Dart call sites or collecting one capture per
control. This is an important boundary: names such as `inputGain`,
`usbMonitorVol`, `band1Freq`, and `midiClockOutUSB` are semantic fields, not
wire-level offsets.

### Confirmed Global EQ toggle evidence

The controlled capture
`usbcap/settings-global-eq-off-on-off-on.pcapng` provides one direct
wire-level mapping. Its four long family-`0x0c` state messages are identical
except for transaction metadata and the byte at zero-based message offset
`0x22` (decimal 34), which follows the capture sequence `0, 1, 0, 1` for
EQ off/on/off/on. Thus:

```text
SysEx message offset 0x22 = Global EQ enable state (0=off, 1=on)
```

This identifies the enable flag only; the four-band frequency/gain/Q fields
and Global EQ position still need independent value-changing captures.

## Capture plan for unresolved controls

All captures should use the GP-180, the same firmware version, and a fresh
Suite connection. Save one capture per row, begin with a read/state refresh,
change only the named value once, wait for the acknowledgement/state report,
restore the original value, and capture the restore transaction too. Record
the before/after UI values, slot/preset, firmware version, MIDI endpoints, and
whether the action was made in Suite or on the hardware. Do not combine rows
in one capture.

| Capture | Exact scope | Expected evidence |
|---|---|---|
| `global-eq-bands` | Change each Global EQ band one at a time: band 1–4 frequency, gain, and Q; toggle each band enable state; move EQ position through every available location. | Family `0x0c` request/state deltas for each field, with the known EQ-enable byte at offset `0x22` excluded from the band-field comparison. |
| `input-output-levels` | Change input gain, microphone/input level, left and right input mode, and output mode individually; exercise each discrete option and two interior numeric values. | Family `0x0c`/`0x1c` request and acknowledgement/state mapping for input/output fields. |
| `usb-routing` | Change left/right USB mode, monitor volume, recording volume, reverse-charge, and each USB pair route (`1/2`, `3/4`, `5/6`, `7/8`) individually. | USB-setting payload fields, discrete enumerations, and volume scaling. |
| `tap-sync` | Toggle delay, modulation, pre-effect, and drum sync independently; change global tempo at two values with sync both off and on. | Tap/general-setting payloads and relationship between tempo and synchronized modules. |
| `footswitch-mode` | Cycle every Footswitch Mode option; assign each available FS A/B/C action to a different function; test short press, long press, and hold where exposed. | Footswitch assignment structure and family `0x30`/settings messages; separate physical event reports from configuration writes. |
| `exp-controls` | For EXP1 and EXP2 independently, select every mode/A-B option, calibrate minimum/maximum, and change expression target/range/step. | EXP configuration payloads, calibration limits, and target identifiers. |
| `midi-routing` | Change MIDI input source among DIN/USB/Bluetooth, set each input/output channel to low/middle/high values, and toggle clock source/output for DIN, USB, and MIDI-related paths. | MIDI setting fields, channel numbering, clock routing, and ACK behavior. |
| `bluetooth-settings` | Change audio volume and recording volume, and exercise `BT Only`, `BT Controlled`, and `BT And PD` modes. Bluetooth enable/disable is excluded because it is device-local and produces no observed USB/MIDI traffic. | Bluetooth-setting writes and any device response distinct from host connection traffic. |
| `display-settings` | Change language, brightness/light, display mode, and display timeout independently; test minimum, default, and maximum timeout/light values. | Display/general-setting payload fields and value scaling. |
| `auto-save` | Toggle Auto Save; change any Auto Function option independently; edit a preset with Auto Save off and on without manually saving. | Save timing, general-setting write, and whether automatic save emits `0x2c`/preset traffic. |
| `drum-controls` | Select two metronome styles and two drum styles; change BPM, volume, drum on/off, loop, velocity, transpose, track mute, and play/pause/stop independently. | Family `0x14` requests, family `0x5c` responses, and separation of local Suite playback from device controls. |
| `tuner` | Enter and leave tuner, sustain notes while changing tuner input/mute-related options, and record the complete status stream. | Tuner state/report messages, refresh cadence, and host acknowledgements. |
| `parameter-controls` | For one effect in each module group, change bypass, algorithm, and one parameter at minimum/midpoint/maximum; repeat with a second effect where algorithms differ. | `fxid`/`algId` to transport-byte mapping and parameter encoding/range behavior. |
| `preset-operations` | Select adjacent and non-adjacent preset slots; rename, save, export, and import using disposable slots. | Slot identifiers, `0x0f`, `0x2c`, `0x70`, name encoding, and save acknowledgements. |
| `nam-ir-operations` | Import one NAM and one IR into disposable slots; load, rename, export, delete, and restore each. | Complete `0x24`/rename/delete envelopes and correlation with BMAN/IR converted data. |
| `firmware-lifecycle` | Use an already captured update only; isolate start, header, each region transition, final end, jump, ACK, retry, and reboot timing from raw USB. Do not initiate another update solely for this. | Remaining 19-byte/page overhead, dynamic header bytes, retry/error codes, final commit and reboot behavior. |
| `device-identity` | Capture fresh connect/handshake for GP-180 and, if available, GP-300; include USB descriptors and all initial state reads. | Model IDs, subdevice IDs, capability flags, and model-specific page/protocol selection. |

For quantitative controls, use at least three non-default values and include
the exact displayed value. For enumerations, capture every option. The most
valuable first batch is `global-eq-bands`, `input-output-levels`,
`usb-routing`, `exp-controls`, and `midi-routing`; these close the largest
remaining gap between the Suite page inventory and a usable control protocol.

## New controlled capture corpus

The expanded corpus now contains 167 captures. TShark exposes 5,657 complete
reassembled SysEx messages. `no-op-baseline.pcapng` contains no SysEx traffic,
confirming that the following deltas are action-related rather than idle
traffic. Offsets below are relative to the message body immediately after
`F0 7F <CRC>`; the corresponding wire offset is body offset plus three.

### Global settings mappings

| Control | Family | Body offset | Captured mapping |
|---|---:|---:|---|
| Global EQ enable | `0x0c` | `31` | `0↔1` |
| Global EQ band 1 frequency/gain/Q | `0x0c` | `110–133` | Separate packed fields; captures end at 6048 Hz, −4 dB, and Q 4.7. |
| Global EQ band 2 frequency/gain/Q | `0x0c` | `142–165` | Separate packed fields; captures end at 2364 Hz, −15 dB, and Q 8.9. |
| Global EQ band 3 frequency/gain/Q | `0x0c` | `174–197` | Separate packed fields; captures end at 20 Hz, 20 dB, and Q 0.1. |
| Global EQ band 4 frequency/Q | `0x0c` | `206–221` | Separate packed fields; captures end at 4436 Hz and Q 10. |
| Global EQ high/low cut | `0x0c` | `32–61` | High-cut and low-cut packed fields; captures end at 18324 Hz and 20 kHz. |
| Global EQ level | `0x0c` | `42–49` | Complete packed float32 field; device capture confirms 24, 25, 26, 27. |
| Input level | `0x1c` | `30–33` | +14 dB → −9 dB. |
| MIC level | `0x1c` | `46–47` | 26 → 82. |
| MIC monitor | `0x1c` | `51` | `1→0`. |
| MIC phones TRRS/TRS | `0x1c` | `55` | `1→0`. |
| No-CAB left/right | `0x1c` | `39`, `43` | Each independently `1→0`. |
| Output R mono/stereo | `0x1c` | `35` | `0→1`. |
| BT REC level | `0x1c` | `34–37` | −13 dB → 9 dB. |
| MIC REC level | `0x1c` | `38–41` | −10 dB → 16 dB. |
| REC mode / REC mode R | `0x1c` | `43`, `47` | Dry/wet `0→1`. |
| USB monitor/record level | `0x1c` | `50–53`, `30–33` | Packed level fields. |
| USB power option | `0x1c` | `57` | Reverse → charge (`1→0`). |
| BT audio volume | `0x24` | `64–65` | 19 → 74. |
| Auto CAB Match | `0x24` | `71` | `1→0`. |
| Display timeout | `0x24` | `35` | 5 min → 30 min → Always = `0→1→2`. |
| Display brightness | `0x24` | `31` | I → II → III = `0→1→2`. |
| Tap PRE/MOD/DLY | `0x24` | `55`, `57`, `59` | Each independently `1→0`. |
| Auto Save | `0x24` | `75` | `0→1`. |

The EQ band, cut, and level fields are packed/nibble-coded portions of the
long state packet. Their byte ranges are confirmed, but their conversion to
engineering units still needs the command-specific decoder.

### MIDI and EXP/FS mappings

| Control | Family | Body offset | Captured mapping |
|---|---:|---:|---|
| MIDI clock source | `0x22` | `59` | `0→1→2→3→4→0`. |
| MIDI clock output | `0x22` | `63` | `1→0`. |
| MIDI input source | `0x22` | `31` | TRS/USB/BT/Mixed = `0→1→2→3`. |
| MIDI input channel TRS/USB/BT | `0x22` | `35`, `39`, `43` | Captured channel changes and Omni (`0`). |
| MIDI output channel TRS/USB/BT | `0x22` | `47`, `51`, `55` | Captured channel changes and Omni (`0`). |
| Cloud Out USB | `0x22` | `67` | `1→0`. |
| EXP MIDI-IN mode | `0x24` | `47` | EXP → MIDI-IN = `1→0`. |
| External FS mode | `0x24` | `49` | Single/Dual/MIDI OUT = `1→2→0`. |
| External FS-1 assignment | `0x24` | `50–51` | Combobox sweep enumerates `0x00` through `0x0f`. |
| External FS-2 assignment | `0x24` | `52–53` | Patch plus/minus assignment changes `0100→0001`. |
| Footswitch mode | `0x24` | `43` | Patch/Stomp = `0→1`. |
| EXP target 1 WAH/DST | `0x7c` | `31` | `1→2`. |

The MIDI settings use family `0x22` and 78-byte SysEx messages; the EXP/FS
global widgets use family `0x24` 82-byte messages, while EXP target selection
uses family `0x7c`.

### Fresh NR/PRE effect captures

Later NR and PRE captures confirm that numeric family-`0x18` writes use full
SysEx offsets `45:53` (eight nibble bytes). Reconstruct adjacent nibbles into
four bytes, then interpret them with the observed 16-bit word-swapped float
order:

```python
b = [(n[0] << 4) | n[1], (n[2] << 4) | n[3],
     (n[4] << 4) | n[5], (n[6] << 4) | n[7]]
value = struct.unpack(">f", bytes([b[1], b[0], b[3], b[2]]))[0]
```

This decodes NR threshold, attack, hold, ratio and PRE COMP4/OD-9 controls to
their displayed values with only sub-unit quantization error. NR release is a
special split field: concatenate full offsets `45:49` and `41:45` before
decoding. The state bytes at offsets `11:15` vary with effect state and are not
the direct numeric value.

NR variant selection uses family `0x14`, with the variant code at full offsets
`33:35`: `None=0x03`, `Gate_1=0x1b`, `Gate_2=0x1d`, and `Gate_3=0x21`.
PRE variant captures provide:

```text
None=03  COMP=00  COMP4=01  Micro_Boost=14  B_Boost=0b
14_Boost=0e  Boost=1a  OD_9=01  Yellow_OD=02  Penesas=14
Super_OD=06  Blues_OD=09
T_Wah=0f  A_WAH=15  Step_Filter=19  OCTA=21  Pitch=23
PP_Bend=24  Hammy=49  Ring_Mod=2f  Saturate=33  AC_Sim=01
H_to_S=02  S_to_H=07
```

The selector is not globally unique across PRE subfamilies; the surrounding
state marker at full offsets `40:42` distinguishes the relevant variant
family. COMP4 uses discriminator bytes Sustain=`00`, Attack=`01`, Volume=`02`,
Clip=`03`; OD-9 uses Gain=`00`, Tone=`01`, Volume=`02`.

NR toggle is family `0x10`, full offset `36`, with `00=off` and `01=on`.
The new AMP captures use the same family-`0x18` `45:53` block, confirming a
shared live numeric-edit envelope even though selectors and surrounding state
vary by effect.

### New DST, CAB, and WAH captures

The additional effect captures extend the mapping beyond NR/PRE/AMP. Variant
selection remains a family-`0x14` operation; the selector is the two-byte
nibble-coded value at full offsets `33:35`. These values are contextual rather
than globally unique, so the module/effect state in the surrounding fields must
be retained when decoding them.

| Module | Captured variants and selector bytes (`33:35`) |
|---|---|
| DST | Green OD=`0000`, OD-9=`0001`, Yellow OD=`0002`, Super OD=`0006`, Scream OD=`0008`, Blues OD=`0009`, Force=`000a`, Tube Clipper=`000b`, TaiChi OD=`0100`, Lazaro=`0202`, Red Haze=`0204`, Plustortion=`0209`, SM Dist=`020a`, Darktale=`020b`, Chief=`020d`, La Charger=`0300`, Flagman Dist=`0502`, Flex OD=`030f`, Bass OD=`0400`, Black Bass=`0404`, Bass Hammer=`0501`, Micro Boost=`0104`, B Boost=`000b`, 14 Boost=`000e`, Boost=`010a`, None=`0003` |
| PRE | Existing PRE selector coverage is confirmed in the same format, including COMP, COMP4, OD-9, boost, wah/filter, pitch, modulation, and amp/speaker variants. |
| WAH | V Wah=`0001`, C Wah=`0008`, B Wah=`0007`, Hammy=`0409`, None=`0003` |

DST parameter captures cover Gain, Volume, Lo-mid, Treble, Blend, Low,
Hi-mid, and the Attack/Cut/Boost/Flat selector set. Additional focused
captures cover Boost Bright and +3 dB toggles, Flagman Dist Tight, and Fuzz
Fuzz/Volume. CAB captures cover Juice 4x12 Volume, High Cut, Low Cut, and
Precision (High/Regular). WAH captures cover V-Wah Range, Q, Volume, and
Position. All numeric edits use family `0x18` requests with the shared full
offset `45:53` nibble block; the neighboring effect-state bytes change with
the selected algorithm and parameter, so a universal parameter discriminator
has not been asserted from these captures alone. DST, WAH, and CAB bypass
captures use the existing family `0x10` module-enable field at full offset
`36` (`01=on`, `00=off`).

### Extrapolating effect schemas from Suite metadata

The captures can be generalized with the extracted `module_data.json`, but
only in two separate layers:

1. The Suite metadata supplies the complete vocabulary and likely logical
   schema: `moduleId`, `fxid`, algorithm/parameter `algId`, value range, step,
   default, and display-conversion `code`. For most modules, `fxid` is a
   packed 32-bit identifier whose high byte identifies the module family and
   whose low 24 bits identify the effect variant (for example, DST values
   begin with `0x03`, AMP with `0x07`, and CAB with `0x0a`). NR/PRE include
   legacy/smaller IDs and must not be forced into that pattern.
2. The wire captures supply the transport schema: family `0x14` selects an
   algorithm, family `0x10` toggles a module, and family `0x18` writes a
   numeric parameter through the common `45:53` block. The changing
   effect-state bytes around the block are the remaining candidates for the
   packed effect/algorithm/parameter identity, but their exact assignment
   needs correlation against `fxid` and `algId`; it cannot be safely inferred
   from parameter values alone.

This is sufficient to generate an offline catalog of all 209 effects and 825
parameters, including valid ranges, enum choices, units, and expected display
conversion. A reliable encoder still needs a small calibration set per
algorithm to map each metadata `algId` to the family-`0x18` state bytes. The
current DST/CAB/WAH captures provide that calibration set for their selected
variants and show that the numeric representation is shared, while conversion
from UI percentages or milliseconds to the stored value remains
effect-specific.

### New EQ and MOD captures

The new EQ captures confirm the same three-operation pattern used by the other
modules:

| Operation | Family and field | Result |
|---|---|---|
| EQ variant selection | `0x14`, full offsets `33:35` | Guitar EQ 1=`0305`, Guitar EQ 2=`0306`, Bass EQ 1=`0309`, Mess EQ=`030c`, None=`0003`. |
| EQ bypass | `0x10`, full offset `36` | `01=on`, `00=off`; the module selector is `0007` in the captured request. |
| Guitar EQ 1 numeric edits | `0x18`, full offsets `45:53` | The same shared numeric block carries the five band gains and Volume; all band gains use the metadata `-50~0~+50` range and Volume uses `0~100`. |

The MOD selector sweep similarly maps G-Chorus=`0001`, C-Chorus=`0002`,
B-Chorus=`0008`, Jet=`0101`, B-Jet=`0102`, V-Roto=`0105`,
Vibrato=`0107`, O-Phase=`0109`, Vibe=`0200`, O-Trem=`0201`,
Sine Trem=`0206`, Triangle Trem=`0207`, Bias Trem=`0208`,
Detune=`0209`, Auto Swell=`020d`, Hold=`020f`, Freeze=`0300`, and
None=`0003` at full offsets `33:35`.

G-Chorus rate requires a mode-aware decoder. With Sync off, the captured
values `2.60`, `6.50`, `7.40`, `0.10`, and `10.00` are free-running Hz and
use the metadata `0.10Hz-10.00Hz` rate conversion. With Sync on, the rate
control becomes a subdivision selector: `1/1`, `1/2`, dotted `1/2D`,
triplet `1/2T`, `1/4`, dotted `1/4D`, and `1/16` are not Hz values. They
must be decoded as enum/timing codes and converted to a delay/modulation
period from the current BPM. The capture also shows Sync and Rate as
separate family-`0x18` writes; the shared value block is therefore not
interpretable without the synchronized-mode state.

The G-Chorus captures cover Depth and Volume in the ordinary `0~100` range,
free-running Rate in Hz, synchronized Rate subdivisions, and the Sync
toggle. This establishes the pattern to apply to other MOD algorithms:
`ValToStr_034` is conditional on sync state, while ordinary depth/level
controls use the generic percentage conversion.

The full UI-side variant matrix is generated in
`effect-variant-matrix.md`. It uses the richer `module150_data.json` asset,
which contains 348 variants and 1,701 parameters, including the recently
observed DLY/RVB/MOD/WAH variants. It records each variant's `fxid`, parameter
`algId`, continuous range or enum set, and capture evidence. This asset is
shared Suite data and must still be filtered by model capability before
treating every entry as GP-180-supported. Filename matching is intentionally
conservative, so shorthand differences such as `VOL` versus `Volume` may
appear as missing and should be manually reconciled before capturing.

The AOT snapshot contains explicit binding/lookup methods including
`getFxIdByModuleIdAndTypeName`, `getAlgsByModuleIdAndFxId`,
`getEffectNameByModuleIdAndTypeNameAndFxId`, `parseParameters`, and
`writeParameter`. This confirms a structured UI-to-effect binding layer
rather than display-name-only dispatch. Static analysis of `writeParameter`
and its callers is the next step for recovering how `moduleId`, `fxid`,
`algId`, widget type, and converted value become family-`0x14`/`0x18` fields.

The native ARM64 implementation narrows the boundary: `EncodeToMIDSysEx` and
`DecodeToMIDSysEx` only transform bytes to and from high/low nibbles, while
`HTDevice::addSendMessage` accepts an already-constructed message plus a
one-byte queue/command selector. Neither native routine contains effect
variant or parameter semantics. Those semantics therefore live in the AOT
binding/serialization layer (or in data tables consumed by it), not in the
generic native codec. This confirms that static AOT tracing is the correct
route, while firmware comparison remains useful for validating the resulting
compact wire IDs and range enforcement.

### New DLY and RVB variant inventories

The latest captures reveal that the device/Suite exposes more DLY and RVB
variants than are present in the extracted `module_data.json`. Their selector
values are therefore recorded here as capture-derived additions:

| Module | Captured variant selector sequence (`0x14`, full `33:35`) |
|---|---|
| DLY | BBD Delay S=`010d`, Digital Delay S=`010f`, Pure=`0000`, Tape=`0002`, Ping Pong=`0004`, Slapback=`0005`, Sweep Echo=`0006`, Ring Echo=`0009`, Tube=`000b`, Sweet Echo=`000d`, 999 Echo=`0102`, Vintage Rack=`0104`, Rev Echo=`0208`, Dual Echo=`0003`, None=`0003` |
| RVB | Room=`0000`, Hall=`0001`, Church=`0002`, Plate=`0003`, Spring=`0004`, Tube Spring=`0102`, Concert=`000d`, N-Star=`0006`, Deepsea=`0007`, Sweet Space=`0008`, Shimmer=`0009`, None=`0003` |

The repeated `0003` selector is contextual: Plate/Dual Echo and None are
distinguished by surrounding effect-state bytes and/or the preceding module
state, so selector bytes alone are not a global variant ID. DLY None bypass
uses module selector `0009`; RVB bypass uses `000a`, with family `0x10` full
offset `36` carrying `01=on` and `00=off`.

These captures select the variants but do not yet parameter-sweep them. The
UI metadata predicts the following parameter families where available:
DLY generally exposes Mix, Time, Feedback, and Trail, with Ring Echo and
Sweep Echo adding modulation-specific controls; RVB generally exposes Mix,
Decay, and Trail, with Air/Plate/Sweet Space adding Damp/Mod controls. Every
newly observed variant should still be captured once for its exact parameter
subset because model filtering and variant-specific layouts are not proven
from the shared metadata alone.

### Patch, effect, reset, and device-originated mappings

| Control | Family | Body offset | Captured mapping |
|---|---:|---:|---|
| Module enable | `0x10` | `33` | `0↔1`; selector is commonly body `31`. |
| AMP/CAB/EQ enable | `0x10` | `33` | Same module-enable field across modules. |
| AMP/effect packed parameter | `0x18` | `42–45` | AMP gain, tone, EQ, and bright controls occupy this range. |
| Patch selection index | `0x0f` | `31` | Changes with requested slot sequence; final index convention unresolved. |
| Factory reset selector | `0x10` | `31` | All user data=`02`; factory patches=`01`; global settings=`00`. |
| EXP target assignment | `0x7c` | `31` | WAH=`01`, DST=`02` in the captured target-1 change. |
| Footswitch A/B/C patch assignment | `0x30` | `39`, `46`, `49`, `57` | Assignment-specific changes confirmed; event reports remain otherwise similar. |

Preset selection uses 40-byte family-`0x0f` messages. Slot rename uses
family `0x20`, with the slot at body `31` and high/low-nibble ASCII name data
starting at body `38`. Patch imports/exports remain family `0x70`; NAM/IR
transfers remain family `0x24`.

### Device-triggered evidence

- BPM changes use family `0x14`, with the BPM field at body `30–31`;
  corresponding family `0x5c` state reports mirror the change.
- Device preset-volume changes use family `0x5c`, changing body `34–35`.
- Device gain changes use family `0x18`, changing the packed body `42–45`
  parameter field.
- Drum on/off uses family `0x14`, body `43`.
- Physical module toggles use family `0x10`, with module selector body `31`
  and enable body `33`.
- Device mode switching uses family `0x24`, body `43`.
- Footswitch A/B/C event messages are family `0x30` and 106 bytes; their
  payloads are byte-identical apart from transaction/per-message fields, so
  the physical A/B/C identity is not encoded in the observed event body.
- Tuner activation produces a continuing family-`0x20`/`0x70` stream rather
  than a single isolated toggle.

The expanded captures close most of the previously proposed first-priority
mapping batch. Remaining high-value work is decoding packed numeric
representations, correlating all effect IDs/algorithms, and reconstructing the
full preset/global-state schemas.

### Packed Global EQ values solved

The five follow-up captures deliberately dwell for at least two seconds at
each filename value, allowing stable state packets to be separated from the
fast knob sweep. Each numeric field uses eight nibble bytes that reconstruct a
little-endian IEEE-754 `float32`:

```text
nibbles[0:8] -> four reconstructed bytes -> struct.unpack("<f", bytes)
```

Offsets below are full reassembled SysEx offsets; subtract eight to obtain the
offset after the protocol prefix.

| Control | Full SysEx field | After prefix | Confirmed decoded values |
|---|---:|---:|---|
| Low-cut frequency | `57:65` | `49:57` | 1047.85, 4914.70, 4489.26, 4791.21, 12919.96, 7501.89 Hz. |
| High-cut frequency | `35:43` | `27:35` | 7628.27, 3971.42, 20.00, 368.82, 2594.10, 10762.84 Hz. |
| Band 4 frequency | `209:217` | `201:209` | 20.00, 17988.32, 18625.44, 20000.00, 8433.00, 6844.96, 2539.94 Hz. |
| Band 4 Q | `217:225` | `209:217` | 0.1000, 2.3663, 5.7096, 9.0721, 9.3849, 10.0000. |
| Band 4 gain | `225:233` | `217:225` | 3.2703, −17.8619, −20.00, 18.8362, 20.00, 1.7605 dB. |

The Suite labels are rounded/quantized, so the stored float does not always
equal the displayed value (for example, displayed Q 2.4 is stored as 2.3663).
Field locations and float reconstruction are high-confidence; the remaining
task is recovering the Suite display quantization formula.

### Latest device-triggered captures

The subsequent device-triggered captures add the following mappings:

| Operation | Family and field | Result |
|---|---|---|
| Global EQ level | `0x0c`, full offsets `45:53` | Nibble-coded little-endian float32; device values 24, 25, 26, 27 decode exactly. |
| Drum volume | `0x14`, full offset `38` | UI values 79, 78, 77, 76 encode as nibbles `0f`, `0e`, `0d`, `0c`. |
| Metronome time signature | `0x14`, full offsets `11:13` and `44` | 4/4, 5/4, 6/4, 6/8, 7/4 map to encoded states `0x01`–`0x05` at offset 44; offsets 11:13 carry the packed state. |
| Drum tap tempo | `0x14` and mirrored `0x5c`, full offsets `33:35` | 122, 272, 187 BPM encode as `02 0c`, `07 0a`, `01 00`. |
| Drum on/off | `0x14`, full offset `46` | `01` on, `00` off. |
| Auto Save | `0x24`, full offset `78` | `01` on, `00` off; an intermediate `0x10` packet is status traffic. |
| Preset chain reorder | `0x18`, full offsets `36,38,...,56` | An 11-byte permutation array encodes module order; AMP, NR, and RVB moves are now confirmed. |

Preset manual-save captures confirm that the name is nibble-encoded in the
family-`0x1c` metadata packet beginning at full offset 33, and appears twice
in the reconstructed family-`0x2c` transfer. The complete save transfer is 34
chunks with replay/retry traffic; the direct numeric preset-slot field still
needs isolation.

Tuner template captures show family-`0x20` 74-byte device reports. The
normalized template state advances through `06 0e`, `06 0c`, ..., `07 0e`,
`07 0c` while full offset 42 advances from `00` through `09`. The sequence
marker is confirmed, but the final two template labels remain ambiguous
because of initialization/state-report ordering.

The four new AMP captures confirm family-`0x18` 58-byte live parameter writes.
The parameter block is full offsets `45:53`; offsets 11:12 also vary as part
of serialized effect state. This confirms the field location but does not yet
provide a universal percent-to-wire conversion.

### Remaining captures to collect

The following controls are not yet isolated by the new corpus. Each should be
recorded as a separate Suite-triggered capture using the one-variable-at-a-time
workflow above, with a restore action where safe:

| Priority | Capture scope |
|---|---|
| P1 | Global EQ band 4 gain; Global EQ position; repeat one band with several known values to solve packed frequency/gain/Q conversion; high-cut and low-cut with two additional values. |
| P1 | USB left/right mode and all USB pair routing options (`USB1/2`, `3/4`, `5/6`, `7/8`); isolate any remaining USB input/output source selectors. |
| P1 | No further display-language or generic display-mode capture is required; only brightness and timeout are confirmed device controls. |
| P1 | Bluetooth recording-volume control and each BT routing/control mode (`BT Only`, `BT Controlled`, `BT And PD`). Bluetooth enable/disable is device-local and does not generate USB/MIDI traffic. |
| P1 | MIDI clock output for USB and any remaining DIN/MIC clock outputs; capture each clock-source option with its displayed label. |
| P1 | EXP1 and EXP2 mode/A-B selection, expression calibration minimum/maximum, and target/range changes. |
| P1 | Tap drum synchronization and any remaining tap-sync target; change global tempo with each sync combination. |
| P2 | Global footswitch assignment options not covered by Patch/Stomp mode and external FS assignment sweeps; include long-press/hold actions if exposed. |
| P2 | Auto Function options and an edit with Auto Save off/on to establish whether automatic saving emits additional `0x2c`/preset traffic. |
| P2 | Drum Suite controls: pattern/style selection, volume, velocity, transpose, loop, mute, pause/resume, and stop; separate local-preview actions from device commands. |
| P2 | Tuner entry/exit with a complete sustained-note status stream and any exposed tuner mute/input options. |
| P2 | One parameter at minimum/midpoint/maximum for every effect/module group, including algorithm changes, to map `fxid`/`algId` and numeric conversion beyond AMP. |
| P2 | Preset schema: select a known patch, change one field, save, reload, export, and compare the corresponding `0x70`/`0x2c` state. Repeat for module order, bypass, quick knobs, EXP assignment, and footswitch assignment. |
| P3 | NAM/IR load/rename/delete/export round trips using disposable slots to complete slot metadata and operation envelopes. |
| P3 | GP-180 versus GP-300 identity/capability captures, if a GP-300 is available: USB descriptors, handshake, initial state read, and one setting from each model-specific page. |

Do not repeat the firmware update unless a recovery-capable test setup is
available; the existing update capture is sufficient for static lifecycle
analysis. The most valuable next captures are the P1 rows because they close
the remaining global-settings protocol gaps rather than adding more UI
inventory.

The Foxy Clean preset import and export each contain ten full `0x70` chunks and
reconstruct 1,126 decoded bytes. The supplied `.prst` is 1,128 bytes. Export
payload data aligns with the source beginning after a seven-byte transfer header;
import data has an additional command-side prefix and differs in slot/name
fields. This demonstrates that the transfer stream is a framed representation
of the preset rather than a byte-for-byte copy of the disk file, while still
retaining long exact matching regions.

## Cross-platform Suite findings

The Android APKs expose the native protocol library much more clearly than the
stripped Windows DLL. Both Android versions contain an arm64 `lib5868USB.so` with
exported C++ symbols for:

- `EncodeToMIDSysEx` and `DecodeToMIDSysEx`
- `calcCRC`
- `HTFirmware::reciveACKData` and `HTFirmware::reciveMidiData`
- `HTSubFirmware::pushMidiMessage`, `readyForNext`, `getHead`, and `isSendOver`
- `HTDevice::handleIncomingMidiMessage` and `startUpdateFirmware`
- `getFirmwareHeader` and firmware-info/version helpers

This establishes an explicit native encoder/decoder and a stateful firmware-update
sequence with per-sub-firmware readiness/completion handling. The Android v2.0.4
and v2.1.0 symbol sets are effectively the same, so this transport is shared
across those releases rather than being Dart-only. Android v2.1.0 additionally
contains explicit `ht_midi_data_protocol` firmware-update and CRC utility paths in
its Dart snapshot.

The APKs contain ARM64 native libraries (and ARMv7 libraries in v2.0.4), making
Android the best next Ghidra target: symbols can be analyzed directly on ARM
without recovering Dart AOT control flow. The macOS packages should next be
expanded to locate their corresponding `5868USB` dylib and compare symbols.

The macOS v2.1.0 package has now been expanded. Its universal
`Contents/Frameworks/5868USB.dylib` contains the same RTTI/class names as the
Android library, including `HTDevice`, `HTFirmware`, `HTMIDIManager`, and
`handleIncomingMidiMessage`, plus CoreMIDI integration (`MIDIEventListAdd`,
`MIDIInputPortCreate`, and related APIs). This independently confirms that the
protocol implementation is shared across desktop and mobile platforms; only the
MIDI backend changes (WinMM on Windows, CoreMIDI on macOS, JUCE/native MIDI on
Android).

The highest-value next static-analysis target is therefore the Android
`lib5868USB.so`, where the exported `EncodeToMIDSysEx`, `DecodeToMIDSysEx`, and
`calcCRC` symbols are directly available. The macOS dylib is useful for
cross-checking class structure and native backend behavior but is less
convenient for symbol-level analysis because those functions are not exported
under their readable names.
