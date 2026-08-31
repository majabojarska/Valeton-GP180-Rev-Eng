# Analysis manifest

## Inputs

| Artifact                                             | SHA-256                                                            | Initial classification                                               |
| ---------------------------------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------- |
| `targets/GP-180 Firmware V1.1.1.bin`                 | `e6512040f1a3b7c61a9bbdb32e39adc0dd504c0ea8804ad145a775304653060a` | 5,036,421-byte proprietary `TFW` container; header contains `GP-180` |
| `targets/GP-180 Firmware V1.0.0.bin`                 | `cd4df59bc8fba15f793656645f06342c1734a5435f33b7542fb448dcd4df49ae` | 8,470,664-byte proprietary `TFW` container                           |
| `targets/Valeton Suite Setup V2.1.0 for Windows.exe` | `bd9d345bf0c7abeb6256d3aab075ccc56a4096f0282784cf558c9b44c36ff8b0` | 32-bit x86 NSIS 3.10 installer                                       |

Additional Suite targets are now present:

- Windows v2.0.3 ZIP containing an NSIS installer.
- macOS v2.0.3 and v2.1.0 ZIPs containing `.pkg` installers.
- Android v2.0.4 and v2.1.0 ZIPs containing APKs.
- No iOS/IPA artifact is currently present in `targets/`.

Additional protocol/reference artifacts:

- `targets/001-New GEN.prst` (1,128 bytes): GP-180 preset export, visibly different from the 552-byte GP50 format.
- `targets/PRSM ARC LD Gain BAL2 CAB-MRAK.nam` (294,251 bytes): JSON NAM v0.7 SlimmableContainer.
- `1763963558701.Valeton Suite.ipa`: iOS/iPadOS Flutter app; it contains `flutter_midi_command.framework` but no `5868USB` native library in the IPA listing.
- GP-180 MIDI and Effect List PDFs provide the official CC map and model/effect names.

The official GP-180 MIDI list maps the device-triggered controls to ordinary MIDI
CC messages: patch selection uses CC0 plus Program Change, module toggles use
CC48-59, tuner is CC60, CTRL A/B/C are CC69-71, tempo uses CC73/74, and drum
controls use CC92-96. This explains why physical-device captures produce
unsolicited SysEx state reports while external controllers can use simpler CC/PC
messages. The GP-150 list is nearly identical but lacks GP-180 CTRL C (CC71) and
has minor looper-placement wording differences.

## Extracted Suite components

The installer was extracted into the session workspace under `files/suite-extracted/` (112 MiB, 710 files). The application is Flutter:

- `data/app.so`: stripped x86-64 Dart AOT snapshot containing protocol/UI strings and package paths.
- `assets/5868USB.dll`: PE32+ x86-64 native USB/MIDI library; imports WinMM MIDI input/output APIs and contains firmware helpers.
- `data/flutter_assets/assets/data/module_data.json`, `module50_data.json`, and `module150_data.json`: effect/model metadata.

## Static protocol evidence

- `5868USB.dll` imports `midiOutLongMsg`, `midiInPrepareHeader`, `midiInAddBuffer`, and related open/close functions, confirming WinMM long-message transport.
- The native module contains MIDI queue/receive paths: `addSendMessage`, `handleIncomingMidiMessage`, and `reSendMidiMessage`.
- Firmware helpers include `HTFirmware`, `FirmwareFileType`, `isRealFirmware`, and `isRealFirmwareWithDeviceName`.
- The Dart snapshot exposes `HTFirmwareHead`, `FirmwareParseResult`, `_checkCrcFirmware`, `checkCrcFirmware2`, and `sendUpdateFirmwareStop`.
- The Suite identifies the device port as `Valeton GP-180 MIDI`.
- Firmware text includes `RmtCmdMidi`, `Firmware Version`, `NAM Slot %d`, and `User IR`.
- Signature scanning did not find an embedded ELF/ZIP/7z image. The `TFW` container needs format inference from header fields and Suite-side parser code.

## Confidence and blockers

The transport layer and relevant Suite components are identified with high confidence. Exact command IDs, SysEx header bytes, payload layouts, chunking, and checksum algorithms remain partly unconfirmed. The second firmware image enables version comparison, while cross-platform Suite comparison may expose shared Dart protocol logic. Write operations should not be implemented from static evidence alone.
