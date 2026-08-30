# Effect-parameter capture plan

## Goal

Map effect/module controls from Suite UI fields to family, command, payload
offset, encoding, and engineering-unit conversion. The existing
`module_data.json` vocabulary contains 209 effects and 825 parameters across
ten module groups; captures should establish the transport mapping without
mixing preset state changes or unrelated UI refreshes.

## Controlled setup

1. Use one known disposable preset and record its name/slot and firmware
   version.
2. Start a fresh capture after the Suite finishes its initial state refresh.
3. Change only one effect or one parameter at a time.
4. For numeric parameters, dwell at the requested value for at least two
   seconds, then restore the original value and dwell again.
5. For switches and enumerations, hold each option for at least two seconds.
6. Do not save the preset during parameter captures; save operations belong in
   the separate preset-schema campaign.
7. Name captures with the exact module, effect, parameter, and displayed
   values, for example:

```text
suite-triggered-effect-AMP-AC_Pre-Gain-sequence-21-50-77-unit-percent.pcapng
```

## Phase 1: representative effects

Capture one representative effect from each module group:

| Group | Representative scope |
|---|---|
| NR | Threshold and release/decay controls, if exposed. |
| PRE | One distortion/overdrive and one wah/pre-effect with algorithm selection. |
| DST | One distortion effect with bypass and all visible parameters. |
| AMP | Gain, volume, bass, middle, treble, presence, bright, and AMP EQ controls. |
| CAB | Cabinet selection, microphone/position controls, level, and bypass. |
| EQ | Band frequency, gain, Q, cut filters, and bypass. |
| MOD | One modulation effect with rate, depth, mix, and sync. |
| DLY | Delay time, feedback, mix, tap-sync, and subdivisions. |
| RVB | Decay/time, tone, pre-delay, mix, and bypass. |
| N→S | One NAM/SnapTone effect with model selection, level, and bypass. |

For each representative effect, collect:

- bypass off/on;
- every visible numeric parameter at minimum, midpoint, and maximum;
- two interior values where the display is nonlinear or quantized;
- every algorithm/effect selection in the effect dropdown;
- any parameter whose widget is a switch, enum, time, frequency, or percentage.

## Phase 2: complete parameter coverage

After the representative layouts are decoded, cover every effect in
`module_data.json`:

1. Select the effect without changing any parameter.
2. Capture its algorithm/effect identifier and initial state.
3. Change each parameter at minimum/midpoint/maximum.
4. Repeat only for parameters with a distinct widget type or conversion rule
   when the same transport encoding has already been proven.
5. Capture effects with duplicate parameter names separately; their `fxid` and
   `algId` may differ.

## Phase 3: preset integration

Using separate captures, verify that effect edits persist through:

- preset save and reload;
- module reorder;
- module bypass;
- quick-knob assignment;
- EXP target assignment;
- footswitch assignment.

These captures must be separate from the parameter-value captures so preset
serialization and live parameter messages can be distinguished.

## Analysis output per capture

For each operation, record:

- direction and family;
- complete SysEx length;
- transaction/checksum fields;
- effect/module selector;
- parameter selector;
- raw value bytes;
- decoded value and displayed UI value;
- ACK/state response;
- confidence and whether the value is live-only or persisted.

The existing AMP captures already show family `0x18` parameter traffic
concentrated around body offsets `42–45`. The first objective is to determine
whether other module groups reuse that schema or introduce group-specific
selectors and encodings.

