# Deferred USBPcap captures

These captures are intentionally postponed. They are not evidence that the
features do not exist; they are scopes that are ambiguous, device-local, or
lower priority than effect-parameter mapping.

## USB routing/modes

Deferred because the Suite labels and GP-180 device behavior are not yet clear
enough to define a controlled operation. Do not capture until the exact UI
control and its available options are identified.

## Bluetooth routing/volume

Deferred for now. Bluetooth radio enable/disable is device-local and produces
no observed USB/MIDI traffic. Bluetooth audio/recording volume and routing
options may still be captured later if their wire-level behavior becomes
necessary.

## Global EQ position

Deferred pending UI clarification. This refers to the Global EQ page's
`setGlobalEqPosition` setting, if exposed by the GP-180 UI; it is distinct from
dragging an EQ effect within a preset signal chain. Do not conflate it with the
device-triggered signal-chain reorder captures.

## Display language and generic display mode

Skipped. The GP-180 does not expose display-language control through the
device, and the Suite `displayMode` field has not been established as a
GP-180 wire-level setting.

