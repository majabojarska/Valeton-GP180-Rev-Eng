# Valeton GP180 Reverse Engineering

## Goals

- Reverse engineer the SysEx protocol of the Valeton GP180 guitar multi-effects processor.
- Build a platform-agnostic web application (PWA), to manage presets, firmware updates, IR/NAM loading, and settings for the GP180. The application will leverage the [WebMIDI API](https://developer.mozilla.org/en-US/docs/Web/API/Web_MIDI_API) to communicate with the device over MIDI.

### Nice-to-haves

- Preset snapshots into git 

## Non-goals

- Modification of the GP180 firmware or hardware, although hardware extension modules may be considered in the future.

## Starting points

Possibly useful prior works:

- [Valeton GP5/GP50 web companion](https://github.com/drewmerc302/valeton-gp50/tree/master)
  - If GP5/GP50 use the same/similar SysEx protocol, this could solve a major part of SysEx reverse engineering for the GP150/GP180.
- [GP150 preset format analysis](https://gist.githubusercontent.com/AlbertoBarba/ec59feecba60ca956eeb6970f0ac0055/raw/445a6b275e0e542b29754f8a3bc09249ca81df8a/GP150_PRST_FORMAT.md)
- [gp200-studio, a browser-based editor for the Valeton GP200](https://github.com/kabir0st/gp200-studio)
  - This is roughly what I want to achieve for the GP180, with the added features of IR/NAM loading and firmware updates.
  - Sets the precedent for [reverse engineering a Valeton SysEx protocol with Ghidra](https://github.com/kabir0st/gp200-studio/tree/PRODUCTION/re/ghidra).

Firmware to analyze (Ghidra):

- [GP180 Firmware v1.0.0](https://www.valetoneffects.com/downloads/GP180_Firmware_v1.0.0.zip)
- [GP180 Firmware v1.1.1](https://www.valeton.net/download/246/gp-180/24231/gp-180-firmware-v1-1-1-zip%ef%bc%88compatible-with-computer-software-v2-1-0-and-mobile-software-v2-1-0%ef%bc%89.zip)

Software to analyze (Ghidra):

- [Valeton Suite v2.1.0 for Windows](https://www.valeton.net/download/254/win/24238/valeton-suite-setup-v2-1-0-for-windows-zip-3.zip)
  - First one to support native NAM A2 lite loading.
- [Valeton Suite v2.0.3 for Windows](https://www.valeton.net/download/254/win/23068/valeton-suite-setup-v2-0-3-for-windows-zip-2.zip)
- [Valeton Suite v2.1.0 for Mac](https://www.valeton.net/download/255/mac/24239/valeton-suite-setup-v2-1-0-for-mac-zip-3.zip)
  - First one to support native NAM A2 lite loading.
- [Valeton Suite v2.0.3 for Mac](https://www.valeton.net/download/255/mac/23069/valeton-suite-setup-v2-0-3-for-mac-zip-2.zip)

Forum threads with useful context:

- [The Gear Forum - GP50,GP150,GP180 discussion](https://thegearforum.com/threads/valeton-gp-50-gp-150-and-gp-180.10093/)
  - All released around Oct 2025, hinting they all share some common design and possibly SysEx protocol.

## Unknowns

- Is the GP5/GP50/GP150/GP180 series SysEx-compatible with the GP200?

## Knowns

- GP-200 presents are explicitly not compatible with GP50/150/180.
