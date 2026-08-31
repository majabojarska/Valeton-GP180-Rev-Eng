#!/usr/bin/env python3
"""Low-level GP-180 SysEx framing helpers recovered from Valeton Suite."""

from __future__ import annotations

from typing import Iterable


def crc8(data: Iterable[int]) -> int:
    """Native calcCRC table, equivalent to CRC-8 polynomial 0x07."""
    value = 0
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (
                ((value << 1) ^ 0x07) & 0xFF if value & 0x80 else (value << 1) & 0xFF
            )
    return value


def crc16_native(data: Iterable[int], *, skip: int = 0) -> int:
    """Native ``checkCrc`` CRC-16/ARC variant, initialized to ``0xffff``.

    The Windows DLL uses the reflected 0xa001 polynomial and compares the
    resulting bytes in table order (low byte first), so the returned integer
    is the byte-swapped representation used by that routine.
    """
    crc = 0xFFFF
    for byte in list(data)[skip:]:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return ((crc & 0xFF) << 8) | (crc >> 8)


def encode_nibbles(data: bytes) -> bytes:
    """Native EncodeToMIDSysEx: emit each byte high nibble, then low nibble."""
    result = bytearray(len(data) * 2)
    for index, byte in enumerate(data):
        result[index * 2] = byte >> 4
        result[index * 2 + 1] = byte & 0x0F
    return bytes(result)


def decode_nibbles(data: bytes) -> bytes:
    """Native DecodeToMIDSysEx inverse; reject odd length or non-nibble values."""
    if len(data) % 2:
        raise ValueError("nibble stream has odd length")
    if any(byte > 0x0F for byte in data):
        raise ValueError("nibble stream contains a value above 0x0f")
    return bytes(
        (data[index] << 4) | data[index + 1] for index in range(0, len(data), 2)
    )


def decode_message_payload(message: bytes, payload_offset: int) -> tuple[int, bytes]:
    """Decode a caller-selected nibble-coded region of a captured message.

    GP-180 commands have command-specific headers, and not every command uses
    nibble coding for its complete body. The native codec does not identify
    those boundaries, so the offset must come from the command parser.
    """
    if len(message) < 5 or message[:2] != b"\xf0\x7f" or message[-1] != 0xF7:
        raise ValueError("expected F0 7F ... F7 GP-180 SysEx")
    if not 3 <= payload_offset < len(message) - 1:
        raise ValueError("payload offset is outside the SysEx body")
    encoded = message[payload_offset:-1]
    return message[2], decode_nibbles(encoded)


def build_message(crc: int, payload: bytes) -> bytes:
    """Build framing when the caller has independently determined the CRC."""
    return b"\xf0\x7f" + bytes((crc,)) + encode_nibbles(payload) + b"\xf7"


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        raise SystemExit("usage: gp180_codec.py PAYLOAD_OFFSET HEX_SYSEX [...]")
    offset = int(sys.argv[1], 0)
    for argument in sys.argv[2:]:
        message = bytes.fromhex(argument)
        crc, payload = decode_message_payload(message, offset)
        print(f"crc=0x{crc:02x} payload={payload.hex()}")
