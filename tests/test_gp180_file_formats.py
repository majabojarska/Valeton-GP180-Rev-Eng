import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "tools"))

from gp180_codec import crc16_native, encode_nibbles
from gp180_file_formats import decode_capture, describe


def make_message(payload: bytes) -> bytes:
    return b"\xf0\x7f\x00\x24" + b"\x40\x00\x00\x0b\x00\x00\x00" + encode_nibbles(payload) + b"\xf7"


def make_corpus(tmp: Path, record: bytes) -> Path:
    transfer = b"\x01\x20\x20\x01\x01\x90\x10\x50" + b"\0" * 27 + record
    chunks = [transfer[index:index + 118] for index in range(0, len(transfer), 118)]
    path = tmp / "corpus.jsonl"
    with path.open("w") as stream:
        for frame, chunk in enumerate(chunks, 1):
            message = make_message(chunk)
            stream.write(json.dumps({
                "capture": "sample.pcapng",
                "frame": frame,
                "family": "0x24",
                "length": len(message),
                "raw": message.hex(),
            }) + "\n")
    return path


class FileFormatTests(unittest.TestCase):
    def test_native_crc16(self):
        self.assertEqual(crc16_native(b"123456789"), 0x374B)
        self.assertEqual(crc16_native(b"xx123456789", skip=2), 0x374B)

    def test_describe_bman(self):
        record = bytearray(8123)
        record[:4] = b"BMAN"
        record[4:6] = (1).to_bytes(2, "little")
        record[8:12] = (7980).to_bytes(4, "little")
        record[12:16] = (496).to_bytes(4, "little")
        record[16:20] = (1871).to_bytes(4, "little")
        record[20:24] = (413).to_bytes(4, "little")
        info = describe(b"\0" * 8 + b"\0" * 27 + bytes(record))
        self.assertEqual(info["marker"], "BMAN")
        self.assertEqual(info["header_fields"][:4], [7980, 496, 1871, 413])

    def test_describe_vtsi(self):
        record = bytearray(8123)
        record[:4] = b"VTSI"
        record[4:8] = (2696).to_bytes(4, "little")
        record[8:12] = (0xdead).to_bytes(4, "little")
        record[20:24] = (2560).to_bytes(4, "little")
        record[28:32] = struct.pack("<f", 1.875)
        info = describe(b"\0" * 8 + b"\0" * 27 + bytes(record))
        self.assertEqual(info["marker"], "VTSI")
        self.assertEqual(info["model_region_size"], 2696)
        self.assertEqual(info["integrity_field"], 0xdead)
        self.assertEqual(info["scale"], 1.875)

    def test_decode_capture_reassembles_and_extracts_record(self):
        record = bytearray(8123)
        record[:4] = b"BMAN"
        record[4:6] = (1).to_bytes(2, "little")
        record[8:12] = (7980).to_bytes(4, "little")
        with tempfile.TemporaryDirectory() as directory:
            corpus = make_corpus(Path(directory), bytes(record))
            data = decode_capture(corpus, "sample.pcapng")
        self.assertEqual(data[35:39], b"BMAN")
        self.assertEqual(len(data), 8158)


if __name__ == "__main__":
    unittest.main()
