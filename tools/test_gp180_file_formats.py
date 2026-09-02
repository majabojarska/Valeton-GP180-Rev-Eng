import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "tools"))

from gp180_bman import BMAN_SIZE, WEIGHT_OFFSET, build_candidate
from generate_nam_variants import variants
from gp180_namb import NAMB_SIZE, WEIGHT_OFFSET as NAMB_WEIGHT_OFFSET, build_namb
from gp180_namb import namb_crc32
from gp180_codec import (
    build_message,
    crc8,
    crc16_native,
    decode_message_payload,
    decode_nibbles,
    encode_nibbles,
)
from gp180_file_formats import decode_capture, describe, parse_transfer
from verify_namb_bman import verify_controlled_pairs


def make_message(payload: bytes, index: int = 0) -> bytes:
    offset = 119 * index
    return (
        b"\xf0\x7f\x00\x24"
        + bytes((0x40, offset & 0x7F, (offset >> 7) & 0x7F, 0x0B, index, 0, 0))
        + encode_nibbles(payload)
        + b"\xf7"
    )


def make_corpus(tmp: Path, record: bytes) -> Path:
    transfer = b"\x01\x20\x20\x01\x01\x90\x10\x50" + b"\0" * 27 + record
    chunks = [transfer[index : index + 118] for index in range(0, len(transfer), 118)]
    path = tmp / "corpus.jsonl"
    with path.open("w") as stream:
        for frame, chunk in enumerate(chunks, 1):
            message = make_message(chunk, frame - 1)
            stream.write(
                json.dumps(
                    {
                        "capture": "sample.pcapng",
                        "frame": frame,
                        "family": "0x24",
                        "length": len(message),
                        "raw": message.hex(),
                    }
                )
                + "\n"
            )
    return path


class FileFormatTests(unittest.TestCase):
    def test_bman_candidate_replaces_weight_region(self):
        template = bytearray(BMAN_SIZE)
        template[:4] = b"BMAN"
        nam = {
            "version": "0.7.0",
            "architecture": "SlimmableContainer",
            "config": {
                "submodels": [
                    {
                        "model": {
                            "architecture": "WaveNet",
                            "sample_rate": 48000.0,
                            "weights": [float(index) for index in range(1871)],
                        }
                    }
                ]
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nam_path = root / "model.nam"
            nam_path.write_text(json.dumps(nam))
            candidate = build_candidate(nam_path, bytes(template))
        self.assertEqual(struct.unpack_from("<f", candidate, WEIGHT_OFFSET)[0], 0.0)
        self.assertEqual(
            struct.unpack_from("<f", candidate, WEIGHT_OFFSET + 4 * 17)[0], 17.0
        )

    def test_bman_candidate_rejects_wrong_template(self):
        nam = Path("NAM/HELLBERT.nam")
        with self.assertRaisesRegex(ValueError, "template"):
            build_candidate(nam, b"\0" * BMAN_SIZE)

    def test_namb_candidate_replaces_contiguous_native_weights(self):
        template = bytearray(NAMB_SIZE)
        template[:4] = b"BMAN"
        template[0x18:0x1C] = b"\x12\x34\x56\x78"
        nam = {
            "version": "0.7.0",
            "architecture": "SlimmableContainer",
            "config": {"submodels": [{"model": {
                "architecture": "WaveNet",
                "sample_rate": 48000.0,
                "weights": [float(index) for index in range(1871)],
            }}]},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.nam"
            path.write_text(json.dumps(nam))
            candidate = build_namb(path, bytes(template))
        self.assertEqual(
            struct.unpack_from("<f", candidate, NAMB_WEIGHT_OFFSET + 4 * 935)[0],
            935.0,
        )
        self.assertNotEqual(candidate[0x18:0x1C], b"\x12\x34\x56\x78")

    def test_cached_namb_crc32(self):
        paths = sorted(Path("NAM/nam_to_namb_import").glob("*.namb"))
        self.assertGreater(len(paths), 0)
        for path in paths:
            data = path.read_bytes()
            self.assertEqual(len(data), NAMB_SIZE, path.name)
            self.assertEqual(
                int.from_bytes(data[0x18:0x1C], "little"),
                namb_crc32(data),
                path.name,
            )

    def test_controlled_namb_to_bman_projection(self):
        results = verify_controlled_pairs(
            Path("sysex-corpus.jsonl"),
            Path("NAM/nam_to_namb_import"),
        )
        self.assertEqual(len(results), 17)

    def test_controlled_nam_variant_set(self):
        source = json.loads(Path("NAM/HELLBERT.nam").read_text())
        generated = variants(source)
        self.assertEqual(len(generated), 17)
        self.assertEqual(generated[0][0], "00-baseline")
        self.assertEqual(generated[0][2], source)
        for _, _, document in generated:
            self.assertEqual(document["version"], "0.7.0")
            self.assertEqual(len(document["config"]["submodels"]), 2)

    def test_crc8_known_vector(self):
        self.assertEqual(crc8(b"123456789"), 0xF4)

    def test_native_crc16(self):
        self.assertEqual(crc16_native(b"123456789"), 0x374B)
        self.assertEqual(crc16_native(b"xx123456789", skip=2), 0x374B)

    def test_nibble_round_trip(self):
        payload = bytes(range(256))
        self.assertEqual(decode_nibbles(encode_nibbles(payload)), payload)

    def test_decode_nibbles_rejects_invalid_streams(self):
        with self.assertRaises(ValueError):
            decode_nibbles(b"\x01")
        with self.assertRaises(ValueError):
            decode_nibbles(b"\x01\x10")

    def test_build_and_decode_message(self):
        message = build_message(0x5A, b"\x00\x12\xfe")
        self.assertEqual(
            decode_message_payload(message, 3),
            (0x5A, b"\x00\x12\xfe"),
        )

    def test_decode_message_rejects_invalid_framing_and_offsets(self):
        with self.assertRaises(ValueError):
            decode_message_payload(b"\x00\x7f\x00\x01\xf7", 3)
        with self.assertRaises(ValueError):
            decode_message_payload(b"\xf0\x7f\x00\x01\xf7", 2)
        with self.assertRaises(ValueError):
            decode_message_payload(b"\xf0\x7f\x00\x01\xf7", 4)

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
        record[8:12] = (0xDEAD).to_bytes(4, "little")
        record[20:24] = (2560).to_bytes(4, "little")
        record[28:32] = struct.pack("<f", 1.875)
        info = describe(b"\0" * 8 + b"\0" * 27 + bytes(record))
        self.assertEqual(info["marker"], "VTSI")
        self.assertEqual(info["model_region_size"], 2696)
        self.assertEqual(info["integrity_field"], 0xDEAD)
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

    def test_parse_transfer_recovers_chunk_offsets_and_final_segment(self):
        record = bytearray(8123)
        record[:4] = b"BMAN"
        with tempfile.TemporaryDirectory() as directory:
            corpus = make_corpus(Path(directory), bytes(record))
            info = parse_transfer(corpus, "sample.pcapng")
        self.assertEqual(info["chunk_count"], 70)
        self.assertEqual(info["full_chunk_count"], 69)
        self.assertEqual(info["final_chunk_size"], 16)
        self.assertEqual(info["decoded_size"], 8158)
        self.assertTrue(info["indexes_sequential"])
        self.assertTrue(info["offsets_valid"])
        self.assertTrue(info["transfer_id_stable"])
        self.assertTrue(info["kind_stable"])
        self.assertEqual(info["per_chunk_integrity"], "observed-nibbles-unverified")
        chunks = info["chunks"]
        self.assertEqual(chunks[1].offset, 119)
        self.assertEqual(chunks[-1].expected_offset, 119 * 69)

    def test_parse_real_transfer_reports_completion_ack(self):
        info = parse_transfer(
            Path("sysex-corpus.jsonl"),
            "suite-triggered-nam-file-import-slot-2-NAM-HELLBERT.pcapng",
        )
        self.assertEqual(info["kind"], 0x40)
        self.assertEqual(info["transfer_id"], 9)
        self.assertTrue(info["offsets_valid"])
        self.assertEqual(info["transfer_prefix"], "ae20200101901050")
        self.assertEqual(info["completion_acks"][0]["status"], 0)

    def test_decode_capture_rejects_missing_transfer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "capture": "other.pcapng",
                        "frame": 1,
                        "family": "0x10",
                        "length": 40,
                        "raw": "",
                    }
                )
                + "\n"
            )
            with self.assertRaises(ValueError):
                decode_capture(path, "sample.pcapng")

    def test_describe_rejects_invalid_data(self):
        with self.assertRaisesRegex(ValueError, "expected 8158"):
            describe(b"short")
        with self.assertRaisesRegex(ValueError, "no BMAN or VTSI"):
            describe(b"\0" * 8158)


if __name__ == "__main__":
    unittest.main()
