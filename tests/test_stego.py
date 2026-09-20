"""Unit tests for stego.py.

All test images are generated programmatically with PIL - nothing is
downloaded or scraped.
"""

import os
import random
import struct
import sys
import tempfile
import unittest

from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stego


def make_test_image(width=64, height=64, seed=42):
    """Create a deterministic pseudo-random RGB PNG-friendly test image."""
    rng = random.Random(seed)
    img = Image.new("RGB", (width, height))
    pixels = [
        (rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255))
        for _ in range(width * height)
    ]
    img.putdata(pixels)
    return img


class StegoTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def path(self, name):
        return os.path.join(self.tmpdir.name, name)

    def make_cover(self, name="cover.png", width=64, height=64, seed=42):
        img = make_test_image(width, height, seed)
        p = self.path(name)
        img.save(p, format="PNG")
        return p


class TestRoundTrip(StegoTestCase):
    def test_round_trip_text_payload(self):
        cover = self.make_cover()
        output = self.path("out.png")
        payload = "Hello, steganography world! 12345".encode("utf-8")
        stego.encode(cover, payload, output)
        recovered = stego.decode(output)
        self.assertEqual(recovered, payload)

    def test_round_trip_binary_payload(self):
        cover = self.make_cover()
        output = self.path("out.png")
        payload = bytes(random.Random(7).randint(0, 255) for _ in range(500))
        stego.encode(cover, payload, output)
        recovered = stego.decode(output)
        self.assertEqual(recovered, payload)

    def test_round_trip_empty_payload(self):
        cover = self.make_cover()
        output = self.path("out.png")
        payload = b""
        stego.encode(cover, payload, output)
        recovered = stego.decode(output)
        self.assertEqual(recovered, payload)

    def test_round_trip_via_files_cli_style(self):
        cover = self.make_cover(width=32, height=32)
        output = self.path("out.png")
        secret_path = self.path("secret.bin")
        payload = os.urandom(64)
        with open(secret_path, "wb") as f:
            f.write(payload)
        with open(secret_path, "rb") as f:
            data = f.read()
        stego.encode(cover, data, output)
        recovered = stego.decode(output)
        self.assertEqual(recovered, payload)


class TestCapacity(StegoTestCase):
    def test_capacity_known_image_size(self):
        # 10x10 RGB image -> 10*10*3 = 300 bits per bit-plane -> 37 bytes total
        # (300 // 8 = 37), minus header size (9 bytes) = 28 usable payload bytes.
        img = Image.new("RGB", (10, 10), color=(0, 0, 0))
        cap = stego.compute_capacity(img)
        header_size = stego.HEADER_STRUCT.size
        total_bytes = (10 * 10 * 3) // 8
        expected = total_bytes - header_size
        self.assertEqual(cap, expected)
        self.assertEqual(header_size, 9)  # 4 (magic) + 1 (flags) + 4 (length)

    def test_capacity_report_matches_compute_capacity(self):
        cover = self.make_cover(width=20, height=15)
        report = stego.capacity_report(cover)
        with Image.open(cover) as img:
            img = img.convert("RGB")
            expected = stego.compute_capacity(img)
        self.assertEqual(report["max_payload_bytes"], expected)
        self.assertEqual(report["width"], 20)
        self.assertEqual(report["height"], 15)

    def test_payload_exactly_at_capacity_succeeds(self):
        cover = self.make_cover(width=16, height=16)
        output = self.path("out.png")
        with Image.open(cover) as img:
            cap = stego.compute_capacity(img.convert("RGB"))
        payload = os.urandom(cap)
        stego.encode(cover, payload, output)
        recovered = stego.decode(output)
        self.assertEqual(recovered, payload)


class TestCapacityRejection(StegoTestCase):
    def test_oversized_payload_rejected_cleanly(self):
        cover = self.make_cover(width=8, height=8)  # tiny image, small capacity
        output = self.path("out.png")
        with Image.open(cover) as img:
            cap = stego.compute_capacity(img.convert("RGB"))
        payload = os.urandom(cap + 1000)  # way too big
        with self.assertRaises(stego.CapacityError):
            stego.encode(cover, payload, output)
        # Ensure no partial/corrupt output file was left in a decodable state.
        self.assertFalse(os.path.exists(output))


class TestNoHiddenData(StegoTestCase):
    def test_decode_plain_image_fails_cleanly(self):
        cover = self.make_cover()
        with self.assertRaises(stego.NoHiddenDataError):
            stego.decode(cover)

    def test_decode_random_noise_image_fails_cleanly(self):
        img = Image.new("RGB", (32, 32))
        rng = random.Random(99)
        img.putdata([
            (rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255))
            for _ in range(32 * 32)
        ])
        p = self.path("noise.png")
        img.save(p, format="PNG")
        with self.assertRaises(stego.NoHiddenDataError):
            stego.decode(p)


class TestEncryption(StegoTestCase):
    def test_encrypted_round_trip_correct_passphrase(self):
        cover = self.make_cover()
        output = self.path("out.png")
        payload = b"top secret watermark data"
        stego.encode(cover, payload, output, passphrase="correct-horse-battery")
        recovered = stego.decode(output, passphrase="correct-horse-battery")
        self.assertEqual(recovered, payload)

    def test_encrypted_wrong_passphrase_fails_cleanly(self):
        cover = self.make_cover()
        output = self.path("out.png")
        payload = b"top secret watermark data"
        stego.encode(cover, payload, output, passphrase="correct-horse-battery")
        with self.assertRaises(stego.DecryptionError):
            stego.decode(output, passphrase="wrong-passphrase")

    def test_encrypted_missing_passphrase_fails_cleanly(self):
        cover = self.make_cover()
        output = self.path("out.png")
        payload = b"top secret watermark data"
        stego.encode(cover, payload, output, passphrase="correct-horse-battery")
        with self.assertRaises(stego.DecryptionError):
            stego.decode(output)  # no passphrase supplied

    def test_encryption_changes_ciphertext_each_time(self):
        # AES-GCM uses a random nonce, so encrypting the same payload twice
        # should not produce identical ciphertext (sanity check we're not
        # accidentally using a fixed nonce/ECB-like scheme).
        payload = b"same payload twice"
        blob1 = stego.encrypt_payload(payload, "pw")
        blob2 = stego.encrypt_payload(payload, "pw")
        self.assertNotEqual(blob1, blob2)
        self.assertEqual(stego.decrypt_payload(blob1, "pw"), payload)
        self.assertEqual(stego.decrypt_payload(blob2, "pw"), payload)


class TestMinimalVisualChange(StegoTestCase):
    def test_only_lsbs_differ_between_cover_and_stego(self):
        cover = self.make_cover(width=40, height=40)
        output = self.path("out.png")
        payload = b"a reasonably sized payload to flip many LSBs" * 5
        stego.encode(cover, payload, output)

        with Image.open(cover) as c_img, Image.open(output) as s_img:
            c_img = c_img.convert("RGB")
            s_img = s_img.convert("RGB")
            self.assertEqual(c_img.size, s_img.size)

            cover_pixels = list(c_img.getdata())
            stego_pixels = list(s_img.getdata())

            differing_channels = 0
            for cp, sp in zip(cover_pixels, stego_pixels):
                for cv, sv in zip(cp, sp):
                    # Every channel byte may only change by flipping bit 0.
                    # That means: either the bytes are equal, or they differ
                    # by exactly 1 (the LSB flip), and clearing bit 0 on both
                    # must make them equal.
                    self.assertLessEqual(abs(cv - sv), 1,
                                          "channel changed by more than the LSB")
                    self.assertEqual(cv & 0xFE, sv & 0xFE,
                                      "a non-LSB bit was modified")
                    if cv != sv:
                        differing_channels += 1
            # Sanity: some bits actually were changed (payload is non-trivial).
            self.assertGreater(differing_channels, 0)

    def test_unused_tail_pixels_completely_unchanged(self):
        # Use a large cover with a tiny payload; pixels far beyond the
        # embedded header+payload region should be byte-for-byte identical.
        cover = self.make_cover(width=50, height=50)
        output = self.path("out.png")
        payload = b"tiny"
        stego.encode(cover, payload, output)

        with Image.open(cover) as c_img, Image.open(output) as s_img:
            c_img = c_img.convert("RGB")
            s_img = s_img.convert("RGB")
            cover_pixels = list(c_img.getdata())
            stego_pixels = list(s_img.getdata())

            header_size = stego.HEADER_STRUCT.size
            used_bits = (header_size + len(payload)) * 8
            # channels per pixel = 3, so used_bits channels are touched;
            # everything after that index (in flattened channel order)
            # must be byte-identical.
            flat_cover = bytearray()
            for p in cover_pixels:
                flat_cover.extend(p)
            flat_stego = bytearray()
            for p in stego_pixels:
                flat_stego.extend(p)

            self.assertEqual(flat_cover[used_bits:], flat_stego[used_bits:])


class TestLossyFormatRejection(StegoTestCase):
    def test_encode_to_jpeg_output_rejected(self):
        cover = self.make_cover()
        output = self.path("out.jpg")
        payload = b"should not be allowed to hide into jpeg output"
        with self.assertRaises(stego.LossyFormatError):
            stego.encode(cover, payload, output, passphrase=None)

    def test_encode_to_jpeg_output_leaves_no_file(self):
        cover = self.make_cover()
        output = self.path("out.jpeg")
        payload = b"payload"
        with self.assertRaises(stego.LossyFormatError):
            stego.encode(cover, payload, output)
        self.assertFalse(os.path.exists(output))

    def test_encode_to_png_output_is_allowed(self):
        cover = self.make_cover()
        output = self.path("fine.png")
        payload = b"payload"
        stego.encode(cover, payload, output)  # should not raise
        self.assertTrue(os.path.exists(output))


class TestHeaderAndMagic(StegoTestCase):
    def test_header_struct_size_is_nine_bytes(self):
        self.assertEqual(stego.HEADER_STRUCT.size, 9)

    def test_magic_marker_present_in_container(self):
        container = stego._build_container(b"hi", encrypted=False)
        magic, flags, length = stego.HEADER_STRUCT.unpack(container[:9])
        self.assertEqual(magic, stego.MAGIC)
        self.assertEqual(flags, 0)
        self.assertEqual(length, 2)

    def test_encrypted_flag_set_in_container(self):
        container = stego._build_container(b"hi", encrypted=True)
        magic, flags, length = stego.HEADER_STRUCT.unpack(container[:9])
        self.assertEqual(flags & stego.FLAG_ENCRYPTED, stego.FLAG_ENCRYPTED)


class TestBitPacking(StegoTestCase):
    def test_bytes_to_bits_and_back_round_trip(self):
        data = bytes(range(256))
        bits = stego._bytes_to_bits(data)
        self.assertEqual(len(bits), len(data) * 8)
        recovered = stego._bits_to_bytes(bits)
        self.assertEqual(recovered, data)

    def test_bits_to_bytes_rejects_non_multiple_of_eight(self):
        with self.assertRaises(stego.StegoError):
            stego._bits_to_bytes([0, 1, 1])


if __name__ == "__main__":
    unittest.main()
