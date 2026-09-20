#!/usr/bin/env python3
"""
stego.py - LSB (Least Significant Bit) Image Steganography Tool

Hides an arbitrary payload (text or binary file bytes) inside the least
significant bits of a lossless (PNG) image's pixel channels, and extracts
it back out byte-for-byte. Optionally encrypts the payload first with
AES-256-GCM (via the `cryptography` package) using a passphrase, so
"encrypt then hide" are two separable, composable steps.

Format written into the image (before any encryption bytes are hidden):

    MAGIC (4 bytes)  b"STG1"
    FLAGS (1 byte)   bit 0 = payload is encrypted
    LENGTH (4 bytes) big-endian uint32, number of payload bytes that follow
    PAYLOAD (LENGTH bytes)

All of the above (magic + flags + length + payload) is what actually gets
bit-packed into the image's LSBs. This means decoding never has to guess
where the data ends - it reads the fixed-size header first, then reads
exactly LENGTH more bytes.

Only 1 bit per color channel is used (the classic 1-bit LSB scheme), which
keeps the change to each byte to at most +/-1, imperceptible to the eye and
statistically minimal (only the LSB of each channel byte can change).

LOSSY FORMAT WARNING: LSB steganography embeds data in the exact numeric
value of each pixel channel byte. Any lossy re-encoding (JPEG, WEBP lossy,
resizing, color-space conversion, etc.) will scramble or destroy the LSBs
and the hidden payload will not survive. This tool therefore *enforces*
that the encode output path ends in `.png` (a lossless format) and raises
a clear error otherwise, rather than silently producing a file that looks
fine but has lost its hidden data.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

from PIL import Image

MAGIC = b"STG1"
HEADER_STRUCT = struct.Struct(">4sBI")  # magic, flags, length
FLAG_ENCRYPTED = 0b00000001

# AES-GCM constants
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 200_000

LOSSLESS_EXTENSIONS = {".png"}


class StegoError(Exception):
    """Base error for all steganography operations."""


class CapacityError(StegoError):
    """Raised when the payload does not fit in the cover image."""


class NoHiddenDataError(StegoError):
    """Raised when decoding an image that has no valid hidden payload."""


class LossyFormatError(StegoError):
    """Raised when the requested output format is not lossless."""


class DecryptionError(StegoError):
    """Raised when decryption fails (e.g. wrong passphrase)."""


# ---------------------------------------------------------------------------
# Bit-level helpers (hand-written, no external bit-manipulation libraries)
# ---------------------------------------------------------------------------

def _bytes_to_bits(data: bytes) -> list:
    """Expand bytes into a flat list of individual bits (MSB first per byte)."""
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_bytes(bits) -> bytes:
    """Pack a flat sequence of bits (MSB first per byte) back into bytes."""
    if len(bits) % 8 != 0:
        raise StegoError("Bit stream length is not a multiple of 8; corrupt data.")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def _build_container(payload: bytes, encrypted: bool) -> bytes:
    """Prepend the magic marker, flags, and length header to the payload."""
    flags = FLAG_ENCRYPTED if encrypted else 0
    header = HEADER_STRUCT.pack(MAGIC, flags, len(payload))
    return header + payload


# ---------------------------------------------------------------------------
# Encryption layer (AES-256-GCM via `cryptography`; no hand-rolled crypto)
# ---------------------------------------------------------------------------

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_payload(data: bytes, passphrase: str) -> bytes:
    """Encrypt data with AES-256-GCM. Output = salt || nonce || ciphertext(+tag)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext


def decrypt_payload(blob: bytes, passphrase: str) -> bytes:
    """Reverse of encrypt_payload. Raises DecryptionError on any failure."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    if len(blob) < SALT_SIZE + NONCE_SIZE:
        raise DecryptionError("Encrypted blob is too short to be valid.")
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:]
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise DecryptionError(
            "Failed to decrypt payload: wrong passphrase or corrupted data."
        ) from exc


# ---------------------------------------------------------------------------
# Capacity
# ---------------------------------------------------------------------------

def compute_capacity(image: Image.Image, bits_per_channel: int = 1) -> int:
    """Return the maximum number of *payload* bytes (post-header) that fit.

    Capacity is computed from width * height * number-of-channels, using
    `bits_per_channel` LSBs of each channel byte, minus the fixed header
    size (magic + flags + length).
    """
    width, height = image.size
    channels = len(image.getbands())
    total_bits = width * height * channels * bits_per_channel
    total_bytes = total_bits // 8
    header_size = HEADER_STRUCT.size
    return max(0, total_bytes - header_size)


def capacity_report(path: str) -> dict:
    with Image.open(path) as img:
        width, height = img.size
        channels = len(img.getbands())
        max_payload = compute_capacity(img)
    return {
        "path": path,
        "width": width,
        "height": height,
        "channels": channels,
        "header_bytes": HEADER_STRUCT.size,
        "max_payload_bytes": max_payload,
    }


# ---------------------------------------------------------------------------
# Core encode / decode
# ---------------------------------------------------------------------------

def _validate_lossless_path(path: str) -> None:
    ext = os.path.splitext(path)[1].lower()
    if ext not in LOSSLESS_EXTENSIONS:
        raise LossyFormatError(
            f"Output path '{path}' has extension '{ext}', which is not a "
            f"lossless format. LSB steganography requires exact pixel "
            f"values to survive, so only {sorted(LOSSLESS_EXTENSIONS)} "
            f"output is supported. Re-saving as JPEG or another lossy "
            f"format will destroy the hidden data."
        )


def encode(cover_path: str, payload: bytes, output_path: str,
           passphrase: str | None = None) -> None:
    """Hide `payload` inside `cover_path`, writing the result to `output_path`.

    Raises CapacityError if the payload (plus header) does not fit.
    Raises LossyFormatError if output_path is not a lossless (.png) path.
    """
    _validate_lossless_path(output_path)

    encrypted = passphrase is not None
    if encrypted:
        payload = encrypt_payload(payload, passphrase)

    container = _build_container(payload, encrypted)

    with Image.open(cover_path) as img:
        img = img.convert("RGB")
        capacity = compute_capacity(img)
        if len(payload) > capacity:
            raise CapacityError(
                f"Payload of {len(payload)} bytes exceeds this cover "
                f"image's capacity of {capacity} bytes. Use a larger "
                f"image, a smaller payload, or reduce the payload size."
            )

        bits = _bytes_to_bits(container)
        pixels = list(img.getdata())
        width, height = img.size
        channels = len(img.getbands())

        flat = bytearray()
        for pixel in pixels:
            flat.extend(pixel)

        for i, bit in enumerate(bits):
            flat[i] = (flat[i] & 0xFE) | bit

        new_pixels = []
        for i in range(0, len(flat), channels):
            new_pixels.append(tuple(flat[i:i + channels]))

        out_img = Image.new("RGB", (width, height))
        out_img.putdata(new_pixels)
        out_img.save(output_path, format="PNG")


def decode(stego_path: str, passphrase: str | None = None) -> bytes:
    """Extract the hidden payload from `stego_path`.

    Raises NoHiddenDataError if the magic marker does not match (i.e. no
    valid payload was ever hidden, or the image was corrupted/recompressed).
    Raises DecryptionError if the payload was encrypted and the passphrase
    is missing or wrong.
    """
    with Image.open(stego_path) as img:
        img = img.convert("RGB")
        pixels = list(img.getdata())
        channels = len(img.getbands())

        flat = bytearray()
        for pixel in pixels:
            flat.extend(pixel)

        header_bits_needed = HEADER_STRUCT.size * 8
        if len(flat) < header_bits_needed:
            raise NoHiddenDataError("Image is too small to contain a header.")

        header_bits = [flat[i] & 1 for i in range(header_bits_needed)]
        header_bytes = _bits_to_bytes(header_bits)
        magic, flags, length = HEADER_STRUCT.unpack(header_bytes)

        if magic != MAGIC:
            raise NoHiddenDataError(
                "No valid hidden payload found in this image (magic marker "
                "mismatch). Either nothing was hidden here, or the image "
                "was modified/recompressed after encoding."
            )

        total_bits_needed = header_bits_needed + length * 8
        if len(flat) < total_bits_needed:
            raise NoHiddenDataError(
                "Declared payload length exceeds available image data; "
                "the image is corrupted or truncated."
            )

        payload_bits = [flat[i] & 1 for i in range(header_bits_needed, total_bits_needed)]
        payload = _bits_to_bytes(payload_bits)

    is_encrypted = bool(flags & FLAG_ENCRYPTED)
    if is_encrypted:
        if passphrase is None:
            raise DecryptionError(
                "This payload is encrypted; a --passphrase is required."
            )
        payload = decrypt_payload(payload, passphrase)
    return payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_encode(args: argparse.Namespace) -> None:
    with open(args.secret_file, "rb") as f:
        payload = f.read()
    encode(args.cover, payload, args.output, passphrase=args.passphrase)
    print(f"Encoded {len(payload)} bytes from '{args.secret_file}' into "
          f"'{args.output}'.")


def _cmd_decode(args: argparse.Namespace) -> None:
    payload = decode(args.stego_image, passphrase=args.passphrase)
    with open(args.recovered_file, "wb") as f:
        f.write(payload)
    print(f"Decoded {len(payload)} bytes from '{args.stego_image}' into "
          f"'{args.recovered_file}'.")


def _cmd_capacity(args: argparse.Namespace) -> None:
    report = capacity_report(args.cover)
    print(f"Image:            {report['path']}")
    print(f"Dimensions:       {report['width']} x {report['height']}")
    print(f"Channels:         {report['channels']}")
    print(f"Header overhead:  {report['header_bytes']} bytes")
    print(f"Max payload size: {report['max_payload_bytes']} bytes")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stego.py",
        description="LSB image steganography tool (encode/decode/capacity).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_encode = sub.add_parser("encode", help="Hide a payload inside a PNG cover image.")
    p_encode.add_argument("cover", help="Path to the lossless cover image (e.g. PNG).")
    p_encode.add_argument("secret_file", help="Path to the file whose bytes to hide.")
    p_encode.add_argument("output", help="Path to write the stego PNG image to.")
    p_encode.add_argument("--passphrase", default=None,
                           help="Optional passphrase to AES-256-GCM encrypt the payload before hiding it.")
    p_encode.set_defaults(func=_cmd_encode)

    p_decode = sub.add_parser("decode", help="Extract a hidden payload from a stego image.")
    p_decode.add_argument("stego_image", help="Path to the PNG image containing hidden data.")
    p_decode.add_argument("recovered_file", help="Path to write the recovered bytes to.")
    p_decode.add_argument("--passphrase", default=None,
                           help="Passphrase to decrypt the payload, if it was encrypted at encode time.")
    p_decode.set_defaults(func=_cmd_decode)

    p_capacity = sub.add_parser("capacity", help="Report the max payload size for a cover image.")
    p_capacity.add_argument("cover", help="Path to the cover image to inspect.")
    p_capacity.set_defaults(func=_cmd_capacity)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except StegoError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
