# Image Steganography Tool

A small, self-contained Python tool that hides arbitrary data (text or any
binary file) inside PNG images using **LSB (Least Significant Bit)**
steganography, implemented from scratch. `Pillow` is used only for image
I/O (opening/saving PNGs and reading pixel data) — all of the bit-level
encoding/decoding logic is hand-written. An optional **AES-256-GCM**
encryption layer (via the `cryptography` package) can be composed on top,
so you can "encrypt, then hide" as two separate steps.

## How LSB steganography works

Every pixel in an RGB image is three bytes (red, green, blue), each ranging
0-255. Changing the **least significant bit** of a byte changes its value by
at most 1 (e.g. 200 -> 201 or 200 -> 200), which is imperceptible to the eye
and barely alters the image statistically.

This tool:

1. Flattens the image into a stream of channel bytes (R, G, B, R, G, B, ...).
2. Builds a small container around your payload:

   ```
   MAGIC (4 bytes: b"STG1") | FLAGS (1 byte) | LENGTH (4 bytes, big-endian) | PAYLOAD (LENGTH bytes)
   ```

   The magic marker lets `decode` verify that a payload was actually hidden
   (rather than reading random noise and returning garbage). The length
   header means decoding never has to guess where the payload ends — it
   reads exactly `LENGTH` more bytes after the 9-byte header.
3. Expands that container into individual bits and writes each bit into the
   least significant bit of one channel byte, in order.
4. Saves the result as a **lossless PNG**.

Decoding does the reverse: read the first 9 bytes' worth of LSBs, verify the
magic marker, read the declared `LENGTH`, then read that many more bytes'
worth of LSBs.

## Capacity math

For an image of width `W`, height `H`, and `C` channels (3 for RGB), using 1
bit per channel:

```
usable_bits  = W * H * C
usable_bytes = usable_bits // 8
max_payload  = usable_bytes - HEADER_SIZE   # HEADER_SIZE = 9 bytes
```

Example: a 64x64 RGB image has `64*64*3 = 12288` usable bits = `1536` bytes,
so it can hide `1536 - 9 = 1527` bytes of payload. Run `python stego.py
capacity <image>` to get this for any image you have.

Encoding a payload larger than an image's capacity is **rejected with a
clear `CapacityError`** — the tool never silently truncates or overflows
into pixels it shouldn't touch.

## Optional encryption layer

Passing `--passphrase` at encode time runs the payload through AES-256-GCM
**before** hiding it:

- A random 16-byte salt + PBKDF2-HMAC-SHA256 (200,000 iterations) derives a
  256-bit key from your passphrase.
- A random 12-byte nonce and AES-256-GCM (via the `cryptography` package —
  no hand-rolled ciphers) encrypt the payload, producing an authenticated
  ciphertext.
- `salt || nonce || ciphertext` is what actually gets hidden in the image.

Decoding with the wrong passphrase (or without one, for an encrypted image)
fails cleanly with a `DecryptionError` — it never hands back corrupted
plaintext.

Encryption and hiding are separate, composable steps: `encrypt_payload()` /
`decrypt_payload()` can be used independently of `encode()` / `decode()`.

## Lossy format warning

LSB steganography depends on the *exact* numeric value of every pixel byte.
**Any lossy re-encoding — JPEG, lossy WEBP, resizing, color-space
conversion, even re-saving in some image editors — will scramble or destroy
the hidden bits.** This tool enforces that at encode time: the output path
must end in `.png`, or encoding raises a `LossyFormatError` before writing
anything. If you need to distribute a stego image, keep it as PNG all the
way through; never post it to a platform that recompresses uploads (many
social/chat apps do this to JPEG automatically).

## CLI usage

```bash
pip install -r requirements.txt

# Report how many bytes a cover image can hide
python stego.py capacity cover.png

# Hide secret.txt inside cover.png, write result to output.png
python stego.py encode cover.png secret.txt output.png

# Same, but encrypt the payload first with a passphrase
python stego.py encode cover.png secret.txt output.png --passphrase "correct horse battery staple"

# Recover the hidden payload
python stego.py decode output.png recovered.txt

# Recover an encrypted payload (wrong/missing passphrase fails cleanly)
python stego.py decode output.png recovered.txt --passphrase "correct horse battery staple"
```

### Example round-trip

```bash
python - <<'PY'
from PIL import Image
import random
rng = random.Random(1)
img = Image.new("RGB", (100, 100))
img.putdata([(rng.randint(0,255), rng.randint(0,255), rng.randint(0,255)) for _ in range(100*100)])
img.save("cover.png")
PY

echo "This message is hidden inside an image." > secret.txt

python stego.py capacity cover.png
python stego.py encode cover.png secret.txt output.png --passphrase "hunter2"
python stego.py decode output.png recovered.txt --passphrase "hunter2"
diff secret.txt recovered.txt && echo "Round-trip OK"
```

## Running the tests

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The test suite (`tests/test_stego.py`) generates all cover images
programmatically with PIL (no downloaded assets) and covers:

- Encode-then-decode round-trips for text, binary, empty, and file-based
  payloads.
- Capacity calculation correctness against known image dimensions.
- Oversized payloads being rejected instead of corrupting the image.
- Decoding an image with no hidden payload failing cleanly (magic-marker
  check), including on random noise images.
- Encrypted round-trips with the correct passphrase.
- Encrypted decode failing cleanly with the wrong or a missing passphrase.
- The statistical/visual change from hiding data being minimal: every
  changed channel byte differs from the cover by at most 1, and clearing
  bit 0 on both cover and stego bytes always makes them equal (i.e. only
  LSBs ever change) — plus pixels beyond the hidden payload's extent stay
  byte-for-byte identical.
- Encoding into a non-lossless output path (`.jpg`/`.jpeg`) being rejected
  with a clear error rather than silently producing a fragile file.
- Low-level bit-packing/unpacking helpers and the header/magic-marker
  container format.

## Continuous integration

`.github/workflows/tests.yml` runs the full test suite on every push and
pull request, on both Python 3.11 and 3.12.

## Project layout

```
image-steganography/
├── stego.py                  # core LSB codec, AES-GCM layer, and CLI
├── tests/
│   └── test_stego.py         # unit tests (generates its own PIL images)
├── requirements.txt
├── LICENSE
├── README.md
└── .github/workflows/tests.yml
```

## License

MIT — see [LICENSE](LICENSE).
