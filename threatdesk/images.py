"""Image handling: safe decode, re-encode, perceptual hash. Never trusts the uploaded bytes as-is."""
from __future__ import annotations

import io

import imagehash
from PIL import Image, UnidentifiedImageError

from threatdesk.safety import InvalidInput

MAX_UPLOAD = 1024 * 1024
ALLOWED_FORMATS = {"PNG", "JPEG"}
PHASH_MATCH_DISTANCE = 10
Image.MAX_IMAGE_PIXELS = 25_000_000          # decompression-bomb guard


def decode(data: bytes, allowed: set[str] = ALLOWED_FORMATS) -> Image.Image:
    if len(data) > MAX_UPLOAD:
        raise InvalidInput("Image must be 1 MB or smaller.")
    try:
        probe = Image.open(io.BytesIO(data))
        fmt = probe.format
        probe.verify()                        # structural check; the object is unusable afterwards
        img = Image.open(io.BytesIO(data))
        img.load()
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError, Image.DecompressionBombError):
        raise InvalidInput("File is not a readable image.")
    if fmt not in allowed:
        raise InvalidInput(f"Image format {fmt} not allowed.")
    return img


def reencode_png(img: Image.Image) -> bytes:
    """Fresh PNG: drops metadata and anything appended after the image data."""
    mode = "RGBA" if img.mode in ("RGBA", "LA", "P") else "RGB"
    out = io.BytesIO()
    img.convert(mode).save(out, format="PNG", optimize=True)
    return out.getvalue()


def phash_hex(img: Image.Image) -> str:
    return str(imagehash.phash(img.convert("RGB")))


def distance(a: str | None, b: str | None) -> int | None:
    if not a or not b:
        return None
    try:
        return int(imagehash.hex_to_hash(a) - imagehash.hex_to_hash(b))
    except (ValueError, TypeError):
        return None


def process_logo_upload(data: bytes) -> tuple[bytes, str]:
    img = decode(data)
    return reencode_png(img), phash_hex(img)
