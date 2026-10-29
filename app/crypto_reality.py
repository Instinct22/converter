from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def _b64decode(text: str) -> bytes:
    pad = '=' * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def generate_reality_keys() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    priv_raw = private.private_bytes_raw()
    pub_raw = private.public_key().public_bytes_raw()
    return _b64(priv_raw), _b64(pub_raw)


def public_from_private(private_b64: str) -> str:
    raw = _b64decode(private_b64)
    private = X25519PrivateKey.from_private_bytes(raw)
    return _b64(private.public_key().public_bytes_raw())


def random_short_id() -> str:
    return os.urandom(4).hex()
