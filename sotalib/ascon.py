"""Ascon lightweight cryptography, as standardised in NIST SP 800-232.

Two primitives are provided, and only the two this project needs:

* ``Ascon-Hash256``  -- 256-bit cryptographic hash (integrity)
* ``Ascon-AEAD128``  -- authenticated encryption with 128-bit key, nonce and tag
  (confidentiality + ciphertext integrity)

This is a readable reference implementation in pure Python. It is the *host*
side of the project; the device runs the C implementation in
``components/ascon``. Both are validated against the same official
Known-Answer-Test vectors in ``tests/vectors/`` (see ``tests/test_ascon_kat.py``
and ``tests/host/``), which is what guarantees the two agree.

Byte-order note, because it is the single easiest thing to get wrong here:
SP 800-232 uses **little-endian** conversion between byte strings and the
64-bit state words. This differs from the older Ascon v1.2 specification,
which was big-endian -- which is why Ascon-Hash256 and the v1.2 Ascon-Hash
produce different digests for the same input. All loads and stores below are
little-endian, and the C implementation uses the same convention.

Not constant-time and not side-channel hardened; it never touches the device
and only ever handles the build-time signing/packaging keys.
"""

from __future__ import annotations

import hmac

__all__ = [
    "ASCON_HASH_BYTES",
    "ASCON_KEY_BYTES",
    "ASCON_NONCE_BYTES",
    "ASCON_TAG_BYTES",
    "AsconHash256",
    "hash256",
    "aead128_encrypt",
    "aead128_decrypt",
    "AsconTagError",
]

M64 = 0xFFFFFFFFFFFFFFFF

ASCON_HASH_BYTES = 32
ASCON_KEY_BYTES = 16
ASCON_NONCE_BYTES = 16
ASCON_TAG_BYTES = 16

_HASH_RATE = 8   # Ascon-Hash256 absorbs/squeezes 8 bytes per permutation
_AEAD_RATE = 16  # Ascon-AEAD128 processes 16 bytes per permutation

# Initial values, before the initial p^12. Little-endian interpretations of the
# IV byte strings in SP 800-232.
_IV_HASH256 = 0x0000080100CC0002
_IV_AEAD128 = 0x00001000808C0001

# Domain separation constant, XORed into x4 between associated data and payload.
_DSEP = 0x80 << 56


class AsconTagError(Exception):
    """Raised when Ascon-AEAD128 decryption fails to authenticate.

    A tag mismatch means the ciphertext, the nonce, the associated data or the
    key is wrong. The plaintext is never returned in that case.
    """


# --------------------------------------------------------------------------
# word helpers
# --------------------------------------------------------------------------

def _load(b: bytes) -> int:
    """Little-endian load of up to 8 bytes into a 64-bit word."""
    return int.from_bytes(b.ljust(8, b"\x00"), "little")


def _store(x: int, n: int = 8) -> bytes:
    """Little-endian store of the low ``n`` bytes of a 64-bit word."""
    return (x & M64).to_bytes(8, "little")[:n]


def _pad(n: int) -> int:
    """The Ascon padding word for a partial block of ``n`` bytes: 0x01 << 8n."""
    return 0x01 << (8 * n)


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & M64


# --------------------------------------------------------------------------
# permutation
# --------------------------------------------------------------------------

def _permute(s: list[int], rounds: int) -> None:
    """Apply Ascon-p^rounds to the 5-word state ``s`` in place.

    Round constants run 0xf0, 0xe1, ... 0x4b in steps of 15; an r-round
    permutation uses the *last* r of the twelve, so p^8 starts at 0xb4.
    """
    for r in range(12 - rounds, 12):
        # constant addition
        s[2] ^= 0xF0 - 15 * r

        # substitution layer (bitsliced 5-bit S-box)
        s[0] ^= s[4]
        s[4] ^= s[3]
        s[2] ^= s[1]
        t = [(s[i] ^ M64) & s[(i + 1) % 5] for i in range(5)]
        for i in range(5):
            s[i] ^= t[(i + 1) % 5]
        s[1] ^= s[0]
        s[0] ^= s[4]
        s[3] ^= s[2]
        s[2] ^= M64

        # linear diffusion layer
        s[0] ^= _rotr(s[0], 19) ^ _rotr(s[0], 28)
        s[1] ^= _rotr(s[1], 61) ^ _rotr(s[1], 39)
        s[2] ^= _rotr(s[2], 1) ^ _rotr(s[2], 6)
        s[3] ^= _rotr(s[3], 10) ^ _rotr(s[3], 17)
        s[4] ^= _rotr(s[4], 7) ^ _rotr(s[4], 41)


# --------------------------------------------------------------------------
# Ascon-Hash256
# --------------------------------------------------------------------------

class AsconHash256:
    """Incremental Ascon-Hash256, mirroring the ``hashlib`` interface.

    The incremental form exists so the host can hash a firmware image the same
    way the device does -- in chunks, without ever holding the whole image.
    """

    digest_size = ASCON_HASH_BYTES
    block_size = _HASH_RATE

    def __init__(self, data: bytes = b"") -> None:
        self._s = [_IV_HASH256, 0, 0, 0, 0]
        _permute(self._s, 12)
        self._buf = bytearray()
        self._done: bytes | None = None
        if data:
            self.update(data)

    def update(self, data: bytes) -> "AsconHash256":
        if self._done is not None:
            raise RuntimeError("update() after digest()")
        self._buf += data
        # absorb every complete rate block currently buffered
        n = len(self._buf) - (len(self._buf) % _HASH_RATE)
        for off in range(0, n, _HASH_RATE):
            self._s[0] ^= _load(self._buf[off:off + _HASH_RATE])
            _permute(self._s, 12)
        del self._buf[:n]
        return self

    def digest(self) -> bytes:
        if self._done is None:
            s = list(self._s)
            # final, always-present partial block: 0..rate-1 bytes plus padding
            s[0] ^= _load(bytes(self._buf))
            s[0] ^= _pad(len(self._buf))
            _permute(s, 12)
            out = bytearray()
            while len(out) < ASCON_HASH_BYTES:
                take = min(_HASH_RATE, ASCON_HASH_BYTES - len(out))
                out += _store(s[0], take)
                if len(out) < ASCON_HASH_BYTES:
                    _permute(s, 12)
            self._done = bytes(out)
        return self._done

    def hexdigest(self) -> str:
        return self.digest().hex()


def hash256(data: bytes) -> bytes:
    """One-shot Ascon-Hash256. Returns 32 bytes."""
    return AsconHash256(data).digest()


# --------------------------------------------------------------------------
# Ascon-AEAD128
# --------------------------------------------------------------------------

def _aead_init(key: bytes, nonce: bytes, ad: bytes) -> tuple[list[int], int, int]:
    if len(key) != ASCON_KEY_BYTES:
        raise ValueError(f"key must be {ASCON_KEY_BYTES} bytes, got {len(key)}")
    if len(nonce) != ASCON_NONCE_BYTES:
        raise ValueError(f"nonce must be {ASCON_NONCE_BYTES} bytes, got {len(nonce)}")

    k0, k1 = _load(key[0:8]), _load(key[8:16])
    s = [_IV_AEAD128, k0, k1, _load(nonce[0:8]), _load(nonce[8:16])]
    _permute(s, 12)
    s[3] ^= k0
    s[4] ^= k1

    # associated data
    if ad:
        off = 0
        while len(ad) - off >= _AEAD_RATE:
            s[0] ^= _load(ad[off:off + 8])
            s[1] ^= _load(ad[off + 8:off + 16])
            _permute(s, 8)
            off += _AEAD_RATE
        rest = ad[off:]
        if len(rest) >= 8:
            s[0] ^= _load(rest[0:8])
            s[1] ^= _load(rest[8:]) ^ _pad(len(rest) - 8)
        else:
            s[0] ^= _load(rest) ^ _pad(len(rest))
        _permute(s, 8)

    s[4] ^= _DSEP  # domain separation, applied whether or not there was any AD
    return s, k0, k1


def _aead_finalise(s: list[int], k0: int, k1: int) -> bytes:
    s[2] ^= k0
    s[3] ^= k1
    _permute(s, 12)
    return _store(s[3] ^ k0) + _store(s[4] ^ k1)


def aead128_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                    ad: bytes = b"") -> tuple[bytes, bytes]:
    """Ascon-AEAD128 encryption.

    Returns ``(ciphertext, tag)``. ``len(ciphertext) == len(plaintext)`` and
    ``len(tag) == 16``.

    The nonce must never be reused with the same key.
    """
    s, k0, k1 = _aead_init(key, nonce, ad)

    out = bytearray()
    off = 0
    while len(plaintext) - off >= _AEAD_RATE:
        s[0] ^= _load(plaintext[off:off + 8])
        s[1] ^= _load(plaintext[off + 8:off + 16])
        out += _store(s[0]) + _store(s[1])
        _permute(s, 8)
        off += _AEAD_RATE

    # final partial block (0..15 bytes) -- always present, carries the padding
    rest = plaintext[off:]
    if len(rest) >= 8:
        s[0] ^= _load(rest[0:8])
        out += _store(s[0])
        tail = rest[8:]
        s[1] ^= _load(tail) ^ _pad(len(tail))
        if tail:
            out += _store(s[1], len(tail))
    else:
        s[0] ^= _load(rest) ^ _pad(len(rest))
        if rest:
            out += _store(s[0], len(rest))

    return bytes(out), _aead_finalise(s, k0, k1)


def aead128_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
                    ad: bytes = b"") -> bytes:
    """Ascon-AEAD128 decryption with tag verification.

    Returns the plaintext, or raises :class:`AsconTagError` if the tag does not
    verify. Nothing is returned on failure -- unauthenticated plaintext must
    never escape.
    """
    if len(tag) != ASCON_TAG_BYTES:
        raise ValueError(f"tag must be {ASCON_TAG_BYTES} bytes, got {len(tag)}")

    s, k0, k1 = _aead_init(key, nonce, ad)

    out = bytearray()
    off = 0
    while len(ciphertext) - off >= _AEAD_RATE:
        c0 = _load(ciphertext[off:off + 8])
        c1 = _load(ciphertext[off + 8:off + 16])
        out += _store(s[0] ^ c0) + _store(s[1] ^ c1)
        s[0], s[1] = c0, c1
        _permute(s, 8)
        off += _AEAD_RATE

    rest = ciphertext[off:]
    if len(rest) >= 8:
        c0 = _load(rest[0:8])
        out += _store(s[0] ^ c0)
        s[0] = c0
        tail = rest[8:]
        if tail:
            ct = _load(tail)
            m = s[1] ^ ct
            out += _store(m, len(tail))
            # replace the low len(tail) bytes of the state with the ciphertext
            s[1] = (m & ~((1 << (8 * len(tail))) - 1)) ^ ct
        s[1] ^= _pad(len(tail))
    else:
        if rest:
            ct = _load(rest)
            m = s[0] ^ ct
            out += _store(m, len(rest))
            s[0] = (m & ~((1 << (8 * len(rest))) - 1)) ^ ct
        s[0] ^= _pad(len(rest))

    if not hmac.compare_digest(_aead_finalise(s, k0, k1), tag):
        raise AsconTagError("Ascon-AEAD128 tag verification failed")
    return bytes(out)
