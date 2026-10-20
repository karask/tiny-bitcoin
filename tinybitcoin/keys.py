"""Chapter 4 · Keys, addresses and their encodings.

Chapter 3 gave us numbers and points. To put them inside transactions,
Bitcoin uses standard byte encodings:

* SEC for public keys (33 bytes compressed, 65 uncompressed),
* DER for signatures (about 71 bytes),
* Base58Check for addresses, which humans copy and paste. The checksum
  catches typos.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from functools import cached_property

from .ecc import G, N, P, Point, Signature, sign
from .hashing import hash160, sha256, sha256d

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode_sec(point: Point, compressed: bool = True) -> bytes:
    """SEC 1 encoding of a public key.

    uncompressed:  0x04 | x (32 bytes, big-endian) | y (32 bytes, big-endian)
    compressed:    0x02 if y is even, else 0x03 | x (32 bytes, big-endian)
    """
    # BEGIN SOLUTION ch04
    x = point.x.to_bytes(32, "big")
    if not compressed:
        return b"\x04" + x + point.y.to_bytes(32, "big")
    return (b"\x02" if point.y % 2 == 0 else b"\x03") + x
    # END SOLUTION


def decode_sec(data: bytes) -> Point:
    """Decode a SEC public key. Raise ValueError if it is malformed.

    For a compressed key, reject x >= P, then recover y from y² = x³ + 7
    (mod P). Because P % 4 == 3, a square root of a is pow(a, (P + 1) // 4, P).
    If its parity does not match the prefix, use P - y instead. Point()
    raises ValueError if x was not on the curve.
    """
    # BEGIN SOLUTION ch04
    if len(data) == 65 and data[0] == 0x04:
        return Point(int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big"))
    if len(data) == 33 and data[0] in (0x02, 0x03):
        x = int.from_bytes(data[1:], "big")
        if x >= P:
            raise ValueError("x out of range")
        y = pow((x**3 + 7) % P, (P + 1) // 4, P)
        if y % 2 != data[0] % 2:
            y = P - y
        return Point(x, y)
    raise ValueError("not a SEC-encoded public key")
    # END SOLUTION


def encode_der(sig: Signature) -> bytes:
    """DER encoding of a signature:

        0x30 <length of the rest>
        0x02 <length of r> <r as big-endian bytes>
        0x02 <length of s> <s as big-endian bytes>

    DER integers are signed. Strip leading zero bytes, then if the first
    remaining byte is >= 0x80, put one 0x00 back so the number is positive.
    """
    # BEGIN SOLUTION ch04
    def der_int(n: int) -> bytes:
        b = n.to_bytes(32, "big").lstrip(b"\x00")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    body = der_int(sig.r) + der_int(sig.s)
    return b"\x30" + bytes([len(body)]) + body
    # END SOLUTION


def decode_der(data: bytes) -> Signature:
    """Parse a strict-DER signature (BIP 66), raising ValueError otherwise (provided)."""
    if len(data) < 8 or data[0] != 0x30 or data[1] != len(data) - 2:
        raise ValueError("bad DER signature")

    def read_int(pos: int) -> tuple[int, int]:
        if pos + 2 > len(data) or data[pos] != 0x02:
            raise ValueError("bad DER integer")
        length = data[pos + 1]
        value = data[pos + 2 : pos + 2 + length]
        if length == 0 or len(value) != length:
            raise ValueError("bad DER integer length")
        if value[0] & 0x80:
            raise ValueError("negative DER integer")
        if length > 1 and value[0] == 0 and not value[1] & 0x80:
            raise ValueError("DER integer has excess padding")
        return int.from_bytes(value, "big"), pos + 2 + length

    r, pos = read_int(2)
    s, pos = read_int(pos)
    if pos != len(data):
        raise ValueError("trailing bytes after DER signature")
    return Signature(r, s)


def base58_encode(data: bytes) -> str:
    """Base58: write the bytes as one big-endian number in base 58.

    Use BASE58_ALPHABET, which drops 0, O, I and l so they cannot be confused.
    Each leading zero *byte* becomes a leading "1", otherwise it would vanish.
    """
    # BEGIN SOLUTION ch04
    n = int.from_bytes(data, "big")
    digits = ""
    while n:
        n, remainder = divmod(n, 58)
        digits = BASE58_ALPHABET[remainder] + digits
    zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * zeros + digits
    # END SOLUTION


def base58_decode(text: str) -> bytes:
    """Inverse of base58_encode (provided)."""
    n = 0
    for char in text:
        if char not in BASE58_ALPHABET:
            raise ValueError(f"invalid Base58 character {char!r}")
        n = n * 58 + BASE58_ALPHABET.index(char)
    zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * zeros + n.to_bytes((n.bit_length() + 7) // 8, "big")


def base58check_encode(payload: bytes) -> str:
    """Append the first 4 bytes of sha256d(payload) as a checksum, then Base58."""
    # BEGIN SOLUTION ch04
    return base58_encode(payload + sha256d(payload)[:4])
    # END SOLUTION


def base58check_decode(text: str) -> bytes:
    """Decode Base58Check and return the payload. Raise ValueError on a bad checksum."""
    # BEGIN SOLUTION ch04
    raw = base58_decode(text)
    if len(raw) < 5:
        raise ValueError("Base58Check string too short")
    payload, checksum = raw[:-4], raw[-4:]
    if sha256d(payload)[:4] != checksum:
        raise ValueError("bad Base58Check checksum")
    return payload
    # END SOLUTION


def p2pkh_address(public_key: bytes, prefix: int) -> str:
    """The pay-to-public-key-hash address of a SEC-encoded public key.

    Base58Check of: one version byte (`prefix`: 0x00 on mainnet, 0x6f on
    testnet/regtest/TINY) followed by HASH160(public key).
    """
    # BEGIN SOLUTION ch04
    return base58check_encode(bytes([prefix]) + hash160(public_key))
    # END SOLUTION


def address_to_pubkey_hash(address: str, prefix: int) -> bytes:
    """Return the 20-byte HASH160 inside a P2PKH address (provided)."""
    payload = base58check_decode(address)
    if len(payload) != 21 or payload[0] != prefix:
        raise ValueError(f"not a P2PKH address for version byte {prefix:#04x}")
    return payload[1:]


@dataclass(frozen=True)
class PrivateKey:
    """A private key (provided). The secret is just a number in [1, N)."""

    secret: int
    compressed: bool = True

    def __post_init__(self) -> None:
        if not 1 <= self.secret < N:
            raise ValueError("private key out of range")

    @classmethod
    def generate(cls) -> PrivateKey:
        """A fresh key from the operating system's secure random number generator."""
        return cls(secrets.randbelow(N - 1) + 1)

    @classmethod
    def from_passphrase(cls, passphrase: str) -> PrivateKey:
        """A *brain wallet*: the key is a hash of the passphrase.

        Handy for reproducible tests. Never use one for real money: people
        run bots that hash dictionaries of phrases and sweep the coins.
        """
        return cls(int.from_bytes(sha256(passphrase.encode()), "big") % (N - 1) + 1)

    @cached_property
    def point(self) -> Point:
        return self.secret * G

    def sec(self) -> bytes:
        return encode_sec(self.point, self.compressed)

    def sign(self, z: int) -> Signature:
        return sign(self.secret, z)

    def address(self, prefix: int) -> str:
        return p2pkh_address(self.sec(), prefix)
