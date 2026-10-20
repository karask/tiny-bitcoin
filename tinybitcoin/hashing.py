"""Chapter 1 · Hash functions.

Bitcoin uses two compositions of standard hash functions:

* HASH256 = SHA-256(SHA-256(x)), "sha256d": block hashes, txids, Merkle trees,
  checksums.
* HASH160 = RIPEMD-160(SHA-256(x)): the short 20-byte public-key hashes inside
  addresses.
"""

from __future__ import annotations

import hashlib

from . import ripemd160 as _ripemd160


def sha256(data: bytes) -> bytes:
    """Single SHA-256 (provided)."""
    return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    """RIPEMD-160 (provided). Falls back to pure Python where OpenSSL lacks it."""
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return _ripemd160.ripemd160(data)


def sha256d(data: bytes) -> bytes:
    """HASH256: SHA-256 applied twice."""
    # BEGIN SOLUTION ch01
    return sha256(sha256(data))
    # END SOLUTION


def hash160(data: bytes) -> bytes:
    """HASH160: RIPEMD-160 of the SHA-256 of `data` (20 bytes)."""
    # BEGIN SOLUTION ch01
    return ripemd160(sha256(data))
    # END SOLUTION
