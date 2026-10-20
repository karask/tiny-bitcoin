"""Chapter 1 · Bytes on the wire.

Everything in Bitcoin ends up as bytes: that is what gets hashed, signed and
sent between nodes. Two conventions trip up almost everyone:

* Integers are serialised **little-endian** (least significant byte first).
* Lengths and counts use a variable-length integer that Bitcoin Core calls
  *CompactSize* and everyone else calls a *varint*.

A third convention only affects humans: hashes are *displayed* byte-reversed.
"""

from __future__ import annotations

from typing import BinaryIO


def read_exact(s: BinaryIO, n: int) -> bytes:
    """Read exactly `n` bytes from the stream `s`, or raise ValueError (provided)."""
    data = s.read(n)
    if len(data) != n:
        raise ValueError(f"unexpected end of data: wanted {n} bytes, got {len(data)}")
    return data


def int_to_little_endian(n: int, length: int) -> bytes:
    """Encode the non-negative integer `n` as exactly `length` little-endian bytes.

    Example: int_to_little_endian(1, 4) == bytes.fromhex("01000000")
    """
    # BEGIN SOLUTION ch01
    return n.to_bytes(length, "little")
    # END SOLUTION


def little_endian_to_int(b: bytes) -> int:
    """Decode little-endian bytes into an integer (the inverse of the above)."""
    # BEGIN SOLUTION ch01
    return int.from_bytes(b, "little")
    # END SOLUTION


def encode_varint(n: int) -> bytes:
    """Encode `n` as a CompactSize ("varint").

        n < 0xfd            1 byte:  n itself
        n <= 0xffff         0xfd followed by n as 2 little-endian bytes
        n <= 0xffffffff     0xfe followed by n as 4 little-endian bytes
        otherwise           0xff followed by n as 8 little-endian bytes
    """
    # BEGIN SOLUTION ch01
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + int_to_little_endian(n, 2)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + int_to_little_endian(n, 4)
    return b"\xff" + int_to_little_endian(n, 8)
    # END SOLUTION


def read_varint(s: BinaryIO) -> int:
    """Read a CompactSize from the stream `s`.

    Use read_exact, so that truncated input raises ValueError. Also reject
    non-canonical encodings (for example 0xfd0100 for the number 1) with
    ValueError, like Bitcoin Core does. If two byte strings could mean the
    same transaction, they would hash to two different transaction ids.
    """
    # BEGIN SOLUTION ch01
    prefix = read_exact(s, 1)[0]
    if prefix == 0xFD:
        n, minimum = little_endian_to_int(read_exact(s, 2)), 0xFD
    elif prefix == 0xFE:
        n, minimum = little_endian_to_int(read_exact(s, 4)), 0x10000
    elif prefix == 0xFF:
        n, minimum = little_endian_to_int(read_exact(s, 8)), 0x100000000
    else:
        return prefix
    if n < minimum:
        raise ValueError("non-canonical varint")
    return n
    # END SOLUTION


def hash_to_hex(h: bytes) -> str:
    """Show a hash the way block explorers and Bitcoin Core do: byte-reversed hex.

    Internally (in headers, transactions and Merkle trees) hashes are used in
    the order SHA-256 produced them. For display, Bitcoin treats a hash as a
    little-endian 256-bit number and prints it most significant byte first.
    That is why block hashes *display* with leading zeros.
    """
    # BEGIN SOLUTION ch01
    return h[::-1].hex()
    # END SOLUTION


def hex_to_hash(s: str) -> bytes:
    """Inverse of hash_to_hex: turn a displayed hash back into internal byte order."""
    # BEGIN SOLUTION ch01
    return bytes.fromhex(s)[::-1]
    # END SOLUTION
