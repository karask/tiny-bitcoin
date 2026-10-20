"""Chapter 2 · Block headers and proof-of-work (plus chapter 9's difficulty adjustment).

A block header is 80 bytes. For the block to be valid, the header's hash,
read as a number, must not exceed the *target*. The only known way to find
such a header is to keep changing the nonce and hashing again. That is
proof-of-work. The header stores the target in a compact form called `bits`.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, BinaryIO

from .encoding import hash_to_hex, int_to_little_endian, little_endian_to_int, read_exact
from .hashing import sha256d

if TYPE_CHECKING:
    from .params import ChainParams


@dataclass
class BlockHeader:
    version: int
    prev_block: bytes  # hash of the previous block's header (internal byte order)
    merkle_root: bytes  # commits to every transaction in the block (chapter 7)
    time: int  # Unix time, as claimed by the miner
    bits: int  # the target, in compact form
    nonce: int  # the number miners change while searching

    def serialize(self) -> bytes:
        """Return the 80-byte header:

        version       4 bytes, little-endian
        prev_block   32 bytes, as stored
        merkle_root  32 bytes, as stored
        time          4 bytes, little-endian
        bits          4 bytes, little-endian
        nonce         4 bytes, little-endian
        """
        # BEGIN SOLUTION ch02
        return (
            int_to_little_endian(self.version, 4)
            + self.prev_block
            + self.merkle_root
            + int_to_little_endian(self.time, 4)
            + int_to_little_endian(self.bits, 4)
            + int_to_little_endian(self.nonce, 4)
        )
        # END SOLUTION

    @classmethod
    def parse(cls, s: BinaryIO) -> BlockHeader:
        """Read an 80-byte header from the stream `s` (the inverse of serialize)."""
        # BEGIN SOLUTION ch02
        return cls(
            version=little_endian_to_int(read_exact(s, 4)),
            prev_block=read_exact(s, 32),
            merkle_root=read_exact(s, 32),
            time=little_endian_to_int(read_exact(s, 4)),
            bits=little_endian_to_int(read_exact(s, 4)),
            nonce=little_endian_to_int(read_exact(s, 4)),
        )
        # END SOLUTION

    def hash(self) -> bytes:
        """The block hash: sha256d of the serialized header (internal byte order)."""
        # BEGIN SOLUTION ch02
        return sha256d(self.serialize())
        # END SOLUTION

    def id(self) -> str:
        """The block hash as humans see it (provided)."""
        return hash_to_hex(self.hash())


def bits_to_target(bits: int) -> int:
    """Expand the compact `bits` into the full 256-bit target.

    bits = 0xEEMMMMMM is a 1-byte exponent E and a 3-byte mantissa M:

        target = M * 256**(E - 3)      (if E < 3, shift M right instead)

    The format comes from OpenSSL, where 0x00800000 is a sign bit. If it is
    set, raise ValueError, because a target cannot be negative.
    Example: bits_to_target(0x1d00ffff) == 0xffff * 256**26
    """
    # BEGIN SOLUTION ch02
    if bits & 0x00800000:
        raise ValueError("negative target")
    exponent, mantissa = bits >> 24, bits & 0x007FFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))
    # END SOLUTION


def target_to_bits(target: int) -> int:
    """Compress a target into `bits`. This drops low-order precision.

    Use the number of bytes the target needs as the exponent and its top 3
    bytes as the mantissa. If the mantissa's top bit is set, the number would
    look negative: shift the mantissa right one byte and add 1 to the exponent.
    """
    # BEGIN SOLUTION ch02
    size = (target.bit_length() + 7) // 8
    if size <= 3:
        mantissa = target << (8 * (3 - size))
    else:
        mantissa = target >> (8 * (size - 3))
    if mantissa & 0x00800000:
        mantissa >>= 8
        size += 1
    return (size << 24) | mantissa
    # END SOLUTION


def check_pow(header: BlockHeader, pow_limit: int) -> bool:
    """Does `header` carry valid proof-of-work?

    Its target (decoded from `bits`) must be positive and no easier than
    `pow_limit`. Its hash, read as a little-endian number, must not exceed
    the target.
    """
    # BEGIN SOLUTION ch02
    try:
        target = bits_to_target(header.bits)
    except ValueError:
        return False
    if not 0 < target <= pow_limit:
        return False
    return little_endian_to_int(header.hash()) <= target
    # END SOLUTION


def block_work(bits: int) -> int:
    """The expected number of hashes needed to find a block at this target.

    A random hash is <= target with probability (target + 1) / 2**256, so the
    expected work is 2**256 // (target + 1). The best chain is the one with
    the most total work, not the one with the most blocks (chapter 9).
    """
    # BEGIN SOLUTION ch02
    return 2**256 // (bits_to_target(bits) + 1)
    # END SOLUTION


def mine(header: BlockHeader, max_nonce: int = 2**32) -> BlockHeader | None:
    """Try nonces from header.nonce up to (not including) max_nonce.

    Return a copy of the header (use dataclasses.replace) with the first nonce
    that gives valid proof-of-work, or None if there is none in range.
    Hint: only the last 4 bytes change, so serialize the first 76 bytes once.
    """
    # BEGIN SOLUTION ch02
    target = bits_to_target(header.bits)
    prefix = header.serialize()[:76]
    for nonce in range(header.nonce, max_nonce):
        if little_endian_to_int(sha256d(prefix + int_to_little_endian(nonce, 4))) <= target:
            return replace(header, nonce=nonce)
    return None
    # END SOLUTION


def retarget(bits: int, actual_timespan: int, params: ChainParams) -> int:
    """Chapter 9 · The difficulty adjustment (Bitcoin Core's CalculateNextWorkRequired).

    Every `params.retarget_interval` blocks the target is rescaled so blocks
    keep arriving every `params.target_spacing` seconds on average:

        new_target = old_target * actual_timespan // params.target_timespan

    `actual_timespan` is how long the last period took. First clamp it to
    [target_timespan // 4, target_timespan * 4], so difficulty changes at
    most 4x per period. Never return a target easier than params.pow_limit.
    """
    # BEGIN SOLUTION ch09
    expected = params.target_timespan
    actual = min(max(actual_timespan, expected // 4), expected * 4)
    target = bits_to_target(bits) * actual // expected
    return target_to_bits(min(target, params.pow_limit))
    # END SOLUTION
