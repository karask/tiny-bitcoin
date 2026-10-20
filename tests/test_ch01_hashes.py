"""Chapter 1 · Bytes and hashes."""

from io import BytesIO

import pytest
from vectors import GENESIS_HASH, GENESIS_HEADER_HEX

from tinybitcoin.encoding import (
    encode_varint,
    hash_to_hex,
    hex_to_hash,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from tinybitcoin.hashing import hash160, sha256d


def test_little_endian():
    assert int_to_little_endian(1, 4) == bytes.fromhex("01000000")
    assert int_to_little_endian(0x12345678, 4) == bytes.fromhex("78563412")
    assert int_to_little_endian(500, 8) == bytes.fromhex("f401000000000000")
    assert little_endian_to_int(bytes.fromhex("78563412")) == 0x12345678
    assert little_endian_to_int(int_to_little_endian(2**63 + 5, 8)) == 2**63 + 5


@pytest.mark.parametrize(
    "n, encoded",
    [
        (0, "00"),
        (0xFC, "fc"),
        (0xFD, "fdfd00"),
        (0xFFFF, "fdffff"),
        (0x10000, "fe00000100"),
        (0xFFFFFFFF, "feffffffff"),
        (0x100000000, "ff0000000001000000"),
    ],
)
def test_varint(n, encoded):
    assert encode_varint(n).hex() == encoded
    assert read_varint(BytesIO(bytes.fromhex(encoded))) == n


@pytest.mark.parametrize("encoded", ["fd0100", "fdfc00", "feffff0000", "ffffffffff00000000"])
def test_varint_rejects_non_canonical(encoded):
    with pytest.raises(ValueError):
        read_varint(BytesIO(bytes.fromhex(encoded)))


def test_varint_rejects_truncated_input():
    with pytest.raises(ValueError):
        read_varint(BytesIO(bytes.fromhex("fd01")))


def test_sha256d():
    assert (
        sha256d(b"").hex() == "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
    )
    assert (
        sha256d(b"hello").hex()
        == "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
    )


def test_hash160():
    # The compressed public key of private key 1 (you will derive it in chapter 4).
    pubkey = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    assert hash160(pubkey).hex() == "751e76e8199196d454941c45d1b3a323f1433bd6"


def test_hashes_are_displayed_reversed():
    h = bytes(range(32))
    assert hash_to_hex(h) == h[::-1].hex()
    assert hex_to_hash(hash_to_hex(h)) == h


def test_checkpoint_hash_the_genesis_block():
    """Checkpoint: you can compute the hash of Bitcoin's first block."""
    header = bytes.fromhex(GENESIS_HEADER_HEX)
    assert len(header) == 80
    assert hash_to_hex(sha256d(header)) == GENESIS_HASH
