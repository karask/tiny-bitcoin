"""Chapter 2 · Block headers and proof-of-work."""

from dataclasses import replace
from io import BytesIO

import pytest
from vectors import GENESIS_HASH, GENESIS_HEADER_HEX, GENESIS_MERKLE_ROOT

from tinybitcoin.encoding import hex_to_hash
from tinybitcoin.header import (
    BlockHeader,
    bits_to_target,
    block_work,
    check_pow,
    mine,
    target_to_bits,
)
from tinybitcoin.params import MAINNET, TINY


def genesis_header() -> BlockHeader:
    return BlockHeader.parse(BytesIO(bytes.fromhex(GENESIS_HEADER_HEX)))


def test_parse_genesis_header():
    header = genesis_header()
    assert header.version == 1
    assert header.prev_block == bytes(32)
    assert header.merkle_root == hex_to_hash(GENESIS_MERKLE_ROOT)
    assert header.time == 1231006505
    assert header.bits == 0x1D00FFFF
    assert header.nonce == 2083236893


def test_serialize_round_trip():
    assert genesis_header().serialize().hex() == GENESIS_HEADER_HEX


def test_checkpoint_build_the_genesis_header_from_its_fields():
    """Checkpoint: rebuild Satoshi's header field by field and get the famous hash."""
    header = BlockHeader(
        version=1,
        prev_block=bytes(32),
        merkle_root=hex_to_hash(GENESIS_MERKLE_ROOT),
        time=1231006505,
        bits=0x1D00FFFF,
        nonce=2083236893,
    )
    assert header.id() == GENESIS_HASH


def test_bits_to_target():
    assert bits_to_target(0x1D00FFFF) == 0xFFFF * 256**26
    assert bits_to_target(0x1D00FFFF) == int("00000000ffff" + "00" * 26, 16)


# The compact-encoding cases from Bitcoin Core's arith_uint256 tests.
@pytest.mark.parametrize(
    "bits, target, canonical_bits",
    [
        (0x01003456, 0x00, 0x00000000),
        (0x01123456, 0x12, 0x01120000),
        (0x02123456, 0x1234, 0x02123400),
        (0x03123456, 0x123456, 0x03123456),
        (0x04123456, 0x12345600, 0x04123456),
        (0x05009234, 0x92340000, 0x05009234),
        (0x20123456, 0x123456 << (8 * 29), 0x20123456),
    ],
)
def test_compact_encoding(bits, target, canonical_bits):
    assert bits_to_target(bits) == target
    assert target_to_bits(target) == canonical_bits


@pytest.mark.parametrize("bits", [0x04923456, 0x01FEDCBA])
def test_negative_targets_are_invalid(bits):
    with pytest.raises(ValueError):
        bits_to_target(bits)


def test_genesis_has_valid_proof_of_work():
    assert check_pow(genesis_header(), MAINNET.pow_limit)


def test_pow_fails_if_anything_changes():
    assert not check_pow(replace(genesis_header(), nonce=0), MAINNET.pow_limit)
    assert not check_pow(replace(genesis_header(), time=1231006506), MAINNET.pow_limit)


def test_target_must_not_be_easier_than_the_limit():
    easy = mine(replace(genesis_header(), bits=0x207FFFFF, nonce=0))
    assert check_pow(easy, TINY.pow_limit)
    assert not check_pow(easy, MAINNET.pow_limit)


def test_block_work():
    # Bitcoin Core reports the genesis block's "chainwork" as 0x100010001.
    assert block_work(0x1D00FFFF) == 0x100010001
    assert block_work(0x207FFFFF) == 2


def test_mine_finds_a_valid_nonce():
    header = BlockHeader(1, bytes(32), bytes(32), 1700000000, 0x1F00FFFF, 0)
    mined = mine(header)
    assert mined is not None
    assert check_pow(mined, TINY.pow_limit)
    assert mined.nonce >= header.nonce
    assert header.nonce == 0, "mine() must return a copy, not modify its argument"


def test_mine_gives_up_after_max_nonce():
    header = BlockHeader(1, bytes(32), bytes(32), 1700000000, 0x1D00FFFF, 0)
    assert mine(header, max_nonce=1000) is None
