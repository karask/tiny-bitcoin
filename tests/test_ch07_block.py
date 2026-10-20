"""Chapter 7 · Blocks, Merkle trees and context-free validation."""

from dataclasses import replace
from io import BytesIO

import pytest
from vectors import (
    BLOCK170_BITS,
    BLOCK170_COINBASE_TXID,
    BLOCK170_HASH,
    BLOCK170_MERKLE_ROOT,
    BLOCK170_NONCE,
    BLOCK170_PREV_HASH,
    BLOCK170_TIME,
    GENESIS_HASH,
    GENESIS_HEADER_HEX,
    REGTEST_GENESIS_HASH,
    SATOSHI_TO_HAL_TXID,
)

from tinybitcoin.block import Block, ValidationError, check_block, check_transaction, merkle_root
from tinybitcoin.encoding import hash_to_hex, hex_to_hash
from tinybitcoin.hashing import sha256d
from tinybitcoin.header import BlockHeader, check_pow, mine
from tinybitcoin.params import COIN, GENESIS_COINBASE_HEX, MAINNET, MAX_MONEY, TINY
from tinybitcoin.tx import NULL_OUTPOINT, OutPoint, Tx, TxIn, TxOut

GENESIS_BLOCK_HEX = GENESIS_HEADER_HEX + "01" + GENESIS_COINBASE_HEX


def coinbase(tag: bytes = b"\x01\x02") -> Tx:
    return Tx(1, [TxIn(NULL_OUTPOINT, tag)], [TxOut(50 * COIN, b"\x51")])


def spend(n: int) -> Tx:
    return Tx(1, [TxIn(OutPoint(bytes([n]) * 32, 0))], [TxOut(n, b"\x51")])


def tiny_block(txs: list[Tx], root: bytes | None = None) -> Block:
    """A block with valid proof-of-work on the TINY chain."""
    if root is None:
        root = merkle_root([tx.hash() for tx in txs]) if txs else bytes(32)
    header = mine(BlockHeader(1, bytes(32), root, 1296688700, TINY.genesis_bits, 0))
    return Block(header, txs)


def test_parse_the_genesis_block():
    block = Block.parse(BytesIO(bytes.fromhex(GENESIS_BLOCK_HEX)))
    assert block.id() == GENESIS_HASH
    assert len(block.txs) == 1 and block.txs[0].is_coinbase()
    assert block.serialize().hex() == GENESIS_BLOCK_HEX


def test_params_build_both_genesis_blocks():
    assert MAINNET.genesis_block().id() == GENESIS_HASH
    assert TINY.genesis_block().id() == REGTEST_GENESIS_HASH


def test_merkle_root_of_one_transaction_is_its_txid():
    txid = hex_to_hash(SATOSHI_TO_HAL_TXID)
    assert merkle_root([txid]) == txid


def test_merkle_root_duplicates_the_last_hash_on_odd_levels():
    a, b, c = (sha256d(bytes([i])) for i in range(3))
    expected = sha256d(sha256d(a + b) + sha256d(c + c))
    assert merkle_root([a, b, c]) == expected
    assert merkle_root([a, b, c, c]) == expected  # CVE-2012-2459: same root, more txs


def test_checkpoint_rebuild_block_170():
    """Checkpoint: rebuild block 170's Merkle root and header, and check its proof-of-work."""
    txids = [hex_to_hash(BLOCK170_COINBASE_TXID), hex_to_hash(SATOSHI_TO_HAL_TXID)]
    root = merkle_root(txids)
    assert hash_to_hex(root) == BLOCK170_MERKLE_ROOT
    header = BlockHeader(
        1, hex_to_hash(BLOCK170_PREV_HASH), root, BLOCK170_TIME, BLOCK170_BITS, BLOCK170_NONCE
    )
    assert header.id() == BLOCK170_HASH
    assert check_pow(header, MAINNET.pow_limit)


def test_check_block_accepts_the_genesis_blocks():
    check_block(MAINNET.genesis_block(), MAINNET)
    check_block(TINY.genesis_block(), TINY)


def test_check_block_accepts_a_good_block():
    check_block(tiny_block([coinbase(), spend(1), spend(2)]), TINY)


def assert_rejected(block: Block, reason: str) -> None:
    with pytest.raises(ValidationError) as error:
        check_block(block, TINY)
    assert error.value.reason == reason


def test_check_block_rejections():
    good = tiny_block([coinbase(), spend(1)])
    unmined = replace(good.header, nonce=good.header.nonce + 1)
    while check_pow(unmined, TINY.pow_limit):
        unmined = replace(unmined, nonce=unmined.nonce + 1)
    assert_rejected(Block(unmined, good.txs), "high-hash")
    assert_rejected(tiny_block([]), "bad-blk-length")
    assert_rejected(tiny_block([coinbase(), spend(1)], root=sha256d(b"lies")), "bad-txnmrklroot")
    assert_rejected(tiny_block([spend(1), spend(2)]), "bad-cb-missing")
    assert_rejected(tiny_block([coinbase(), coinbase(b"\x03\x04")]), "bad-cb-multiple")


def test_break_it_a_mutated_block_is_rejected():
    txs = [coinbase(), spend(1), spend(2)]
    root = merkle_root([tx.hash() for tx in txs])
    mutated = tiny_block(txs + [spend(2)], root=root)  # same root, one more transaction
    assert_rejected(mutated, "bad-txns-duplicate")


@pytest.mark.parametrize(
    "tx, reason",
    [
        (Tx(1, [], [TxOut(1, b"")]), "bad-txns-vin-empty"),
        (Tx(1, [TxIn(OutPoint(b"\x01" * 32, 0))], []), "bad-txns-vout-empty"),
        (Tx(1, [TxIn(OutPoint(b"\x01" * 32, 0))], [TxOut(-1, b"")]), "bad-txns-vout-negative"),
        (
            Tx(1, [TxIn(OutPoint(b"\x01" * 32, 0))], [TxOut(MAX_MONEY + 1, b"")]),
            "bad-txns-vout-toolarge",
        ),
        (
            Tx(1, [TxIn(OutPoint(b"\x01" * 32, 0))], [TxOut(MAX_MONEY, b""), TxOut(1, b"")]),
            "bad-txns-txouttotal-toolarge",
        ),
        (
            Tx(1, [TxIn(OutPoint(b"\x01" * 32, 0))] * 2, [TxOut(1, b"")]),
            "bad-txns-inputs-duplicate",
        ),
        (Tx(1, [TxIn(NULL_OUTPOINT, b"\x01")], [TxOut(1, b"")]), "bad-cb-length"),
        (Tx(1, [TxIn(NULL_OUTPOINT, bytes(101))], [TxOut(1, b"")]), "bad-cb-length"),
        (
            Tx(1, [TxIn(OutPoint(b"\x01" * 32, 0)), TxIn(NULL_OUTPOINT)], [TxOut(1, b"")]),
            "bad-txns-prevout-null",
        ),
        (
            Tx(1, [TxIn(OutPoint(b"\x01" * 32, 0))], [TxOut(1, bytes(1_000_000))]),
            "bad-txns-oversize",
        ),
    ],
)
def test_check_transaction_rejections(tx, reason):
    with pytest.raises(ValidationError) as error:
        check_transaction(tx)
    assert error.value.reason == reason


def test_break_it_the_value_overflow_incident():
    # Block 74638 (August 2010) contained a transaction with two outputs of
    # 92,233,720,368.54277039 BTC each. Their sum overflowed a 64-bit integer.
    overflow = 9_223_372_036_854_277_039
    tx = Tx(1, [TxIn(OutPoint(b"\x01" * 32, 0))], [TxOut(overflow, b""), TxOut(overflow, b"")])
    with pytest.raises(ValidationError):
        check_transaction(tx)
