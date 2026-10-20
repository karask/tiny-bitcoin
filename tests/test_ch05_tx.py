"""Chapter 5 · Transactions."""

from io import BytesIO

import pytest
from vectors import (
    BLOCK9_COINBASE_TXID,
    GENESIS_MERKLE_ROOT,
    HAL_PUBKEY_HEX,
    SATOSHI_PUBKEY_HEX,
    SATOSHI_TO_HAL_TX_HEX,
    SATOSHI_TO_HAL_TXID,
)

from tinybitcoin.encoding import hex_to_hash
from tinybitcoin.params import COIN, GENESIS_COINBASE_HEX
from tinybitcoin.tx import NULL_OUTPOINT, OutPoint, Tx, TxIn, TxOut


def parse_tx(hex_string: str) -> Tx:
    return Tx.parse(BytesIO(bytes.fromhex(hex_string)))


def test_outpoint_round_trip():
    outpoint = OutPoint(bytes(range(32)), 7)
    assert outpoint.serialize() == bytes(range(32)) + bytes.fromhex("07000000")
    assert OutPoint.parse(BytesIO(outpoint.serialize())) == outpoint


def test_txin_round_trip():
    txin = TxIn(OutPoint(bytes(32), 1), b"\x01\x02", 0xFFFFFFFE)
    assert txin.serialize().hex() == "00" * 32 + "01000000" + "02" + "0102" + "feffffff"
    assert TxIn.parse(BytesIO(txin.serialize())) == txin


def test_txout_round_trip():
    out = TxOut(50 * COIN, bytes.fromhex("51"))
    assert out.serialize().hex() == "00f2052a01000000" + "01" + "51"
    assert TxOut.parse(BytesIO(out.serialize())) == out


def test_parse_the_genesis_coinbase():
    tx = parse_tx(GENESIS_COINBASE_HEX)
    assert tx.version == 1 and tx.locktime == 0
    assert tx.is_coinbase()
    assert tx.inputs[0].prevout == NULL_OUTPOINT
    headline = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    assert headline in tx.inputs[0].script_sig
    assert [out.amount for out in tx.outputs] == [50 * COIN]
    assert tx.serialize().hex() == GENESIS_COINBASE_HEX
    assert tx.id() == GENESIS_MERKLE_ROOT  # block 0 has just this one transaction


def test_checkpoint_parse_the_first_payment():
    """Checkpoint: decode Satoshi's 10 BTC payment to Hal Finney and recompute its txid."""
    tx = parse_tx(SATOSHI_TO_HAL_TX_HEX)
    assert not tx.is_coinbase()
    assert len(tx.inputs) == 1
    assert tx.inputs[0].prevout == OutPoint(hex_to_hash(BLOCK9_COINBASE_TXID), 0)
    assert [out.amount for out in tx.outputs] == [10 * COIN, 40 * COIN]  # payment, change
    assert HAL_PUBKEY_HEX in tx.outputs[0].script_pubkey.hex()
    assert SATOSHI_PUBKEY_HEX in tx.outputs[1].script_pubkey.hex()
    assert tx.serialize().hex() == SATOSHI_TO_HAL_TX_HEX
    assert tx.id() == SATOSHI_TO_HAL_TXID


def test_any_change_changes_the_txid():
    tx = parse_tx(SATOSHI_TO_HAL_TX_HEX)
    tx.outputs[0].amount -= 1
    assert tx.id() != SATOSHI_TO_HAL_TXID


def test_coinbase_detection():
    spend = Tx(1, [TxIn(OutPoint(bytes(32), 0))], [TxOut(1, b"")])
    assert not spend.is_coinbase()  # index 0, not 0xffffffff
    two_inputs = Tx(1, [TxIn(NULL_OUTPOINT), TxIn(NULL_OUTPOINT)], [TxOut(1, b"")])
    assert not two_inputs.is_coinbase()


def test_segwit_transactions_are_rejected_with_a_clear_error():
    segwit_start = bytes.fromhex("02000000" + "0001" + "01" + "00" * 41)
    with pytest.raises(ValueError, match="(?i)segwit"):
        Tx.parse(BytesIO(segwit_start))
