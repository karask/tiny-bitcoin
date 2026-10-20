"""Helpers shared by the tests from chapter 8 on."""

from __future__ import annotations

from dataclasses import replace

import pytest

from tinybitcoin.block import Block, ValidationError, merkle_root
from tinybitcoin.chain import BlockIndex, Chain
from tinybitcoin.hashing import hash160
from tinybitcoin.header import mine
from tinybitcoin.keys import PrivateKey
from tinybitcoin.miner import build_block
from tinybitcoin.params import TINY, ChainParams
from tinybitcoin.script import p2pkh_script, sign_p2pkh
from tinybitcoin.tx import OutPoint, Tx, TxIn, TxOut

ALICE = PrivateKey.from_passphrase("alice")
BOB = PrivateKey.from_passphrase("bob")
CAROL = PrivateKey.from_passphrase("carol")
MINER = PrivateKey.from_passphrase("miner")


def lock(key: PrivateKey) -> bytes:
    """The P2PKH scriptPubKey that only `key` can unlock."""
    return p2pkh_script(hash160(key.sec()))


def mine_blocks(
    chain: Chain,
    n: int,
    script_pubkey: bytes | None = None,
    parent: BlockIndex | None = None,
    extra: bytes = b"",
) -> list[Block]:
    """Mine `n` empty blocks on `parent` (default: the tip) and add them to the chain."""
    blocks = []
    for _ in range(n):
        block = build_block(chain, [], script_pubkey or lock(MINER), parent=parent, extra=extra)
        chain.add_block(block)
        blocks.append(block)
        parent = chain.index[block.hash()] if parent is not None else None
    return blocks


def coinbase_outpoint(block: Block) -> OutPoint:
    return OutPoint(block.txs[0].hash(), 0)


def spend(chain: Chain, key: PrivateKey, outpoint: OutPoint, outputs: list[tuple[bytes, int]],
          coin_script: bytes | None = None) -> Tx:
    """A signed transaction spending one P2PKH coin of `key` to (script_pubkey, amount) outputs."""
    script = coin_script or chain.utxos[outpoint].script_pubkey
    tx = Tx(1, [TxIn(outpoint)], [TxOut(amount, spk) for spk, amount in outputs])
    sign_p2pkh(tx, 0, key, script)
    return tx


def funded_chain(params: ChainParams = TINY) -> tuple[Chain, OutPoint]:
    """A chain on which ALICE owns one 50 BTC coinbase coin that is spendable in the next block."""
    chain = Chain(params)
    [first] = mine_blocks(chain, 1, lock(ALICE))
    mine_blocks(chain, params.coinbase_maturity - 1)
    return chain, coinbase_outpoint(first)


def rebuild(block: Block) -> Block:
    """Recompute the Merkle root and proof-of-work after editing a block's transactions."""
    root = merkle_root([tx.hash() for tx in block.txs])
    return Block(mine(replace(block.header, merkle_root=root, nonce=0)), block.txs)


def assert_invalid(chain: Chain, block: Block, reason: str) -> None:
    with pytest.raises(ValidationError) as error:
        chain.add_block(block)
    assert error.value.reason == reason
