"""Chapter 7 · Blocks, Merkle trees and context-free validation.

A block is a header plus a list of transactions. The header commits to the
transactions through one 32-byte Merkle root. Change any transaction and the
root changes, so the proof-of-work no longer matches.

This chapter also starts *validation*: the checks that need nothing but the
block itself (Bitcoin Core's CheckBlock and CheckTransaction). Checks that
need the rest of the chain come in chapter 8.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO

from .encoding import encode_varint, read_varint
from .hashing import sha256d
from .header import BlockHeader, check_pow
from .params import MAX_BLOCK_SIZE, MAX_MONEY
from .tx import Tx

if TYPE_CHECKING:
    from .params import ChainParams


class ValidationError(Exception):
    """Raised when a block or transaction breaks a rule.

    `reason` is Bitcoin Core's reject reason where one exists, so you can
    search Core's source code for it.
    """

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason} ({detail})" if detail else reason)
        self.reason = reason


@dataclass
class Block:
    header: BlockHeader
    txs: list[Tx]

    def serialize(self) -> bytes:
        """header (80 bytes) | varint number of transactions | the transactions."""
        # BEGIN SOLUTION ch07
        return (
            self.header.serialize()
            + encode_varint(len(self.txs))
            + b"".join(tx.serialize() for tx in self.txs)
        )
        # END SOLUTION

    @classmethod
    def parse(cls, s: BinaryIO) -> Block:
        # BEGIN SOLUTION ch07
        header = BlockHeader.parse(s)
        return cls(header, [Tx.parse(s) for _ in range(read_varint(s))])
        # END SOLUTION

    def hash(self) -> bytes:
        return self.header.hash()

    def id(self) -> str:
        return self.header.id()


def merkle_root(hashes: list[bytes]) -> bytes:
    """Fold a list of txids (internal byte order) into a Merkle root.

    Repeat until one hash is left: if the level has an odd number of hashes,
    duplicate the last one; then replace each pair (a, b) by sha256d(a + b).
    A single hash is its own root.
    """
    # BEGIN SOLUTION ch07
    if not hashes:
        raise ValueError("a Merkle tree needs at least one leaf")
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]
    # END SOLUTION


def check_transaction(tx: Tx) -> None:
    """Context-free transaction checks (Bitcoin Core's CheckTransaction).

    Raise ValidationError(reason) for the first problem found:

    * no inputs:  "bad-txns-vin-empty";   no outputs:  "bad-txns-vout-empty"
    * an output amount < 0:  "bad-txns-vout-negative"
    * an output amount > MAX_MONEY:  "bad-txns-vout-toolarge"
    * running total of outputs > MAX_MONEY:  "bad-txns-txouttotal-toolarge"
    * serialized size > MAX_BLOCK_SIZE:  "bad-txns-oversize"
    * the same outpoint spent twice:  "bad-txns-inputs-duplicate"
    * coinbase scriptSig shorter than 2 or longer than 100 bytes:  "bad-cb-length"
    * a non-coinbase input spending the null outpoint:  "bad-txns-prevout-null"

    The amount checks were added after the "value overflow incident" of
    August 2010, when a transaction created 184 billion BTC. In 2017 Bitcoin
    Core stopped repeating the duplicate-input check for transactions in
    blocks. That bug (CVE-2018-17144) would have let a miner inflate the supply.
    """
    # BEGIN SOLUTION ch07
    if not tx.inputs:
        raise ValidationError("bad-txns-vin-empty")
    if not tx.outputs:
        raise ValidationError("bad-txns-vout-empty")
    total = 0
    for out in tx.outputs:
        if out.amount < 0:
            raise ValidationError("bad-txns-vout-negative")
        if out.amount > MAX_MONEY:
            raise ValidationError("bad-txns-vout-toolarge")
        total += out.amount
        if total > MAX_MONEY:
            raise ValidationError("bad-txns-txouttotal-toolarge")
    if tx.size() > MAX_BLOCK_SIZE:
        raise ValidationError("bad-txns-oversize")
    prevouts = [txin.prevout for txin in tx.inputs]
    if len(set(prevouts)) != len(prevouts):
        raise ValidationError("bad-txns-inputs-duplicate")
    if tx.is_coinbase():
        if not 2 <= len(tx.inputs[0].script_sig) <= 100:
            raise ValidationError("bad-cb-length")
    elif any(prevout.is_null() for prevout in prevouts):
        raise ValidationError("bad-txns-prevout-null")
    # END SOLUTION


def check_block(block: Block, params: ChainParams) -> None:
    """Context-free block checks (Bitcoin Core's CheckBlock), in this order:

    * proof-of-work (check_pow):  "high-hash"
    * at least one transaction, and serialized size <= MAX_BLOCK_SIZE:
      "bad-blk-length"
    * the header's merkle_root matches the transactions:  "bad-txnmrklroot"
    * no transaction appears twice:  "bad-txns-duplicate". Duplicating the
      last transactions leaves the Merkle root unchanged (CVE-2012-2459).
    * the first transaction is a coinbase:  "bad-cb-missing"
    * no other transaction is a coinbase:  "bad-cb-multiple"
    * every transaction passes check_transaction
    """
    # BEGIN SOLUTION ch07
    if not check_pow(block.header, params.pow_limit):
        raise ValidationError("high-hash")
    if not block.txs or len(block.serialize()) > MAX_BLOCK_SIZE:
        raise ValidationError("bad-blk-length")
    txids = [tx.hash() for tx in block.txs]
    if merkle_root(txids) != block.header.merkle_root:
        raise ValidationError("bad-txnmrklroot")
    if len(set(txids)) != len(txids):
        raise ValidationError("bad-txns-duplicate")
    if not block.txs[0].is_coinbase():
        raise ValidationError("bad-cb-missing")
    if any(tx.is_coinbase() for tx in block.txs[1:]):
        raise ValidationError("bad-cb-multiple")
    for tx in block.txs:
        check_transaction(tx)
    # END SOLUTION
