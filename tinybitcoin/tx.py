"""Chapter 5 · Transactions and the UTXO model.

Bitcoin has no accounts and no balances. It has *coins*: transaction outputs,
each holding an amount and a locking script. A transaction consumes existing
outputs (its inputs point at them) and creates new ones. The outputs nobody
has spent yet form the UTXO set (chapter 8). Your "balance" is the total of
the outputs your keys can unlock.

tiny-bitcoin handles the original ("legacy") serialisation only. SegWit
(BIP 141) adds a separate witness section, which we leave out.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO

from .encoding import (
    encode_varint,
    hash_to_hex,
    int_to_little_endian,
    little_endian_to_int,
    read_exact,
    read_varint,
)
from .hashing import sha256d


@dataclass(frozen=True)
class OutPoint:
    """Points at one output of an earlier transaction."""

    txid: bytes  # internal byte order
    index: int

    def serialize(self) -> bytes:
        """The 32-byte txid as stored, then the index as 4 little-endian bytes."""
        # BEGIN SOLUTION ch05
        return self.txid + int_to_little_endian(self.index, 4)
        # END SOLUTION

    @classmethod
    def parse(cls, s: BinaryIO) -> OutPoint:
        # BEGIN SOLUTION ch05
        return cls(read_exact(s, 32), little_endian_to_int(read_exact(s, 4)))
        # END SOLUTION

    def is_null(self) -> bool:
        """The "null" outpoint (all-zero txid, index 0xffffffff) marks a coinbase input."""
        return self == NULL_OUTPOINT


NULL_OUTPOINT = OutPoint(bytes(32), 0xFFFFFFFF)


@dataclass
class TxIn:
    prevout: OutPoint  # the output being spent
    script_sig: bytes = b""  # unlocks it (chapter 6)
    sequence: int = 0xFFFFFFFF

    def serialize(self) -> bytes:
        """prevout | varint length of script_sig | script_sig | sequence (4 bytes LE)."""
        # BEGIN SOLUTION ch05
        return (
            self.prevout.serialize()
            + encode_varint(len(self.script_sig))
            + self.script_sig
            + int_to_little_endian(self.sequence, 4)
        )
        # END SOLUTION

    @classmethod
    def parse(cls, s: BinaryIO) -> TxIn:
        # BEGIN SOLUTION ch05
        prevout = OutPoint.parse(s)
        script_sig = read_exact(s, read_varint(s))
        sequence = little_endian_to_int(read_exact(s, 4))
        return cls(prevout, script_sig, sequence)
        # END SOLUTION


@dataclass
class TxOut:
    amount: int  # in satoshis (1 BTC = 100,000,000 satoshis)
    script_pubkey: bytes  # the locking script (chapter 6)

    def serialize(self) -> bytes:
        """amount (8 bytes LE) | varint length of script_pubkey | script_pubkey."""
        # BEGIN SOLUTION ch05
        return (
            int_to_little_endian(self.amount, 8)
            + encode_varint(len(self.script_pubkey))
            + self.script_pubkey
        )
        # END SOLUTION

    @classmethod
    def parse(cls, s: BinaryIO) -> TxOut:
        # BEGIN SOLUTION ch05
        amount = little_endian_to_int(read_exact(s, 8))
        return cls(amount, read_exact(s, read_varint(s)))
        # END SOLUTION


@dataclass
class Tx:
    version: int
    inputs: list[TxIn]
    outputs: list[TxOut]
    locktime: int = 0

    def serialize(self) -> bytes:
        """version (4 LE) | varint count, inputs | varint count, outputs | locktime (4 LE)."""
        # BEGIN SOLUTION ch05
        return (
            int_to_little_endian(self.version, 4)
            + encode_varint(len(self.inputs))
            + b"".join(i.serialize() for i in self.inputs)
            + encode_varint(len(self.outputs))
            + b"".join(o.serialize() for o in self.outputs)
            + int_to_little_endian(self.locktime, 4)
        )
        # END SOLUTION

    @classmethod
    def parse(cls, s: BinaryIO) -> Tx:
        """Parse a legacy transaction.

        A SegWit transaction has the marker byte 0x00 where the input count
        should be. No valid legacy transaction has zero inputs, so when the
        count is 0 raise ValueError("SegWit transactions are not supported").
        """
        # BEGIN SOLUTION ch05
        version = little_endian_to_int(read_exact(s, 4))
        n_inputs = read_varint(s)
        if n_inputs == 0:
            raise ValueError("SegWit transactions are not supported by tiny-bitcoin")
        inputs = [TxIn.parse(s) for _ in range(n_inputs)]
        outputs = [TxOut.parse(s) for _ in range(read_varint(s))]
        locktime = little_endian_to_int(read_exact(s, 4))
        return cls(version, inputs, outputs, locktime)
        # END SOLUTION

    def hash(self) -> bytes:
        """The transaction id in internal byte order: sha256d of the serialization."""
        # BEGIN SOLUTION ch05
        return sha256d(self.serialize())
        # END SOLUTION

    def id(self) -> str:
        """The txid as block explorers show it (provided)."""
        return hash_to_hex(self.hash())

    def is_coinbase(self) -> bool:
        """A coinbase has exactly one input, and that input spends the null outpoint."""
        # BEGIN SOLUTION ch05
        return len(self.inputs) == 1 and self.inputs[0].prevout.is_null()
        # END SOLUTION

    def size(self) -> int:
        return len(self.serialize())
