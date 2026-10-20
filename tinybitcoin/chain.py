"""Chapter 8 · The UTXO set and block connection (and chapter 9: forks, reorgs, difficulty).

A node keeps two things:

* every valid block it has seen. Two miners sometimes find blocks at the
  same time, so these form a tree rather than a list;
* the UTXO set of the *active chain*: the valid branch with the most work.

Connecting a block means checking each transaction against the UTXO set,
then spending its inputs and adding its outputs. Chapter 8 handles a single
chain. Chapter 9 handles the moment another branch overtakes it: the node
disconnects blocks back to the fork point and connects the new branch.
That is a *reorganisation*.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .block import Block, ValidationError, check_block
from .header import BlockHeader, block_work, retarget
from .params import COIN, MAX_MONEY, ChainParams
from .script import OP_RETURN, push_int, verify_input
from .tx import OutPoint, Tx

MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60  # seconds a block's time may be ahead of ours


@dataclass(frozen=True)
class Coin:
    """An unspent output, plus what consensus needs to know about where it came from."""

    amount: int
    script_pubkey: bytes
    height: int  # of the block that created it
    is_coinbase: bool


@dataclass(eq=False)
class BlockIndex:
    """What a node remembers about each block it has accepted (Core's CBlockIndex)."""

    header: BlockHeader
    hash: bytes
    height: int
    chain_work: int  # total work of this block and all its ancestors
    parent: BlockIndex | None
    sequence: int  # arrival order: among equal work, the block seen first wins
    failure: str | None = None  # why this block, or an ancestor, is invalid

    def ancestor(self, height: int) -> BlockIndex:
        """This block's ancestor at `height` (provided)."""
        index = self
        while index.height > height:
            index = index.parent
        return index


@dataclass
class ChainUpdate:
    """How the active chain changed in one add_block call (provided)."""

    connected: list[Block] = field(default_factory=list)
    disconnected: list[Block] = field(default_factory=list)


def block_subsidy(height: int, params: ChainParams) -> int:
    """New coins a block at `height` may create (Core's GetBlockSubsidy).

    50 BTC, halved every params.halving_interval blocks (use a right shift),
    and zero after 64 halvings. In C++ a shift by 64 or more is undefined
    behaviour. Until BIP 42 (2014) added that last rule, the subsidy would
    have jumped back to 50 BTC after 64 halvings.
    """
    # BEGIN SOLUTION ch08
    halvings = height // params.halving_interval
    if halvings >= 64:
        return 0
    return (50 * COIN) >> halvings
    # END SOLUTION


def check_tx_inputs(
    tx: Tx, lookup: Callable[[OutPoint], Coin | None], spend_height: int, params: ChainParams
) -> int:
    """Check a transaction's inputs against the coins it spends; return its fee.

    `lookup(outpoint)` returns the unspent Coin or None. This is Core's
    Consensus::CheckTxInputs. Raise ValidationError for the first problem:

    * an input's coin does not exist (never did, or already spent):
      "bad-txns-inputs-missingorspent"
    * a coinbase coin with fewer than params.coinbase_maturity confirmations,
      i.e. spend_height - coin.height < coinbase_maturity:
      "bad-txns-premature-spend-of-coinbase"
    * the running total of input amounts exceeds MAX_MONEY:
      "bad-txns-inputvalues-outofrange"
    * inputs total less than outputs: "bad-txns-in-belowout"

    The fee is what the inputs provide minus what the outputs take. The
    miner collects it.
    """
    # BEGIN SOLUTION ch08
    total_in = 0
    for txin in tx.inputs:
        coin = lookup(txin.prevout)
        if coin is None:
            raise ValidationError("bad-txns-inputs-missingorspent", tx.id())
        if coin.is_coinbase and spend_height - coin.height < params.coinbase_maturity:
            raise ValidationError("bad-txns-premature-spend-of-coinbase", tx.id())
        total_in += coin.amount
        if total_in > MAX_MONEY:
            raise ValidationError("bad-txns-inputvalues-outofrange", tx.id())
    total_out = sum(out.amount for out in tx.outputs)
    if total_in < total_out:
        raise ValidationError("bad-txns-in-belowout", tx.id())
    return total_in - total_out
    # END SOLUTION


class Chain:
    def __init__(self, params: ChainParams, clock: Callable[[], float] = time.time):
        self.params = params
        self.clock = clock  # the node's idea of "now"
        self.blocks: dict[bytes, Block] = {}
        self.index: dict[bytes, BlockIndex] = {}
        self.active: list[BlockIndex] = []  # active[h] is the block at height h
        self.utxos: dict[OutPoint, Coin] = {}
        self.undo: dict[bytes, list[tuple[OutPoint, Coin]]] = {}  # per connected block
        genesis = params.genesis_block()
        index = BlockIndex(genesis.header, genesis.hash(), 0, block_work(genesis.header.bits),
                           None, sequence=0)
        self.blocks[index.hash] = genesis
        self.index[index.hash] = index
        self.active.append(index)
        # Like Bitcoin Core, never add the genesis coinbase to the UTXO set: those 50 BTC
        # cannot be spent.

    # ------------------------------------------------------------ queries (provided)

    @property
    def tip(self) -> BlockIndex:
        return self.active[-1]

    @property
    def height(self) -> int:
        return self.tip.height

    def has_block(self, block_hash: bytes) -> bool:
        return block_hash in self.index

    def contains(self, block_hash: bytes) -> bool:
        """Is this block on the active chain (rather than a side branch)?"""
        index = self.index.get(block_hash)
        if index is None or index.height > self.height:
            return False
        return self.active[index.height] is index

    def block_at(self, height: int) -> Block:
        return self.blocks[self.active[height].hash]

    def find_transaction(self, txid: bytes) -> tuple[Block, int] | None:
        """The active-chain block containing `txid`, and its height (a slow linear scan)."""
        for index in reversed(self.active):
            block = self.blocks[index.hash]
            if any(tx.hash() == txid for tx in block.txs):
                return block, index.height
        return None

    # ------------------------------------------------------------ header rules

    def median_time_past(self, index: BlockIndex) -> int:
        """The median timestamp of `index` and up to 10 of its ancestors (11 blocks).

        A new block must be later than its parent's median time past. Using
        a median means one miner with a wrong clock cannot drag the chain's
        time backwards.
        """
        # BEGIN SOLUTION ch08
        times = []
        while index is not None and len(times) < 11:
            times.append(index.header.time)
            index = index.parent
        return sorted(times)[len(times) // 2]
        # END SOLUTION

    def next_bits(self, parent: BlockIndex) -> int:
        """The `bits` a block on top of `parent` must have (Core's GetNextWorkRequired).

        Inside a difficulty period the target does not change (provided).
        On a retarget boundary, call retarget() with the time from the period's
        first block to `parent`. The first block is the ancestor
        retarget_interval - 1 blocks below parent. So Bitcoin measures 2015
        block intervals, not 2016: a famous off-by-one that also helps the
        "time warp" attack.
        """
        interval = self.params.retarget_interval
        if (parent.height + 1) % interval != 0:
            return parent.header.bits
        # BEGIN SOLUTION ch09
        first = parent.ancestor(parent.height - (interval - 1))
        return retarget(parent.header.bits, parent.header.time - first.header.time, self.params)
        # END SOLUTION

    def check_header(self, header: BlockHeader, parent: BlockIndex) -> None:
        """Header checks that need the chain (Core's ContextualCheckBlockHeader):

        * header.bits must equal self.next_bits(parent):  "bad-diffbits"
        * header.time must be later than the parent's median time past:
          "time-too-old"
        * header.time must not be more than MAX_FUTURE_BLOCK_TIME after
          self.clock():  "time-too-new"
        """
        # BEGIN SOLUTION ch08
        if header.bits != self.next_bits(parent):
            raise ValidationError("bad-diffbits")
        if header.time <= self.median_time_past(parent):
            raise ValidationError("time-too-old")
        if header.time > self.clock() + MAX_FUTURE_BLOCK_TIME:
            raise ValidationError("time-too-new")
        # END SOLUTION

    # ------------------------------------------------------------ connecting blocks

    def connect_block(self, block: Block, height: int) -> list[tuple[OutPoint, Coin]]:
        """Validate `block` against the UTXO set and apply it (Core's ConnectBlock).

        Return the undo data: every (outpoint, coin) the block spent from the
        UTXO set. Raise ValidationError if anything is wrong, and leave
        self.utxos untouched in that case. So record changes in local
        dicts first and apply them only at the very end:

        1. BIP 34: the coinbase scriptSig must start with push_int(height):
           "bad-cb-height". This makes every coinbase txid unique.
        2. Add the coinbase's outputs as coins (is_coinbase=True).
        3. For each other transaction, in order:
           * fee = check_tx_inputs(...). Inputs may spend outputs created
             earlier in this same block.
           * each input must pass verify_input against the scriptPubKey it
             spends: "mandatory-script-verify-flag-failed"
           * spend its inputs and add its outputs.
        4. The coinbase may claim at most block_subsidy + total fees:
           "bad-cb-amount".

        Skip outputs whose script starts with OP_RETURN. They can never be
        spent, so Bitcoin Core keeps them out of the UTXO set.
        """
        # BEGIN SOLUTION ch08
        coinbase = block.txs[0]
        if not coinbase.inputs[0].script_sig.startswith(push_int(height)):
            raise ValidationError("bad-cb-height")

        created: dict[OutPoint, Coin] = {}  # new coins (some may be spent again in this block)
        spent: dict[OutPoint, Coin] = {}  # coins taken from self.utxos: the undo data

        def lookup(outpoint: OutPoint) -> Coin | None:
            if outpoint in created:
                return created[outpoint]
            return None if outpoint in spent else self.utxos.get(outpoint)

        def add_outputs(tx: Tx, is_coinbase: bool) -> None:
            txid = tx.hash()
            for n, out in enumerate(tx.outputs):
                if out.script_pubkey[:1] != bytes([OP_RETURN]):
                    created[OutPoint(txid, n)] = Coin(out.amount, out.script_pubkey, height,
                                                      is_coinbase)

        add_outputs(coinbase, is_coinbase=True)
        fees = 0
        for tx in block.txs[1:]:
            fees += check_tx_inputs(tx, lookup, height, self.params)
            for i, txin in enumerate(tx.inputs):
                if not verify_input(tx, i, lookup(txin.prevout).script_pubkey):
                    raise ValidationError("mandatory-script-verify-flag-failed", tx.id())
            for txin in tx.inputs:
                if txin.prevout in created:
                    del created[txin.prevout]
                else:
                    spent[txin.prevout] = self.utxos[txin.prevout]
            add_outputs(tx, is_coinbase=False)

        if sum(out.amount for out in coinbase.outputs) > block_subsidy(height, self.params) + fees:
            raise ValidationError("bad-cb-amount")

        for outpoint in spent:
            del self.utxos[outpoint]
        self.utxos.update(created)
        return list(spent.items())
        # END SOLUTION

    def disconnect_block(self, block: Block, undo: list[tuple[OutPoint, Coin]]) -> None:
        """Chapter 9 · Undo connect_block (Core's DisconnectBlock).

        Remove every output the block created from the UTXO set (some may
        not be there, if they were spent inside the block or were OP_RETURN).
        Then put back every coin in `undo`.
        """
        # BEGIN SOLUTION ch09
        for tx in block.txs:
            txid = tx.hash()
            for n in range(len(tx.outputs)):
                self.utxos.pop(OutPoint(txid, n), None)
        for outpoint, coin in undo:
            self.utxos[outpoint] = coin
        # END SOLUTION

    # ------------------------------------------------------------ the block tree

    def add_block(self, block: Block) -> ChainUpdate:
        """Accept a new block from a miner or a peer (provided).

        Raise ValidationError if it is invalid. Otherwise store it, and if its
        branch now has the most work, make that branch the active chain.
        """
        block_hash = block.hash()
        if block_hash in self.index:
            raise ValidationError("duplicate")
        parent = self.index.get(block.header.prev_block)
        if parent is None:
            raise ValidationError("prev-blk-not-found")
        if parent.failure:
            raise ValidationError("bad-prevblk")
        check_block(block, self.params)  # chapter 7
        self.check_header(block.header, parent)  # chapters 8 and 9

        index = BlockIndex(block.header, block_hash, parent.height + 1,
                           parent.chain_work + block_work(block.header.bits), parent,
                           sequence=len(self.index))
        self.index[block_hash] = index
        self.blocks[block_hash] = block

        if index.chain_work <= self.tip.chain_work:
            return ChainUpdate()  # a side branch, kept in case it overtakes later
        if parent is self.tip:  # the common case: the block extends our chain
            try:
                return ChainUpdate(connected=[self._connect_tip(index)])
            except ValidationError as error:
                self._mark_invalid(index, error.reason)
                raise
        update = self.activate_best_chain()  # another branch overtook ours: chapter 9
        if index.failure:
            raise ValidationError(index.failure)
        return update

    def find_fork(self, a: BlockIndex, b: BlockIndex) -> BlockIndex:
        """Chapter 9 · The most recent block that both `a` and `b` descend from.

        Walk the higher one down until both are at the same height, then
        walk both down together until they are the same block.
        """
        # BEGIN SOLUTION ch09
        while a.height > b.height:
            a = a.parent
        while b.height > a.height:
            b = b.parent
        while a is not b:
            a, b = a.parent, b.parent
        return a
        # END SOLUTION

    def activate_best_chain(self) -> ChainUpdate:
        """Chapter 9 · Reorganise onto the valid block with the most work.

        Loop:
          1. best = the block in self.index with no failure and the greatest
             (chain_work, -sequence). Among equal work, the first seen wins.
             If best is the tip, return what changed.
          2. fork = find_fork(tip, best). Call self._disconnect_tip() until
             the tip is fork, recording each block in the update.
          3. Connect the blocks from fork up to best, in order, with
             self._connect_tip(index). If one raises ValidationError, call
             self._mark_invalid(index, error.reason) and go back to step 1.
             The best remaining branch may be the one you just left.
        """
        # BEGIN SOLUTION ch09
        update = ChainUpdate()
        while True:
            best = max(
                (index for index in self.index.values() if index.failure is None),
                key=lambda index: (index.chain_work, -index.sequence),
            )
            if best is self.tip:
                return update
            fork = self.find_fork(self.tip, best)
            while self.tip is not fork:
                update.disconnected.append(self._disconnect_tip())
            path = []
            index = best
            while index is not fork:
                path.append(index)
                index = index.parent
            for index in reversed(path):
                try:
                    update.connected.append(self._connect_tip(index))
                except ValidationError as error:
                    self._mark_invalid(index, error.reason)
                    break
        # END SOLUTION

    def _connect_tip(self, index: BlockIndex) -> Block:
        block = self.blocks[index.hash]
        self.undo[index.hash] = self.connect_block(block, index.height)
        self.active.append(index)
        return block

    def _disconnect_tip(self) -> Block:
        index = self.active.pop()
        block = self.blocks[index.hash]
        self.disconnect_block(block, self.undo.pop(index.hash))
        return block

    def _mark_invalid(self, bad: BlockIndex, reason: str) -> None:
        """Mark `bad` and every block built on it as invalid."""
        bad.failure = reason
        for index in self.index.values():
            if index.height > bad.height and index.ancestor(bad.height) is bad:
                index.failure = "bad-prevblk"
