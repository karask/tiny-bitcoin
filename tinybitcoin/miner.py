"""Chapter 10 · Mining: from mempool to block.

create_coinbase and build_block are provided. Chapters 8 and 9 use them to
make test blocks. Your chapter 10 exercise is the miner's economic decision:
which transactions to include.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .block import Block, merkle_root
from .chain import BlockIndex, Chain, block_subsidy
from .header import BlockHeader, mine
from .params import MAX_BLOCK_SIZE
from .script import push_int, serialize_script
from .tx import NULL_OUTPOINT, OutPoint, Tx, TxIn, TxOut

if TYPE_CHECKING:
    from .mempool import Mempool

BLOCK_RESERVED_BYTES = 1000  # room for the header and the coinbase


def create_coinbase(height: int, script_pubkey: bytes, amount: int, extra: bytes = b"") -> Tx:
    """A coinbase transaction (provided). BIP 34 puts the block height first in its scriptSig."""
    script_sig = push_int(height) + serialize_script([extra])
    return Tx(1, [TxIn(NULL_OUTPOINT, script_sig)], [TxOut(amount, script_pubkey)])


def block_fees(chain: Chain, txs: list[Tx]) -> int:
    """Total fees of `txs` against the tip's UTXO set; later txs may spend earlier ones."""
    created: dict[OutPoint, int] = {}
    fees = 0
    for tx in txs:
        for txin in tx.inputs:
            if txin.prevout in created:
                fees += created.pop(txin.prevout)
            else:
                fees += chain.utxos[txin.prevout].amount
        fees -= sum(out.amount for out in tx.outputs)
        created.update({OutPoint(tx.hash(), n): out.amount for n, out in enumerate(tx.outputs)})
    return fees


def build_block(
    chain: Chain,
    txs: list[Tx],
    script_pubkey: bytes,
    *,
    parent: BlockIndex | None = None,
    time: int | None = None,
    coinbase_amount: int | None = None,
    extra: bytes = b"",
) -> Block:
    """Assemble and mine a block (provided).

    By default the block goes on the chain tip, claims subsidy + fees, and
    is timestamped one target spacing after its parent. The keyword
    arguments let tests build unusual (or invalid) blocks.
    """
    parent = parent or chain.tip
    height = parent.height + 1
    if coinbase_amount is None:
        coinbase_amount = block_subsidy(height, chain.params) + block_fees(chain, txs)
    all_txs = [create_coinbase(height, script_pubkey, coinbase_amount, extra), *txs]
    header = BlockHeader(
        version=0x20000000,  # what Bitcoin Core's miner uses (BIP 9 version bits)
        prev_block=parent.hash,
        merkle_root=merkle_root([tx.hash() for tx in all_txs]),
        time=parent.header.time + chain.params.target_spacing if time is None else time,
        bits=chain.next_bits(parent),
        nonce=0,
    )
    mined = mine(header)
    if mined is None:
        raise RuntimeError("no nonce works; try again with a different `extra`")
    return Block(mined, all_txs)


def select_transactions(mempool: Mempool, max_bytes: int) -> list[Tx]:
    """Choose transactions for the next block: the most fees for the space.

    Greedy works because tiny-bitcoin's mempool never holds a transaction
    that spends another unconfirmed one. Take transactions from the highest
    fee rate (fee / size) down, skipping any that would push the total
    size over `max_bytes`. Fees are in mempool.fees[txid].
    """
    # BEGIN SOLUTION ch10
    by_fee_rate = sorted(
        mempool.txs.values(), key=lambda tx: mempool.fees[tx.hash()] / tx.size(), reverse=True
    )
    chosen, size = [], 0
    for tx in by_fee_rate:
        if size + tx.size() <= max_bytes:
            chosen.append(tx)
            size += tx.size()
    return chosen
    # END SOLUTION


def mine_block(chain: Chain, mempool: Mempool, script_pubkey: bytes, time: int | None = None,
               extra: bytes = b"") -> Block:
    """Mine a block from the mempool, paying the reward to script_pubkey (provided)."""
    txs = select_transactions(mempool, MAX_BLOCK_SIZE - BLOCK_RESERVED_BYTES)
    return build_block(chain, txs, script_pubkey, time=time, extra=extra)
