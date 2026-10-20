"""Chapter 12 · Light clients: Simplified Payment Verification (whitepaper section 8).

A phone cannot download and check every block. A light client keeps only
the 80-byte headers. That is enough to check proof-of-work and follow the
chain with the most work. To learn that a payment is confirmed, it asks a
full node for a *Merkle proof*: the log2(n) hashes that connect the
transaction to a header's Merkle root.

The light client trusts that the most-work chain contains only valid
transactions. It cannot check that itself.
"""

from __future__ import annotations

from .block import ValidationError
from .chain import BlockIndex, Chain
from .hashing import sha256d
from .header import BlockHeader, block_work, check_pow
from .params import ChainParams
from .tx import Tx


def merkle_proof(txids: list[bytes], index: int) -> list[bytes]:
    """The sibling hashes that lead from txids[index] up to the Merkle root.

    Build the tree level by level as in merkle_root (chapter 7), duplicating
    the last hash of odd levels. At each level record the sibling of
    position `index` (index ^ 1), then move up: index //= 2.
    """
    # BEGIN SOLUTION ch12
    level, proof = list(txids), []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        proof.append(level[index ^ 1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        index //= 2
    return proof
    # END SOLUTION


def verify_merkle_proof(txid: bytes, index: int, proof: list[bytes], root: bytes) -> bool:
    """Rebuild the root from a txid, its position and the proof.

    At each level: if index is even the sibling goes on the right,
    sha256d(h + sibling), otherwise on the left, sha256d(sibling + h). Then
    index //= 2. Valid if the result equals `root` and index has reached 0.
    """
    # BEGIN SOLUTION ch12
    h = txid
    for sibling in proof:
        h = sha256d(h + sibling) if index % 2 == 0 else sha256d(sibling + h)
        index //= 2
    return h == root and index == 0
    # END SOLUTION


def prove_transaction(chain: Chain, txid: bytes) -> tuple[bytes, int, list[bytes]] | None:
    """What a full node sends a light client (provided): the block hash, the
    transaction's position in it, and the Merkle proof."""
    found = chain.find_transaction(txid)
    if found is None:
        return None
    block, _ = found
    txids = [tx.hash() for tx in block.txs]
    index = txids.index(txid)
    return block.hash(), index, merkle_proof(txids, index)


class LightClient:
    """Keeps block headers only."""

    def __init__(self, params: ChainParams):
        self.params = params
        genesis = params.genesis_block().header
        self.tip = BlockIndex(genesis, genesis.hash(), 0, block_work(genesis.bits), None, 0)
        self.headers: dict[bytes, BlockIndex] = {self.tip.hash: self.tip}

    def sync(self, chain: Chain) -> None:
        """Download the headers of a full node's active chain (provided)."""
        for index in chain.active[1:]:
            self.add_header(index.header)

    def add_header(self, header: BlockHeader) -> None:
        """Store a header and follow the most-work chain.

        Ignore headers we already have. Raise ValidationError if the parent
        is unknown ("prev-blk-not-found") or the proof-of-work is invalid
        ("high-hash"). Store it as a BlockIndex (as in Chain.add_block), and
        make it the tip if it has more chain work than the current tip.
        (A real light client also checks the difficulty rules and the
        timestamps. Why can it do that from headers alone?)
        """
        # BEGIN SOLUTION ch12
        block_hash = header.hash()
        if block_hash in self.headers:
            return
        parent = self.headers.get(header.prev_block)
        if parent is None:
            raise ValidationError("prev-blk-not-found")
        if not check_pow(header, self.params.pow_limit):
            raise ValidationError("high-hash")
        index = BlockIndex(header, block_hash, parent.height + 1,
                           parent.chain_work + block_work(header.bits), parent, len(self.headers))
        self.headers[block_hash] = index
        if index.chain_work > self.tip.chain_work:
            self.tip = index
        # END SOLUTION

    def confirmations(self, block_hash: bytes) -> int:
        """How deep a block is on our best chain: 1 for the tip, 0 if not on it."""
        # BEGIN SOLUTION ch12
        index = self.headers.get(block_hash)
        if index is None or index.height > self.tip.height:
            return 0
        if self.tip.ancestor(index.height) is not index:
            return 0
        return self.tip.height - index.height + 1
        # END SOLUTION

    def verify_payment(self, tx: Tx, block_hash: bytes, index: int, proof: list[bytes]) -> int:
        """Check a full node's proof that `tx` is in block `block_hash`.

        Return the block's confirmations, or 0 if we do not know the header
        or the Merkle proof does not lead to its merkle_root.
        """
        # BEGIN SOLUTION ch12
        header = self.headers.get(block_hash)
        if header is None:
            return 0
        if not verify_merkle_proof(tx.hash(), index, proof, header.header.merkle_root):
            return 0
        return self.confirmations(block_hash)
        # END SOLUTION
