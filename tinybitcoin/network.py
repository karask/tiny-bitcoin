"""Chapter 11 · The peer-to-peer network.

Bitcoin has no server. Each node talks to a few peers, and news spreads by
gossip:

    inv       "I have something new": a list of (type, hash) pairs
    getdata   "please send me these"
    tx        a transaction
    block     a block

The messages use Bitcoin's real envelope and payload formats. Instead of TCP
sockets they travel through an in-process Network that is deterministic: you
control the clock, the links, and who finds the next block. That lets you
replay forks, partitions and attacks exactly.
"""

from __future__ import annotations

import math
import random
from collections import deque
from dataclasses import dataclass
from io import BytesIO

from .block import Block, ValidationError
from .chain import Chain, ChainUpdate
from .encoding import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_exact,
    read_varint,
)
from .hashing import sha256d
from .keys import PrivateKey
from .mempool import Mempool
from .miner import mine_block
from .params import TINY, ChainParams
from .tx import Tx
from .wallet import Wallet

MSG_TX = 1
MSG_BLOCK = 2


@dataclass
class Message:
    command: str  # "inv", "getdata", "tx" or "block"
    payload: bytes

    def serialize(self, magic: bytes) -> bytes:
        """Bitcoin's message envelope:

        magic      4 bytes: which network this is (params.magic)
        command   12 bytes: ASCII, padded with zero bytes
        length     4 bytes, little-endian: the payload's length
        checksum   4 bytes: the first 4 bytes of sha256d(payload)
        payload
        """
        # BEGIN SOLUTION ch11
        return (
            magic
            + self.command.encode("ascii").ljust(12, b"\x00")
            + int_to_little_endian(len(self.payload), 4)
            + sha256d(self.payload)[:4]
            + self.payload
        )
        # END SOLUTION

    @classmethod
    def parse(cls, data: bytes, magic: bytes) -> Message:
        """The inverse. Raise ValueError if the magic, length or checksum is wrong."""
        # BEGIN SOLUTION ch11
        s = BytesIO(data)
        if read_exact(s, 4) != magic:
            raise ValueError("wrong network magic")
        command = read_exact(s, 12).rstrip(b"\x00").decode("ascii")
        length = little_endian_to_int(read_exact(s, 4))
        checksum = read_exact(s, 4)
        payload = s.read()
        if len(payload) != length:
            raise ValueError("wrong payload length")
        if sha256d(payload)[:4] != checksum:
            raise ValueError("bad checksum")
        return cls(command, payload)
        # END SOLUTION


def encode_inventory(items: list[tuple[int, bytes]]) -> bytes:
    """The payload of inv and getdata (provided): a varint count, then for
    each item its type (4 bytes, little-endian) and hash (32 bytes)."""
    return encode_varint(len(items)) + b"".join(
        int_to_little_endian(kind, 4) + item_hash for kind, item_hash in items
    )


def decode_inventory(payload: bytes) -> list[tuple[int, bytes]]:
    s = BytesIO(payload)
    return [
        (little_endian_to_int(read_exact(s, 4)), read_exact(s, 32)) for _ in range(read_varint(s))
    ]


class Node:
    """A full node with a wallet and a miner."""

    def __init__(self, name: str, network: Network, hashrate: float = 1.0):
        self.name = name
        self.network = network
        self.hashrate = hashrate  # this node's relative share of the mining power
        self.chain = Chain(network.params, clock=network.clock)
        self.mempool = Mempool(self.chain)
        self.wallet = Wallet(network.params, [PrivateKey.from_passphrase(name)])
        self.peers: list[str] = []
        self.orphans: dict[bytes, list[Block]] = {}  # missing parent -> blocks waiting for it

    def __repr__(self) -> str:
        return f"Node({self.name!r}, height={self.chain.height})"

    # ------------------------------------------------------------ talking (provided)

    def send(self, peer: str, command: str, payload: bytes) -> None:
        self.network.send(self.name, peer, Message(command, payload))

    def announce(self, kind: int, item_hash: bytes, exclude: str | None = None) -> None:
        """Tell every peer except `exclude` about a new block or transaction."""
        for peer in self.peers:
            if peer != exclude:
                self.send(peer, "inv", encode_inventory([(kind, item_hash)]))

    def on_connect(self, peer: str) -> None:
        """A new link: tell the peer about our best block and our mempool."""
        items = [(MSG_BLOCK, self.chain.tip.hash)] + [(MSG_TX, txid) for txid in self.mempool.txs]
        self.send(peer, "inv", encode_inventory(items))

    def receive(self, sender: str, data: bytes) -> None:
        """Handle one message. Malformed ones are dropped, as a real node would."""
        try:
            message = Message.parse(data, self.network.params.magic)
            handler = {
                "inv": self.on_inv,
                "getdata": self.on_getdata,
                "tx": self.on_tx,
                "block": self.on_block,
            }.get(message.command)
            if handler is not None:
                handler(sender, message.payload)
        except ValueError as error:  # a parse error: the peer sent garbage
            self.network.log(f"{self.name} drops a malformed message from {sender}: {error}")

    def has_block(self, block_hash: bytes) -> bool:
        """Have we seen this block, in our chain or among our orphans?"""
        return self.chain.has_block(block_hash) or any(
            orphan.hash() == block_hash for waiting in self.orphans.values() for orphan in waiting
        )

    # ------------------------------------------------------------ the protocol

    def on_inv(self, sender: str, payload: bytes) -> None:
        """A peer announced blocks or transactions.

        Reply with a single getdata listing the items we do not have: blocks
        for which self.has_block is False, and transactions that are not in
        our mempool. Send nothing if we have them all.
        """
        # BEGIN SOLUTION ch11
        wanted = [
            (kind, item_hash)
            for kind, item_hash in decode_inventory(payload)
            if (kind == MSG_BLOCK and not self.has_block(item_hash))
            or (kind == MSG_TX and item_hash not in self.mempool)
        ]
        if wanted:
            self.send(sender, "getdata", encode_inventory(wanted))
        # END SOLUTION

    def on_getdata(self, sender: str, payload: bytes) -> None:
        """Send each requested item we have.

        Send a "block" message with block.serialize() for blocks in
        self.chain.blocks, and a "tx" message for transactions in our
        mempool. Skip anything we do not have.
        """
        # BEGIN SOLUTION ch11
        for kind, item_hash in decode_inventory(payload):
            if kind == MSG_BLOCK and item_hash in self.chain.blocks:
                self.send(sender, "block", self.chain.blocks[item_hash].serialize())
            elif kind == MSG_TX and item_hash in self.mempool:
                self.send(sender, "tx", self.mempool.txs[item_hash].serialize())
        # END SOLUTION

    def on_tx(self, sender: str, payload: bytes) -> None:
        """Parse the transaction and offer it to our mempool.

        If it is accepted, announce it to our other peers. If not, drop it.
        Never relay what you could not validate. That rule is what stops
        invalid transactions from flooding the network.
        """
        # BEGIN SOLUTION ch11
        tx = Tx.parse(BytesIO(payload))
        try:
            self.mempool.accept(tx)
        except ValidationError:
            return
        self.announce(MSG_TX, tx.hash(), exclude=sender)
        # END SOLUTION

    def on_block(self, sender: str, payload: bytes) -> None:
        """Parse the block and process it:

        * if self.has_block already, ignore it;
        * if its parent is not in our chain, it is an *orphan*. File it under
          self.orphans[block.header.prev_block] and ask the sender for the
          parent with a getdata;
        * otherwise call self.accept_block(block, sender).
        """
        # BEGIN SOLUTION ch11
        block = Block.parse(BytesIO(payload))
        if self.has_block(block.hash()):
            return
        parent = block.header.prev_block
        if not self.chain.has_block(parent):
            self.orphans.setdefault(parent, []).append(block)
            self.send(sender, "getdata", encode_inventory([(MSG_BLOCK, parent)]))
            return
        self.accept_block(block, sender)
        # END SOLUTION

    # ------------------------------------------------------------ provided

    def accept_block(self, block: Block, sender: str | None = None) -> bool:
        """Add a block, and then any orphans that were waiting for it.

        Returns whether `block` itself was accepted.
        """
        if not self._add_block(block, sender):
            return False
        waiting = self.orphans.pop(block.hash(), [])
        while waiting:
            orphan = waiting.pop()
            if self._add_block(orphan, sender):
                waiting.extend(self.orphans.pop(orphan.hash(), []))
        return True

    def _add_block(self, block: Block, sender: str | None) -> bool:
        try:
            update = self.chain.add_block(block)
        except ValidationError as error:
            self.network.log(f"{self.name} rejects block {block.id()[-8:]}: {error}")
            self.mempool.update(ChainUpdate())  # a reorg cut short may still have moved the tip
            return False
        before = set(self.mempool.txs)
        self.mempool.update(update)
        if update.disconnected:
            self.network.log(
                f"{self.name} reorganises: {len(update.disconnected)} block(s) out, "
                f"{len(update.connected)} in, height {self.chain.height}"
            )
        self.announce(MSG_BLOCK, block.hash(), exclude=sender)
        for txid in self.mempool.txs:
            if txid not in before:  # unconfirmed again after a reorg: spread it again
                self.announce(MSG_TX, txid)
        return True

    def mine(self) -> Block:
        """Mine a block from our mempool on our tip, and announce it."""
        time = max(self.network.time, self.chain.median_time_past(self.chain.tip) + 1)
        block = mine_block(self.chain, self.mempool, self.wallet.script_pubkey, time=time,
                           extra=self.name.encode())
        self.accept_block(block)
        self.network.log(f"{self.name} mines block {self.chain.height} "
                         f"with {len(block.txs) - 1} transaction(s)")
        return block

    def pay(self, address: str, amount: int, fee_rate: int = 1) -> Tx:
        """Pay from our wallet: add the transaction to our mempool and announce it."""
        tx = self.wallet.create_payment(self.chain, address, amount, fee_rate, self.mempool)
        self.mempool.accept(tx)
        self.announce(MSG_TX, tx.hash())
        return tx

    def balance(self) -> int:
        """Our confirmed, spendable balance."""
        return self.wallet.balance(self.chain)


class Network:
    """A deterministic in-process network (provided).

    Messages wait in a queue until run() delivers them, first in, first out.
    """

    def __init__(self, params: ChainParams = TINY, seed: int = 0, verbose: bool = False):
        self.params = params
        self.time = params.genesis_time  # the simulated clock
        self.nodes: dict[str, Node] = {}
        self.queue: deque[tuple[str, str, bytes]] = deque()
        self.random = random.Random(seed)
        self.verbose = verbose
        self.events: list[str] = []
        self._cut: list[tuple[str, str]] = []

    def clock(self) -> float:
        return self.time

    def log(self, event: str) -> None:
        self.events.append(event)
        if self.verbose:
            print(event)

    def add_node(self, name: str, hashrate: float = 1.0) -> Node:
        node = Node(name, self, hashrate)
        self.nodes[name] = node
        return node

    def connect(self, a: str, b: str) -> None:
        if b in self.nodes[a].peers:
            return
        self.nodes[a].peers.append(b)
        self.nodes[b].peers.append(a)
        self.nodes[a].on_connect(b)
        self.nodes[b].on_connect(a)

    def disconnect(self, a: str, b: str) -> None:
        self.nodes[a].peers.remove(b)
        self.nodes[b].peers.remove(a)

    def send(self, sender: str, receiver: str, message: Message) -> None:
        self.queue.append((sender, receiver, message.serialize(self.params.magic)))

    def run(self, max_messages: int = 1_000_000) -> int:
        """Deliver messages (and the ones they trigger) until the network is quiet."""
        delivered = 0
        while self.queue:
            sender, receiver, data = self.queue.popleft()
            if sender in self.nodes[receiver].peers:  # the link may have been cut meanwhile
                self.nodes[receiver].receive(sender, data)
            delivered += 1
            if delivered >= max_messages:
                raise RuntimeError("the network did not settle")
        return delivered

    def partition(self, *groups: list[str]) -> None:
        """Cut every link between nodes in different groups. heal() restores them."""
        side = {name: i for i, group in enumerate(groups) for name in group}
        for a, node in self.nodes.items():
            for b in list(node.peers):
                if a < b and side.get(a) != side.get(b):
                    self.disconnect(a, b)
                    self._cut.append((a, b))

    def heal(self) -> None:
        for a, b in self._cut:
            self.connect(a, b)
        self._cut.clear()

    def mine_round(self) -> Node:
        """One block interval, then let the network settle.

        Blocks arrive as a Poisson process: the clock jumps by an
        exponentially distributed time averaging params.target_spacing, and
        a node chosen in proportion to its hashrate finds the block.
        """
        miners = [node for node in self.nodes.values() if node.hashrate > 0]
        self.time += max(1, round(self.random.expovariate(1 / self.params.target_spacing)))
        miner = self.random.choices(miners, weights=[node.hashrate for node in miners])[0]
        miner.mine()
        self.run()
        return miner


def attacker_success_probability(q: float, z: int) -> float:
    """Whitepaper section 11: the chance that an attacker with a share `q` of
    the hash power ever catches up from `z` blocks behind.

        p = 1 - q        lam = z * q / p
        P = 1 - sum over k = 0..z of  poisson(k; lam) * (1 - (q / p) ** (z - k))

    where poisson(k; lam) = lam**k * exp(-lam) / k!. Compute it the way the
    paper's C code does (multiply by lam / i, k times), because lam**k and k!
    overflow floats for large z. If q >= p the attacker always catches up.
    """
    # BEGIN SOLUTION ch11
    p = 1.0 - q
    if q >= p:
        return 1.0
    lam = z * q / p
    total = 1.0
    for k in range(z + 1):
        poisson = math.exp(-lam)
        for i in range(1, k + 1):
            poisson *= lam / i
        total -= poisson * (1 - (q / p) ** (z - k))
    return total
    # END SOLUTION
