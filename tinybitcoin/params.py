"""Chain parameters (provided).

Bitcoin Core keeps one parameter set per network (mainnet, testnet, signet,
regtest). tiny-bitcoin has two:

* MAINNET: the real thing, used to check our code against real Bitcoin data.
* TINY: Bitcoin Core's *regtest* genesis block and easy proof-of-work, so a
  laptop can mine hundreds of blocks a second. Unlike regtest it keeps the
  difficulty adjustment switched on. Its addresses use the testnet/regtest
  prefix (they start with m or n), so nobody mistakes them for mainnet ones.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .block import Block

COIN = 100_000_000  # satoshis per bitcoin
MAX_MONEY = 21_000_000 * COIN  # consensus sanity limit on any amount (CVE-2010-5139)
MAX_BLOCK_SIZE = 1_000_000  # bytes; the pre-SegWit limit

# The coinbase transaction of the genesis block, with Satoshi's newspaper headline.
# Mainnet and regtest share it.
GENESIS_COINBASE_HEX = (
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ff"
    "ff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e2062"
    "72696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a0100"
    "0000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef"
    "38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
)


@dataclass(frozen=True)
class ChainParams:
    name: str
    pow_limit: int  # the easiest target any block may have
    genesis_time: int
    genesis_bits: int
    genesis_nonce: int
    target_spacing: int = 600  # seconds between blocks, on average
    retarget_interval: int = 2016  # blocks between difficulty adjustments
    halving_interval: int = 210_000  # blocks between subsidy halvings
    coinbase_maturity: int = 100  # confirmations before a coinbase output can be spent
    p2pkh_prefix: int = 0x00  # Base58Check version byte of P2PKH addresses
    magic: bytes = bytes.fromhex("f9beb4d9")  # first 4 bytes of every P2P message

    @property
    def target_timespan(self) -> int:
        """Seconds one difficulty period should take (two weeks on mainnet)."""
        return self.target_spacing * self.retarget_interval

    def genesis_block(self) -> Block:
        """Build the genesis block. Needs chapters 5 and 7 to be implemented."""
        from .block import Block
        from .header import BlockHeader
        from .tx import Tx

        coinbase = Tx.parse(BytesIO(bytes.fromhex(GENESIS_COINBASE_HEX)))
        header = BlockHeader(
            version=1,
            prev_block=bytes(32),
            merkle_root=coinbase.hash(),
            time=self.genesis_time,
            bits=self.genesis_bits,
            nonce=self.genesis_nonce,
        )
        return Block(header, [coinbase])


MAINNET = ChainParams(
    name="main",
    pow_limit=(1 << 224) - 1,  # 0x00000000ffff...ff
    genesis_time=1231006505,  # 2009-01-03 18:15:05 UTC
    genesis_bits=0x1D00FFFF,
    genesis_nonce=2083236893,
)

TINY = ChainParams(
    name="tiny",
    pow_limit=(1 << 255) - 1,  # 0x7fff...ff, as on regtest: about every second hash wins
    genesis_time=1296688602,
    genesis_bits=0x207FFFFF,
    genesis_nonce=2,
    halving_interval=150,  # as on regtest, so you can watch the subsidy halve
    p2pkh_prefix=0x6F,
    magic=bytes.fromhex("fabfb5da"),
)
