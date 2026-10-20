"""Chapter 10 · A wallet: keys, coins and payments.

A wallet does not hold bitcoin. It holds keys, and finds the coins in the
UTXO set that those keys can unlock. Paying someone means choosing coins,
sending what is needed, and returning the rest to yourself as change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .hashing import hash160
from .keys import PrivateKey, address_to_pubkey_hash
from .params import ChainParams
from .script import p2pkh_script, sign_p2pkh
from .tx import OutPoint, Tx, TxIn, TxOut

if TYPE_CHECKING:
    from .chain import Chain, Coin
    from .mempool import Mempool

DUST_LIMIT = 546  # satoshis; Bitcoin Core does not relay smaller P2PKH outputs by default
P2PKH_INPUT_SIZE = 148  # outpoint 36 + script length 1 + scriptSig up to 107 + sequence 4
P2PKH_OUTPUT_SIZE = 34  # amount 8 + script length 1 + scriptPubKey 25
TX_OVERHEAD = 10  # version 4 + input count 1 + output count 1 + locktime 4


class Wallet:
    def __init__(self, params: ChainParams, keys: list[PrivateKey] | None = None):
        self.params = params
        self.keys: dict[bytes, PrivateKey] = {}  # P2PKH scriptPubKey -> the key that unlocks it
        for key in keys or [PrivateKey.generate()]:
            self.add_key(key)

    def add_key(self, key: PrivateKey) -> None:
        self.keys[p2pkh_script(hash160(key.sec()))] = key

    @property
    def script_pubkey(self) -> bytes:
        """Where this wallet receives payments, change and mining rewards (its first key)."""
        return next(iter(self.keys))

    @property
    def address(self) -> str:
        return self.keys[self.script_pubkey].address(self.params.p2pkh_prefix)

    def coins(self, chain: Chain, mempool: Mempool | None = None) -> list[tuple[OutPoint, Coin]]:
        """Spendable coins (provided): in the UTXO set, locked to one of our keys,
        mature, and not already being spent by a transaction in `mempool`."""
        next_height = chain.height + 1
        found = []
        for outpoint, coin in chain.utxos.items():
            if coin.script_pubkey not in self.keys:
                continue
            if coin.is_coinbase and next_height - coin.height < chain.params.coinbase_maturity:
                continue
            if mempool is not None and outpoint in mempool.spent:
                continue
            found.append((outpoint, coin))
        return found

    def balance(self, chain: Chain, mempool: Mempool | None = None) -> int:
        return sum(coin.amount for _, coin in self.coins(chain, mempool))

    def create_payment(
        self,
        chain: Chain,
        address: str,
        amount: int,
        fee_rate: int = 1,
        mempool: Mempool | None = None,
    ) -> Tx:
        """Build and sign a transaction paying `amount` satoshis to `address`.

        1. Take coins, largest first, until they cover amount + fee, where
           fee = fee_rate * (TX_OVERHEAD + inputs * P2PKH_INPUT_SIZE
                             + 2 * P2PKH_OUTPUT_SIZE).
        2. Outputs: the payment (p2pkh_script of address_to_pubkey_hash), then
           change back to self.script_pubkey. If the change would be below
           DUST_LIMIT, leave it out: the miner gets it as extra fee.
        3. Sign each input with sign_p2pkh and the key that owns that coin.

        Raise ValueError("insufficient funds") if all our coins are not enough.
        """
        # BEGIN SOLUTION ch10
        to_script = p2pkh_script(address_to_pubkey_hash(address, self.params.p2pkh_prefix))
        coins = sorted(self.coins(chain, mempool), key=lambda item: item[1].amount, reverse=True)
        selected, total, fee = [], 0, 0
        for outpoint, coin in coins:
            selected.append((outpoint, coin))
            total += coin.amount
            size = TX_OVERHEAD + len(selected) * P2PKH_INPUT_SIZE + 2 * P2PKH_OUTPUT_SIZE
            fee = fee_rate * size
            if total >= amount + fee:
                break
        else:
            raise ValueError("insufficient funds")
        outputs = [TxOut(amount, to_script)]
        change = total - amount - fee
        if change >= DUST_LIMIT:
            outputs.append(TxOut(change, self.script_pubkey))
        tx = Tx(1, [TxIn(outpoint) for outpoint, _ in selected], outputs)
        for i, (_, coin) in enumerate(selected):
            sign_p2pkh(tx, i, self.keys[coin.script_pubkey], coin.script_pubkey)
        return tx
        # END SOLUTION
