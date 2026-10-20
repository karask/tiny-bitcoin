"""Chapter 10 · The mempool: valid transactions waiting for a block.

Block rules are *consensus*: every node must apply exactly the same ones,
or the network splits in two. Mempool rules are *policy*: each node picks
its own, and a transaction that nodes refuse to relay can still be valid in
a block. tiny-bitcoin's policy is deliberately simple:

* inputs must already be confirmed (no chains of unconfirmed transactions),
* the first transaction to spend a coin wins (no replace-by-fee),
* fees must pay at least a minimum rate per byte.
"""

from __future__ import annotations

from .block import ValidationError, check_transaction
from .chain import Chain, ChainUpdate, check_tx_inputs
from .script import verify_input
from .tx import OutPoint, Tx

MIN_RELAY_FEE_RATE = 1  # satoshis per byte


class Mempool:
    def __init__(self, chain: Chain, min_fee_rate: int = MIN_RELAY_FEE_RATE):
        self.chain = chain
        self.min_fee_rate = min_fee_rate
        self.txs: dict[bytes, Tx] = {}  # txid -> transaction
        self.fees: dict[bytes, int] = {}  # txid -> fee
        self.spent: dict[OutPoint, bytes] = {}  # outpoint -> txid of the transaction spending it

    def __contains__(self, txid: bytes) -> bool:
        return txid in self.txs

    def __len__(self) -> int:
        return len(self.txs)

    def accept(self, tx: Tx) -> int:
        """Check `tx` against the chain tip and the mempool, add it, and return its fee.

        Raise ValidationError for the first problem:

        * check_transaction(tx) fails (chapter 7)
        * it is a coinbase:  "coinbase"
        * it is already here:  "txn-already-in-mempool"
        * it spends a coin that a mempool transaction already spends:
          "txn-mempool-conflict"
        * check_tx_inputs against self.chain.utxos, as if in the next block
          (height + 1), fails. So inputs must be confirmed.
        * an input fails verify_input:  "mandatory-script-verify-flag-failed"
        * fee < self.min_fee_rate * tx.size():  "min relay fee not met"

        Then record it in self.txs, self.fees and self.spent.
        """
        # BEGIN SOLUTION ch10
        check_transaction(tx)
        if tx.is_coinbase():
            raise ValidationError("coinbase")
        txid = tx.hash()
        if txid in self.txs:
            raise ValidationError("txn-already-in-mempool")
        if any(txin.prevout in self.spent for txin in tx.inputs):
            raise ValidationError("txn-mempool-conflict")
        fee = check_tx_inputs(tx, self.chain.utxos.get, self.chain.height + 1, self.chain.params)
        for i, txin in enumerate(tx.inputs):
            if not verify_input(tx, i, self.chain.utxos[txin.prevout].script_pubkey):
                raise ValidationError("mandatory-script-verify-flag-failed")
        if fee < self.min_fee_rate * tx.size():
            raise ValidationError("min relay fee not met")
        self.txs[txid] = tx
        self.fees[txid] = fee
        for txin in tx.inputs:
            self.spent[txin.prevout] = txid
        return fee
        # END SOLUTION

    def remove(self, txid: bytes) -> None:
        """Forget a transaction (provided)."""
        tx = self.txs.pop(txid)
        del self.fees[txid]
        for txin in tx.inputs:
            del self.spent[txin.prevout]

    def update(self, update: ChainUpdate) -> None:
        """Follow the chain after Chain.add_block.

        1. Remove every transaction that is no longer valid on the new tip:
           it was confirmed, a conflicting transaction was, or its inputs
           vanished in a reorganisation. Re-run check_tx_inputs to find them.
        2. Try to re-add the transactions of each disconnected block (not
           the coinbase), since they are unconfirmed again. Ignore any that
           fail.
        """
        # BEGIN SOLUTION ch10
        for txid, tx in list(self.txs.items()):
            try:
                check_tx_inputs(tx, self.chain.utxos.get, self.chain.height + 1, self.chain.params)
            except ValidationError:
                self.remove(txid)
        for block in update.disconnected:
            for tx in block.txs[1:]:
                try:
                    self.accept(tx)
                except ValidationError:
                    pass
        # END SOLUTION
