"""Chapter 10 · Mempool, wallet and mining."""

import pytest
from helpers import (
    ALICE,
    BOB,
    CAROL,
    MINER,
    coinbase_outpoint,
    funded_chain,
    lock,
    mine_blocks,
    spend,
)

from tinybitcoin.block import ValidationError
from tinybitcoin.chain import Chain
from tinybitcoin.mempool import Mempool
from tinybitcoin.miner import build_block, mine_block, select_transactions
from tinybitcoin.params import COIN, TINY
from tinybitcoin.script import verify_input
from tinybitcoin.tx import OutPoint
from tinybitcoin.wallet import DUST_LIMIT, P2PKH_INPUT_SIZE, P2PKH_OUTPUT_SIZE, TX_OVERHEAD, Wallet


def chain_with_coins(n: int) -> Chain:
    """A chain where ALICE owns `n` mature 50 BTC coins."""
    chain = Chain(TINY)
    mine_blocks(chain, n, lock(ALICE))
    mine_blocks(chain, TINY.coinbase_maturity - 1)
    return chain


def assert_refused(mempool: Mempool, tx, reason: str) -> None:
    with pytest.raises(ValidationError) as error:
        mempool.accept(tx)
    assert error.value.reason == reason


def test_mempool_accepts_a_valid_payment():
    chain, alice_coin = funded_chain()
    mempool = Mempool(chain)
    tx = spend(chain, ALICE, alice_coin, [(lock(BOB), 49 * COIN)])
    assert mempool.accept(tx) == 1 * COIN
    assert tx.hash() in mempool
    assert mempool.spent[alice_coin] == tx.hash()


def test_mempool_rejections():
    chain, alice_coin = funded_chain()
    mempool = Mempool(chain)
    assert_refused(mempool, chain.block_at(1).txs[0], "coinbase")
    pay_bob = spend(chain, ALICE, alice_coin, [(lock(BOB), 49 * COIN)])
    mempool.accept(pay_bob)
    assert_refused(mempool, pay_bob, "txn-already-in-mempool")
    pay_carol = spend(chain, ALICE, alice_coin, [(lock(CAROL), 49 * COIN)])
    assert_refused(mempool, pay_carol, "txn-mempool-conflict")  # first seen wins
    unconfirmed_parent = spend(chain, BOB, OutPoint(pay_bob.hash(), 0),
                               [(lock(CAROL), 48 * COIN)], coin_script=lock(BOB))
    assert_refused(mempool, unconfirmed_parent, "bad-txns-inputs-missingorspent")


def test_mempool_checks_signatures_and_maturity():
    chain = Chain(TINY)
    [young] = mine_blocks(chain, 1, lock(ALICE))
    mempool = Mempool(chain)
    early = spend(chain, ALICE, coinbase_outpoint(young), [(lock(BOB), 49 * COIN)])
    assert_refused(mempool, early, "bad-txns-premature-spend-of-coinbase")
    chain, alice_coin = funded_chain()
    theft = spend(chain, BOB, alice_coin, [(lock(BOB), 49 * COIN)], coin_script=lock(ALICE))
    assert_refused(Mempool(chain), theft, "mandatory-script-verify-flag-failed")


def test_policy_is_not_consensus():
    chain, alice_coin = funded_chain()
    free = spend(chain, ALICE, alice_coin, [(lock(BOB), 50 * COIN)])  # pays no fee
    assert_refused(Mempool(chain), free, "min relay fee not met")
    chain.add_block(build_block(chain, [free], lock(MINER)))  # ...but a miner may still include it


def test_mempool_follows_the_chain():
    chain, alice_coin = funded_chain()
    mempool = Mempool(chain)
    pay_bob = spend(chain, ALICE, alice_coin, [(lock(BOB), 49 * COIN)])
    mempool.accept(pay_bob)
    mempool.update(chain.add_block(build_block(chain, [pay_bob], lock(MINER))))
    assert len(mempool) == 0  # confirmed


def test_a_conflict_in_a_block_evicts_the_mempool_transaction():
    chain, alice_coin = funded_chain()
    mempool = Mempool(chain)
    mempool.accept(spend(chain, ALICE, alice_coin, [(lock(BOB), 49 * COIN)]))
    pay_carol = spend(chain, ALICE, alice_coin, [(lock(CAROL), 49 * COIN)])
    mempool.update(chain.add_block(build_block(chain, [pay_carol], lock(MINER))))
    assert len(mempool) == 0 and not mempool.spent


def test_a_reorg_returns_transactions_to_the_mempool():
    chain, alice_coin = funded_chain()
    mempool = Mempool(chain)
    fork_point = chain.tip
    pay_bob = spend(chain, ALICE, alice_coin, [(lock(BOB), 49 * COIN)])
    mempool.accept(pay_bob)
    mempool.update(chain.add_block(build_block(chain, [pay_bob], lock(MINER), extra=b"A")))
    assert pay_bob.hash() not in mempool
    b1 = build_block(chain, [], lock(MINER), parent=fork_point, extra=b"B")
    mempool.update(chain.add_block(b1))
    b2 = build_block(chain, [], lock(MINER), parent=chain.index[b1.hash()], extra=b"B")
    mempool.update(chain.add_block(b2))  # the branch without pay_bob wins
    assert pay_bob.hash() in mempool  # unconfirmed again, waiting for the next block


def test_select_transactions_by_fee_rate():
    chain = chain_with_coins(3)
    mempool = Mempool(chain)
    coins = [outpoint for outpoint, coin in chain.utxos.items()
             if coin.script_pubkey == lock(ALICE)]
    txs = [spend(chain, ALICE, coin, [(lock(BOB), 50 * COIN - fee)])
           for coin, fee in zip(coins, [1000, 5000, 3000])]
    for tx in txs:
        mempool.accept(tx)
    assert select_transactions(mempool, 10_000) == [txs[1], txs[2], txs[0]]
    room_for_two = txs[1].size() + txs[2].size()
    assert select_transactions(mempool, room_for_two) == [txs[1], txs[2]]


def test_wallet_finds_its_coins():
    chain = chain_with_coins(2)
    wallet = Wallet(TINY, [ALICE])
    assert wallet.balance(chain) == 100 * COIN
    mine_blocks(chain, 1, lock(ALICE))  # a new, immature coin
    assert wallet.balance(chain) == 100 * COIN
    assert Wallet(TINY, [BOB]).balance(chain) == 0


def test_create_payment_with_change():
    chain = chain_with_coins(1)
    wallet = Wallet(TINY, [ALICE])
    bob = Wallet(TINY, [BOB])
    tx = wallet.create_payment(chain, bob.address, 10 * COIN, fee_rate=2)
    expected_fee = 2 * (TX_OVERHEAD + P2PKH_INPUT_SIZE + 2 * P2PKH_OUTPUT_SIZE)
    assert [out.amount for out in tx.outputs] == [10 * COIN, 40 * COIN - expected_fee]
    assert [out.script_pubkey for out in tx.outputs] == [bob.script_pubkey, wallet.script_pubkey]
    assert tx.size() <= TX_OVERHEAD + P2PKH_INPUT_SIZE + 2 * P2PKH_OUTPUT_SIZE
    coin = chain.utxos[tx.inputs[0].prevout]
    assert verify_input(tx, 0, coin.script_pubkey)
    assert Mempool(chain).accept(tx) == expected_fee


def test_create_payment_combines_coins():
    chain = chain_with_coins(3)
    tx = Wallet(TINY, [ALICE]).create_payment(chain, Wallet(TINY, [BOB]).address, 70 * COIN)
    assert len(tx.inputs) == 2
    assert Mempool(chain).accept(tx) > 0


def test_dust_change_goes_to_the_miner():
    chain = chain_with_coins(1)
    fee = TX_OVERHEAD + P2PKH_INPUT_SIZE + 2 * P2PKH_OUTPUT_SIZE
    amount = 50 * COIN - fee - (DUST_LIMIT - 1)
    tx = Wallet(TINY, [ALICE]).create_payment(chain, Wallet(TINY, [BOB]).address, amount)
    assert len(tx.outputs) == 1


def test_insufficient_funds():
    chain = chain_with_coins(1)
    with pytest.raises(ValueError):
        Wallet(TINY, [ALICE]).create_payment(chain, Wallet(TINY, [BOB]).address, 50 * COIN)


def test_wallet_skips_coins_already_being_spent():
    chain = chain_with_coins(2)
    mempool, wallet, bob = Mempool(chain), Wallet(TINY, [ALICE]), Wallet(TINY, [BOB])
    first = wallet.create_payment(chain, bob.address, 30 * COIN, mempool=mempool)
    mempool.accept(first)
    second = wallet.create_payment(chain, bob.address, 30 * COIN, mempool=mempool)
    mempool.accept(second)  # would be a conflict if it reused the first coin
    assert first.inputs[0].prevout != second.inputs[0].prevout


def test_checkpoint_mine_the_mempool():
    """Checkpoint: Alice pays Bob from her wallet, and a miner collects the fee."""
    chain = chain_with_coins(1)
    mempool, alice, bob = Mempool(chain), Wallet(TINY, [ALICE]), Wallet(TINY, [BOB])
    fee = mempool.accept(alice.create_payment(chain, bob.address, 5 * COIN, fee_rate=10))
    block = mine_block(chain, mempool, lock(MINER))
    assert len(block.txs) == 2
    assert block.txs[0].outputs[0].amount == 50 * COIN + fee
    mempool.update(chain.add_block(block))
    assert len(mempool) == 0
    assert bob.balance(chain) == 5 * COIN
    assert alice.balance(chain) == 45 * COIN - fee
