"""Chapter 8 · The UTXO set and block connection."""

import pytest
from helpers import (
    ALICE,
    BOB,
    CAROL,
    MINER,
    assert_invalid,
    coinbase_outpoint,
    funded_chain,
    lock,
    mine_blocks,
    rebuild,
    spend,
)

from tinybitcoin.chain import MAX_FUTURE_BLOCK_TIME, Chain, Coin, block_subsidy
from tinybitcoin.miner import build_block
from tinybitcoin.params import COIN, MAINNET, TINY
from tinybitcoin.script import OP_RETURN, serialize_script
from tinybitcoin.tx import OutPoint, Tx, TxIn, TxOut


def test_a_new_chain_starts_at_genesis():
    chain = Chain(TINY)
    assert chain.height == 0
    assert chain.tip.hash == TINY.genesis_block().hash()
    assert chain.utxos == {}  # the genesis coinbase can never be spent


@pytest.mark.parametrize(
    "height, subsidy",
    [
        (0, 50 * COIN),
        (209_999, 50 * COIN),
        (210_000, 25 * COIN),
        (420_000, 1_250_000_000),
        (840_000, 312_500_000),  # the April 2024 halving: 3.125 BTC
        (6_929_999, 1),  # the last block with a subsidy
        (6_930_000, 0),
        (64 * 210_000, 0),
    ],
)
def test_block_subsidy(height, subsidy):
    assert block_subsidy(height, MAINNET) == subsidy


def test_total_supply_is_just_under_21_million_bitcoin():
    epochs = range(0, 34 * 210_000, 210_000)
    total = sum(block_subsidy(height, MAINNET) * 210_000 for height in epochs)
    assert total == 2_099_999_997_690_000  # 20,999,999.9769 BTC


def test_mining_a_block_creates_a_coin():
    chain = Chain(TINY)
    block = build_block(chain, [], lock(ALICE))
    update = chain.add_block(block)
    assert update.connected == [block]
    assert chain.height == 1 and chain.tip.hash == block.hash()
    assert chain.utxos[coinbase_outpoint(block)] == Coin(50 * COIN, lock(ALICE), 1, True)


def test_time_may_go_backwards_but_not_below_the_median():
    chain = Chain(TINY)
    mine_blocks(chain, 11)
    mtp = chain.median_time_past(chain.tip)
    assert mtp == chain.active[6].header.time  # the median of heights 1..11
    assert_invalid(chain, build_block(chain, [], lock(MINER), time=mtp), "time-too-old")
    chain.add_block(build_block(chain, [], lock(MINER), time=mtp + 1))  # earlier than its parent


def test_blocks_from_the_future_are_rejected():
    now = TINY.genesis_time + 10_000
    chain = Chain(TINY, clock=lambda: now)
    too_new = build_block(chain, [], lock(MINER), time=now + MAX_FUTURE_BLOCK_TIME + 1)
    assert_invalid(chain, too_new, "time-too-new")
    chain.add_block(build_block(chain, [], lock(MINER), time=now + MAX_FUTURE_BLOCK_TIME))


def test_wrong_difficulty_is_rejected():
    chain = Chain(TINY)
    block = build_block(chain, [], lock(MINER))
    block.header.bits = 0x1F00FFFF  # harder than required, but still not the rule
    assert_invalid(chain, rebuild(block), "bad-diffbits")


def test_coinbase_must_start_with_the_height():
    chain = Chain(TINY)
    block = build_block(chain, [], lock(MINER))
    block.txs[0].inputs[0].script_sig = serialize_script([b"no height here"])
    assert_invalid(chain, rebuild(block), "bad-cb-height")


def test_coinbase_may_not_claim_more_than_subsidy_plus_fees():
    chain = Chain(TINY)
    assert_invalid(chain, build_block(chain, [], lock(MINER), coinbase_amount=50 * COIN + 1),
                   "bad-cb-amount")
    chain.add_block(build_block(chain, [], lock(MINER), coinbase_amount=49 * COIN))  # less is ok


def test_coinbase_maturity():
    chain = Chain(TINY)
    [first] = mine_blocks(chain, 1, lock(ALICE))
    mine_blocks(chain, TINY.coinbase_maturity - 2)
    tx = spend(chain, ALICE, coinbase_outpoint(first), [(lock(BOB), 49 * COIN)])
    early = build_block(chain, [tx], lock(MINER))  # only 99 confirmations
    assert_invalid(chain, early, "bad-txns-premature-spend-of-coinbase")
    mine_blocks(chain, 1)
    chain.add_block(build_block(chain, [tx], lock(MINER)))


def test_checkpoint_alice_pays_bob():
    """Checkpoint: Alice pays Bob 10 BTC, and the UTXO set follows along."""
    chain, alice_coin = funded_chain()
    tx = spend(chain, ALICE, alice_coin, [(lock(BOB), 10 * COIN), (lock(ALICE), 39 * COIN)])
    block = build_block(chain, [tx], lock(MINER))
    chain.add_block(block)
    assert alice_coin not in chain.utxos
    assert chain.utxos[OutPoint(tx.hash(), 0)].amount == 10 * COIN  # Bob's new coin
    assert chain.utxos[OutPoint(tx.hash(), 1)].amount == 39 * COIN  # Alice's change
    assert chain.utxos[coinbase_outpoint(block)].amount == 51 * COIN  # subsidy + 1 BTC fee


def test_a_chain_of_payments_inside_one_block():
    chain, alice_coin = funded_chain()
    to_bob = spend(chain, ALICE, alice_coin, [(lock(BOB), 50 * COIN)])
    to_carol = spend(chain, BOB, OutPoint(to_bob.hash(), 0), [(lock(CAROL), 50 * COIN)],
                     coin_script=lock(BOB))
    chain.add_block(build_block(chain, [to_bob, to_carol], lock(MINER)))
    assert OutPoint(to_bob.hash(), 0) not in chain.utxos
    assert chain.utxos[OutPoint(to_carol.hash(), 0)].script_pubkey == lock(CAROL)


def test_double_spends_are_rejected():
    chain, alice_coin = funded_chain()
    to_bob = spend(chain, ALICE, alice_coin, [(lock(BOB), 50 * COIN)])
    to_carol = spend(chain, ALICE, alice_coin, [(lock(CAROL), 50 * COIN)])
    both = build_block(chain, [to_bob, to_carol], lock(MINER), coinbase_amount=50 * COIN)
    assert_invalid(chain, both, "bad-txns-inputs-missingorspent")
    chain.add_block(build_block(chain, [to_bob], lock(MINER)))
    later = build_block(chain, [to_carol], lock(MINER), coinbase_amount=50 * COIN)
    assert_invalid(chain, later, "bad-txns-inputs-missingorspent")


def test_only_the_owner_can_spend():
    chain, alice_coin = funded_chain()
    theft = spend(chain, BOB, alice_coin, [(lock(BOB), 50 * COIN)], coin_script=lock(ALICE))
    assert_invalid(chain, build_block(chain, [theft], lock(MINER)),
                   "mandatory-script-verify-flag-failed")


def test_outputs_may_not_exceed_inputs():
    chain, alice_coin = funded_chain()
    tx = spend(chain, ALICE, alice_coin, [(lock(BOB), 50 * COIN + 1)])
    assert_invalid(chain, build_block(chain, [tx], lock(MINER), coinbase_amount=0),
                   "bad-txns-in-belowout")


def test_an_invalid_block_changes_nothing():
    chain, alice_coin = funded_chain()
    utxos_before, tip_before = dict(chain.utxos), chain.tip
    good = spend(chain, ALICE, alice_coin, [(lock(BOB), 50 * COIN)])
    bad = Tx(1, [TxIn(OutPoint(b"\x99" * 32, 0))], [TxOut(1, lock(BOB))])  # spends nothing
    assert_invalid(chain, build_block(chain, [good, bad], lock(MINER), coinbase_amount=0),
                   "bad-txns-inputs-missingorspent")
    assert chain.utxos == utxos_before
    assert chain.tip is tip_before


def test_children_of_invalid_blocks_are_invalid():
    chain = Chain(TINY)
    greedy = build_block(chain, [], lock(MINER), coinbase_amount=51 * COIN)
    assert_invalid(chain, greedy, "bad-cb-amount")
    child = build_block(chain, [], lock(MINER), parent=chain.index[greedy.hash()])
    assert_invalid(chain, child, "bad-prevblk")


def test_op_return_outputs_stay_out_of_the_utxo_set():
    chain, alice_coin = funded_chain()
    note = serialize_script([OP_RETURN, b"hello from tiny-bitcoin"])
    tx = spend(chain, ALICE, alice_coin, [(note, 0), (lock(ALICE), 50 * COIN)])
    chain.add_block(build_block(chain, [tx], lock(MINER)))
    assert OutPoint(tx.hash(), 0) not in chain.utxos
    assert OutPoint(tx.hash(), 1) in chain.utxos
