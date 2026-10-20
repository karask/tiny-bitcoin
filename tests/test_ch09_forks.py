"""Chapter 9 · Forks, reorganisations and difficulty adjustment."""

from dataclasses import replace

import pytest
from helpers import (
    ALICE,
    BOB,
    CAROL,
    MINER,
    assert_invalid,
    funded_chain,
    lock,
    mine_blocks,
    rebuild,
    spend,
)

from tinybitcoin.chain import Chain
from tinybitcoin.header import retarget
from tinybitcoin.miner import build_block
from tinybitcoin.params import COIN, MAINNET, TINY
from tinybitcoin.tx import OutPoint


# From Bitcoin Core's src/test/pow_tests.cpp, using real mainnet history.
@pytest.mark.parametrize(
    "bits, first_time, last_time, expected",
    [
        (0x1D00FFFF, 1261130161, 1262152739, 0x1D00D86A),  # blocks 30240-32255: no limit hit
        (0x1D00FFFF, 1231006505, 1233061996, 0x1D00FFFF),  # blocks 0-2015: capped at pow_limit
        (0x1C05A3F4, 1279008237, 1279297671, 0x1C0168FD),  # blocks 66528-68543: at most 4x harder
        (0x1C387F6F, 1263163443, 1269211443, 0x1D00E1FD),  # a slow period: at most 4x easier
    ],
)
def test_checkpoint_retarget_matches_bitcoin_core(bits, first_time, last_time, expected):
    """Checkpoint: your difficulty adjustment agrees with Bitcoin Core on real history."""
    assert retarget(bits, last_time - first_time, MAINNET) == expected


def test_retarget_on_a_fast_chain():
    params = replace(TINY, retarget_interval=10)
    chain = Chain(params)
    for _ in range(9):  # blocks 60 seconds apart: ten times too fast
        chain.add_block(build_block(chain, [], lock(MINER), time=chain.tip.header.time + 60))
    assert chain.next_bits(chain.tip) == 0x201FFFFF  # four times harder (the maximum step)
    lazy = build_block(chain, [], lock(MINER), time=chain.tip.header.time + 60)
    lazy.header.bits = params.genesis_bits  # ignore the adjustment
    assert_invalid(chain, rebuild(lazy), "bad-diffbits")
    chain.add_block(build_block(chain, [], lock(MINER), time=chain.tip.header.time + 60))
    assert chain.tip.header.bits == 0x201FFFFF


def test_difficulty_never_drops_below_the_minimum():
    params = replace(TINY, retarget_interval=10)
    chain = Chain(params)
    for _ in range(9):  # blocks an hour apart: six times too slow
        chain.add_block(build_block(chain, [], lock(MINER), time=chain.tip.header.time + 3600))
    assert chain.next_bits(chain.tip) == params.genesis_bits  # already as easy as allowed


def test_equal_work_first_seen_wins():
    chain = Chain(TINY)
    genesis = chain.tip
    [a1] = mine_blocks(chain, 1, extra=b"A")
    [b1] = mine_blocks(chain, 1, parent=genesis, extra=b"B")
    assert chain.tip.hash == a1.hash()
    assert chain.has_block(b1.hash()) and not chain.contains(b1.hash())


def test_find_fork():
    chain = Chain(TINY)
    genesis = chain.tip
    a = mine_blocks(chain, 3, extra=b"A")
    b = mine_blocks(chain, 2, parent=chain.index[a[0].hash()], extra=b"B")
    a3, b2 = chain.index[a[2].hash()], chain.index[b[1].hash()]
    assert chain.find_fork(a3, b2).hash == a[0].hash()
    assert chain.find_fork(b2, a3).hash == a[0].hash()
    assert chain.find_fork(a3, genesis) is genesis
    assert chain.find_fork(a3, a3) is a3


def test_disconnect_undoes_connect():
    chain, alice_coin = funded_chain()
    before = dict(chain.utxos)
    tx = spend(chain, ALICE, alice_coin, [(lock(BOB), 10 * COIN), (lock(ALICE), 39 * COIN)])
    block = build_block(chain, [tx], lock(MINER))
    undo = chain.connect_block(block, chain.height + 1)
    assert chain.utxos != before
    chain.disconnect_block(block, undo)
    assert chain.utxos == before


def test_disconnect_forgets_coins_created_and_spent_in_the_same_block():
    chain, alice_coin = funded_chain()
    before = dict(chain.utxos)
    to_bob = spend(chain, ALICE, alice_coin, [(lock(BOB), 50 * COIN)])
    to_carol = spend(chain, BOB, OutPoint(to_bob.hash(), 0), [(lock(CAROL), 50 * COIN)],
                     coin_script=lock(BOB))
    block = build_block(chain, [to_bob, to_carol], lock(MINER))
    undo = chain.connect_block(block, chain.height + 1)
    chain.disconnect_block(block, undo)
    assert chain.utxos == before  # Bob's coin must not come back from the dead


def test_a_branch_with_more_work_takes_over():
    chain = Chain(TINY)
    genesis = chain.tip
    a = mine_blocks(chain, 2, extra=b"A")
    b = mine_blocks(chain, 2, parent=genesis, extra=b"B")
    assert chain.tip.hash == a[1].hash()  # a tie: no reorganisation yet
    b3 = build_block(chain, [], lock(MINER), parent=chain.index[b[1].hash()], extra=b"B")
    update = chain.add_block(b3)
    assert update.disconnected == [a[1], a[0]]
    assert update.connected == [b[0], b[1], b3]
    assert chain.tip.hash == b3.hash() and chain.height == 3


def test_checkpoint_a_reorg_reverses_a_payment():
    """Checkpoint: a longer branch double-spends Alice's coin, and Bob's payment vanishes.

    After the reorganisation your UTXO set must be exactly what a node that
    only ever saw the winning branch would have.
    """
    chain, alice_coin = funded_chain()
    fork_point = chain.tip
    pay_bob = spend(chain, ALICE, alice_coin, [(lock(BOB), 50 * COIN)])
    chain.add_block(build_block(chain, [pay_bob], lock(MINER), extra=b"honest"))

    pay_carol = spend(chain, ALICE, alice_coin, [(lock(CAROL), 50 * COIN)], coin_script=lock(ALICE))
    b1 = build_block(chain, [pay_carol], lock(MINER), parent=fork_point, extra=b"attacker",
                     coinbase_amount=50 * COIN)
    chain.add_block(b1)
    b2 = build_block(chain, [], lock(MINER), parent=chain.index[b1.hash()], extra=b"attacker")
    chain.add_block(b2)

    assert chain.tip.hash == b2.hash()
    assert OutPoint(pay_bob.hash(), 0) not in chain.utxos
    assert OutPoint(pay_carol.hash(), 0) in chain.utxos

    fresh = Chain(TINY)
    for block in [chain.block_at(h) for h in range(1, chain.height + 1)]:
        fresh.add_block(block)
    assert chain.utxos == fresh.utxos


def test_most_work_wins_not_most_blocks():
    params = replace(TINY, retarget_interval=4)
    chain = Chain(params)
    genesis = chain.tip
    for _ in range(5):  # fast blocks, so block 4 retargets to four times the difficulty
        chain.add_block(build_block(chain, [], lock(MINER), time=chain.tip.header.time + 60))
    short_branch = chain.tip

    parent = genesis
    for _ in range(8):  # slow blocks stay at minimum difficulty: more blocks, less work
        block = build_block(chain, [], lock(MINER), parent=parent,
                            time=parent.header.time + 800, extra=b"slow")
        chain.add_block(block)
        parent = chain.index[block.hash()]

    assert parent.height > short_branch.height
    assert parent.chain_work < short_branch.chain_work
    assert chain.tip is short_branch


def test_an_invalid_branch_is_abandoned():
    chain = Chain(TINY)
    genesis = chain.tip
    [a1] = mine_blocks(chain, 1, extra=b"A")
    [b1] = mine_blocks(chain, 1, parent=genesis, extra=b"B")
    b2 = build_block(chain, [], lock(MINER), parent=chain.index[b1.hash()],
                     coinbase_amount=51 * COIN)  # more work, but invalid
    assert_invalid(chain, b2, "bad-cb-amount")
    assert chain.tip.hash == a1.hash()  # B1 only ties A1, and A1 was first
    b3 = build_block(chain, [], lock(MINER), parent=chain.index[b2.hash()])
    assert_invalid(chain, b3, "bad-prevblk")
