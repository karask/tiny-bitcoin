"""Chapter 11 · The peer-to-peer network."""

from itertools import pairwise

import pytest

from tinybitcoin.network import (
    MSG_BLOCK,
    MSG_TX,
    Message,
    Network,
    attacker_success_probability,
    decode_inventory,
    encode_inventory,
)
from tinybitcoin.params import COIN, MAINNET, TINY
from tinybitcoin.script import sign_p2pkh
from tinybitcoin.tx import Tx, TxIn, TxOut


def line_network(*names: str, seed: int = 0) -> Network:
    """Nodes connected in a line: each one only talks to its neighbours."""
    net = Network(seed=seed)
    for name in names:
        net.add_node(name)
    for a, b in pairwise(names):
        net.connect(a, b)
    net.run()
    return net


def same_tip(net: Network) -> bool:
    return len({node.chain.tip.hash for node in net.nodes.values()}) == 1


def test_message_envelope():
    message = Message("inv", encode_inventory([(MSG_BLOCK, bytes(32))]))
    data = message.serialize(TINY.magic)
    assert data[:4] == TINY.magic
    assert data[4:16] == b"inv" + bytes(9)
    assert data[16:20] == (1 + 4 + 32).to_bytes(4, "little")
    assert Message.parse(data, TINY.magic) == message


def test_a_real_verack_message():
    # The bytes every mainnet node sends during its handshake.
    expected = "f9beb4d9" + "76657261636b000000000000" + "00000000" + "5df6e0e2"
    assert Message("verack", b"").serialize(MAINNET.magic).hex() == expected


def test_corrupted_messages_are_rejected():
    data = Message("tx", b"\x01\x02\x03").serialize(TINY.magic)
    for bad in (MAINNET.magic + data[4:], data[:-1], data[:-1] + b"\x04"):
        with pytest.raises(ValueError):
            Message.parse(bad, TINY.magic)


def test_inventory_round_trip():
    items = [(MSG_TX, b"\x01" * 32), (MSG_BLOCK, b"\x02" * 32)]
    assert decode_inventory(encode_inventory(items)) == items


def test_a_block_spreads_through_the_network():
    net = line_network("alice", "bob", "carol")  # alice and carol never talk directly
    block = net.nodes["alice"].mine()
    net.run()
    assert all(node.chain.tip.hash == block.hash() for node in net.nodes.values())


def test_payments_spread_and_get_mined():
    net = line_network("alice", "bob", "carol")
    alice, bob, carol = net.nodes.values()
    for _ in range(TINY.coinbase_maturity + 1):
        alice.mine()
    net.run()
    tx = alice.pay(carol.wallet.address, 3 * COIN)
    net.run()
    assert all(tx.hash() in node.mempool for node in net.nodes.values())
    bob.mine()
    net.run()
    assert carol.balance() == 3 * COIN
    assert all(len(node.mempool) == 0 for node in net.nodes.values())


def test_invalid_transactions_are_not_relayed():
    net = line_network("alice", "bob", "carol")
    alice, bob, carol = net.nodes.values()
    for _ in range(TINY.coinbase_maturity + 1):
        alice.mine()
    net.run()
    free = alice.wallet.create_payment(alice.chain, carol.wallet.address, COIN, fee_rate=0)
    alice.send("bob", "tx", free.serialize())
    net.run()
    assert free.hash() not in bob.mempool and free.hash() not in carol.mempool


def test_a_late_node_catches_up():
    net = line_network("alice")
    for _ in range(20):
        net.nodes["alice"].mine()
    net.add_node("dave")
    net.connect("alice", "dave")
    net.run()  # dave walks back through orphan blocks to the genesis block
    assert net.nodes["dave"].chain.height == 20 and same_tip(net)


def test_checkpoint_partition_and_heal():
    """Checkpoint: split the network, let both halves mine, then heal it.

    The side with more work wins. A payment confirmed only on the losing
    side goes back to the mempool, and the winning side mines it.
    """
    net = line_network("alice", "bob", "carol", "dave")
    alice, bob, carol, dave = net.nodes.values()
    for _ in range(TINY.coinbase_maturity + 1):
        alice.mine()
    net.run()

    net.partition(["alice", "bob"], ["carol", "dave"])
    payment = alice.pay(bob.wallet.address, 2 * COIN)
    alice.mine()  # confirmed on the alice/bob side only
    for miner in (carol, dave):  # the other side mines two blocks
        miner.mine()
        net.run()
    assert alice.chain.tip.hash != carol.chain.tip.hash
    assert bob.balance() == 2 * COIN

    net.heal()
    net.run()
    assert same_tip(net) and alice.chain.tip.hash == dave.chain.tip.hash
    assert bob.balance() == 0  # the payment's block lost
    assert all(payment.hash() in node.mempool for node in net.nodes.values())
    carol.mine()
    net.run()
    assert bob.balance() == 2 * COIN


def test_break_it_double_spend_with_a_secret_chain():
    """The attack of whitepaper section 11: pay a merchant, then replace history."""
    net = Network()
    merchant = net.add_node("merchant", hashrate=0)
    honest = net.add_node("honest")
    mallory = net.add_node("mallory")
    net.connect("merchant", "honest")
    net.connect("honest", "mallory")
    for _ in range(TINY.coinbase_maturity + 1):
        mallory.mine()
    net.run()

    payment = mallory.pay(merchant.wallet.address, 10 * COIN)
    net.run()
    refund = Tx(1, [TxIn(txin.prevout) for txin in payment.inputs],
                [TxOut(sum(out.amount for out in payment.outputs), mallory.wallet.script_pubkey)])
    for i, txin in enumerate(refund.inputs):
        coin = mallory.chain.utxos[txin.prevout]
        sign_p2pkh(refund, i, mallory.wallet.keys[coin.script_pubkey], coin.script_pubkey)

    net.partition(["mallory"], ["merchant", "honest"])
    honest.mine()  # the payment gets its first confirmation
    net.run()
    assert merchant.balance() == 10 * COIN  # the merchant ships the goods...

    mallory.mempool.remove(payment.hash())
    mallory.mempool.accept(refund)
    mallory.mine()  # ...while mallory secretly mines a branch that pays herself instead
    mallory.mine()
    net.heal()
    net.run()

    assert same_tip(net)
    assert merchant.balance() == 0
    assert payment.hash() not in merchant.mempool  # and it can never confirm now


def test_an_honest_majority_defeats_the_attack():
    net = line_network("honest", "mallory")
    honest, mallory = net.nodes.values()
    net.partition(["mallory"], ["honest"])
    for _ in range(3):
        honest.mine()
    for _ in range(2):
        mallory.mine()
    net.heal()
    net.run()
    assert mallory.chain.tip.hash == honest.chain.tip.hash
    assert honest.chain.height == 3


def test_simulations_are_reproducible():
    tips = []
    for _ in range(2):
        net = line_network("alice", "bob", "carol", seed=42)
        for _ in range(10):
            net.mine_round()
        tips.append((net.time, net.nodes["alice"].chain.tip.hash))
    assert tips[0] == tips[1]


# Section 11 of the whitepaper prints these tables.
@pytest.mark.parametrize(
    "q, z, p",
    [
        (0.1, 0, 1.0),
        (0.1, 1, 0.2045873),
        (0.1, 2, 0.0509779),
        (0.1, 5, 0.0009137),
        (0.1, 10, 0.0000012),
        (0.3, 5, 0.1773523),
        (0.3, 10, 0.0416605),
        (0.3, 50, 0.0000006),
    ],
)
def test_whitepaper_attacker_success_probability(q, z, p):
    assert round(attacker_success_probability(q, z), 7) == p


@pytest.mark.parametrize(
    "q, z", [(0.10, 5), (0.15, 8), (0.20, 11), (0.25, 15), (0.30, 24), (0.35, 41), (0.40, 89),
             (0.45, 340)]
)
def test_whitepaper_confirmations_for_one_in_a_thousand(q, z):
    assert attacker_success_probability(q, z) < 0.001 <= attacker_success_probability(q, z - 1)


def test_a_majority_attacker_always_wins():
    assert attacker_success_probability(0.5, 100) == 1.0


def test_garbage_from_a_peer_is_dropped():
    net = line_network("alice", "bob")
    for command, payload in [("block", b"\x01\x02"), ("tx", b"\x00" * 10), ("inv", b"\xff")]:
        net.nodes["alice"].send("bob", command, payload)
    net.run()  # must not crash bob
    assert net.nodes["bob"].chain.height == 0
    assert sum("malformed" in event for event in net.events) == 3
