"""The whole game: watch a small Bitcoin network at work.

    python -m tinybitcoin.demo

Everything here runs on tiny-bitcoin's own code. When your workbook passes
all twelve chapters, this demo runs on *your* implementation.
"""

from __future__ import annotations

from collections import Counter

from .network import Network, Node, attacker_success_probability
from .params import COIN
from .script import sign_p2pkh
from .spv import LightClient, prove_transaction
from .tx import Tx, TxIn, TxOut


def btc(sats: int) -> str:
    return f"{sats / COIN:,.8f}".rstrip("0").rstrip(".") + " BTC"


def section(title: str) -> None:
    print(f"\n== {title}")


def short(block_or_tx) -> str:
    return block_or_tx.id()[:12] + "…"


def converged(net: Network) -> bool:
    return len({node.chain.tip.hash for node in net.nodes.values()}) == 1


def double_spend(node: Node, tx: Tx) -> Tx:
    """A transaction that spends the same coins as `tx`, back to `node` itself."""
    refund = Tx(1, [TxIn(txin.prevout) for txin in tx.inputs],
                [TxOut(sum(out.amount for out in tx.outputs), node.wallet.script_pubkey)])
    for i, txin in enumerate(refund.inputs):
        coin = node.chain.utxos[txin.prevout]
        sign_p2pkh(refund, i, node.wallet.keys[coin.script_pubkey], coin.script_pubkey)
    return refund


def main() -> None:
    net = Network(seed=2009)
    for name, hashrate in [("alice", 1), ("bob", 1), ("carol", 1), ("dave", 0), ("mallory", 1)]:
        net.add_node(name, hashrate)
    ring = ["alice", "bob", "carol", "dave", "mallory"]
    for a, b in zip(ring, ring[1:] + ring[:1]):
        net.connect(a, b)
    net.run()
    alice, bob, carol, dave, mallory = net.nodes.values()
    print("tiny-bitcoin: five nodes in a ring, " + " - ".join(ring) + " - alice")

    section("1. Mining. Everyone but dave mines; dave runs a shop.")
    found = Counter(net.mine_round().name for _ in range(110))
    hours = (net.time - net.params.genesis_time) / 3600
    tally = ", ".join(f"{name} {count}" for name, count in found.most_common())
    print(f"   110 blocks in {hours:.0f} simulated hours. Blocks found: {tally}.")
    print(f"   All nodes agree on block {alice.chain.height}: {converged(net)}")
    for node in (alice, bob, carol, mallory):
        print(f"   {node.name:8} can spend {btc(node.balance())} "
              "(newer rewards are still maturing)")

    section("2. alice buys a book from dave for 1 BTC.")
    book = alice.pay(dave.wallet.address, COIN, fee_rate=2)
    net.run()
    in_mempools = sum(book.hash() in node.mempool for node in net.nodes.values())
    print(f"   Transaction {short(book)} is waiting in {in_mempools} of 5 mempools.")
    miner = net.mine_round()
    print(f"   {miner.name} mines it into block {miner.chain.height}. "
          f"dave has {btc(dave.balance())}.")

    section("3. The network splits in two. Both halves keep mining.")
    net.partition(["alice", "bob"], ["carol", "dave", "mallory"])
    gift = bob.pay(carol.wallet.address, 5 * COIN)  # only alice and bob hear about it
    for _ in range(6):
        net.mine_round()
    print(f"   alice and bob see block {alice.chain.height}; "
          f"carol, dave and mallory see block {carol.chain.height}.")
    gift_block = alice.chain.find_transaction(gift.hash())
    if gift_block:
        print(f"   bob's 5 BTC gift to carol is confirmed on the alice/bob side only "
              f"(block {gift_block[1]}).")
    net.events.clear()
    net.heal()
    net.run()
    if not converged(net):
        print("   Healed, but the two branches have equal work. Each node keeps the one it "
              "saw first,")
        print("   until the next block breaks the tie.")
    while not converged(net):
        net.mine_round()
    for event in net.events:
        if "reorganises" in event:
            print("   " + event)
    print(f"   Everyone follows block {alice.chain.height} again.")
    if gift_block and carol.chain.contains(gift_block[0].hash()):
        print(f"   The gift's block won, so carol keeps her 5 BTC: she has {btc(carol.balance())}.")
    else:
        while carol.chain.find_transaction(gift.hash()) is None:
            net.mine_round()
        print("   The gift's block was orphaned, so the gift went back to the mempool and was "
              f"mined again. carol has {btc(carol.balance())}.")

    section("4. mallory tries a double spend.")
    payment = mallory.pay(dave.wallet.address, 2 * COIN)
    net.run()
    refund = double_spend(mallory, payment)
    net.partition(["mallory"], ["alice", "bob", "carol", "dave"])
    alice.mine()
    net.run()
    print(f"   mallory pays dave 2 BTC. After 1 confirmation dave has {btc(dave.balance())} "
          f"(1 from alice, 2 from mallory)")
    print("   and hands over the goods.")
    mallory.mempool.remove(payment.hash())
    mallory.mempool.accept(refund)
    mallory.mine()
    mallory.mine()
    print("   Meanwhile mallory secretly mines 2 blocks that refund the coins to herself.")
    print("   (To win this race reliably she needs more hash power than everyone else.)")
    net.heal()
    net.run()
    print("   She releases them. Her branch has more work, so every node switches to it.")
    print(f"   dave is back to {btc(dave.balance())}: as far as Bitcoin knows, mallory never "
          "paid him.")

    section("5. Why merchants wait for confirmations (whitepaper section 11).")
    print("   attacker's    chance of ever catching up from z blocks behind")
    print("   hash power      z=1     z=2     z=3     z=6")
    for q in (0.10, 0.30, 0.45):
        odds = "".join(f"{attacker_success_probability(q, z):8.4f}" for z in (1, 2, 3, 6))
        print(f"   {q:>10.0%}  {odds}")

    section("6. dave's phone runs a light client.")
    phone = LightClient(net.params)
    phone.sync(dave.chain)
    block_hash, index, proof = prove_transaction(dave.chain, book.hash())
    confirmations = phone.verify_payment(book, block_hash, index, proof)
    full = sum(len(dave.chain.block_at(h).serialize()) for h in range(dave.chain.height + 1))
    print(f"   It stores {len(phone.headers)} headers ({80 * len(phone.headers):,} bytes) "
          f"instead of {full:,} bytes of blocks.")
    print("   (On mainnet: under 80 MB of headers, against hundreds of gigabytes of blocks.)")
    print(f"   With a {len(proof)}-hash Merkle proof it confirms alice's book payment: "
          f"{confirmations} confirmations.")
    print("\nEvery step above ran on the code in tinybitcoin/. Start building it: docs/course.md")


if __name__ == "__main__":
    main()
