"""Chapter 12 · Light clients."""

from dataclasses import replace

import pytest
from helpers import ALICE, BOB, MINER, funded_chain, lock, mine_blocks, spend
from vectors import BLOCK170_COINBASE_TXID, BLOCK170_MERKLE_ROOT, SATOSHI_TO_HAL_TXID

from tinybitcoin.block import ValidationError, merkle_root
from tinybitcoin.chain import Chain
from tinybitcoin.encoding import hex_to_hash
from tinybitcoin.hashing import sha256d
from tinybitcoin.header import check_pow
from tinybitcoin.miner import build_block
from tinybitcoin.params import COIN, TINY
from tinybitcoin.spv import LightClient, merkle_proof, prove_transaction, verify_merkle_proof


def test_merkle_proof_of_the_first_payment():
    txids = [hex_to_hash(BLOCK170_COINBASE_TXID), hex_to_hash(SATOSHI_TO_HAL_TXID)]
    root = hex_to_hash(BLOCK170_MERKLE_ROOT)
    proof = merkle_proof(txids, 1)
    assert proof == [txids[0]]
    assert verify_merkle_proof(txids[1], 1, proof, root)


@pytest.mark.parametrize("n", range(1, 10))
def test_merkle_proofs_for_every_position(n):
    txids = [sha256d(bytes([i])) for i in range(n)]
    root = merkle_root(txids)
    for index, txid in enumerate(txids):
        proof = merkle_proof(txids, index)
        assert len(proof) == (n - 1).bit_length()  # log2(n), rounded up
        assert verify_merkle_proof(txid, index, proof, root)
        assert not verify_merkle_proof(sha256d(b"forged"), index, proof, root)
        if proof:
            tampered = [sha256d(b"tampered")] + proof[1:]
            assert not verify_merkle_proof(txid, index, tampered, root)


def test_a_proof_only_works_at_its_own_position():
    txids = [sha256d(bytes([i])) for i in range(4)]
    root = merkle_root(txids)
    proof = merkle_proof(txids, 0)
    assert verify_merkle_proof(txids[0], 0, proof, root)
    assert not verify_merkle_proof(txids[0], 1, proof, root)  # hashed in the wrong order
    assert not verify_merkle_proof(txids[0], 4, proof, root)  # beyond the tree


def test_light_client_follows_the_most_work_chain():
    chain = Chain(TINY)
    genesis = chain.tip
    mine_blocks(chain, 3, extra=b"A")
    side = mine_blocks(chain, 2, parent=genesis, extra=b"B")
    client = LightClient(TINY)
    client.sync(chain)
    assert client.tip.hash == chain.tip.hash
    for block in side:
        client.add_header(block.header)
    assert client.tip.hash == chain.tip.hash  # two blocks do not beat three


def test_light_client_rejects_bad_headers():
    chain = Chain(TINY)
    [block] = mine_blocks(chain, 1)
    client = LightClient(TINY)
    with pytest.raises(ValidationError, match="prev-blk-not-found"):
        client.add_header(replace(block.header, prev_block=bytes(32)))
    lazy = replace(block.header, nonce=block.header.nonce + 1)
    while check_pow(lazy, TINY.pow_limit):
        lazy = replace(lazy, nonce=lazy.nonce + 1)
    with pytest.raises(ValidationError, match="high-hash"):
        client.add_header(lazy)


def test_checkpoint_verify_a_payment_with_headers_only():
    """Checkpoint: a light client confirms Bob's payment from 80-byte headers and a short proof."""
    chain, alice_coin = funded_chain()
    mine_blocks(chain, 5)  # let the miner's first five coins mature too
    payment = spend(chain, ALICE, alice_coin, [(lock(BOB), 49 * COIN)])
    miner_coins = [(outpoint, coin) for outpoint, coin in chain.utxos.items()
                   if coin.script_pubkey == lock(MINER)][:5]
    filler = [spend(chain, MINER, outpoint, [(lock(MINER), coin.amount - 1000)])
              for outpoint, coin in miner_coins]
    chain.add_block(build_block(chain, filler[:3] + [payment] + filler[3:], lock(MINER)))
    mine_blocks(chain, 5)

    client = LightClient(TINY)
    client.sync(chain)
    block_hash, index, proof = prove_transaction(chain, payment.hash())
    assert index == 4 and len(proof) == 3
    assert client.verify_payment(payment, block_hash, index, proof) == 6


def test_light_client_rejects_a_lying_full_node():
    chain, alice_coin = funded_chain()
    payment = spend(chain, ALICE, alice_coin, [(lock(BOB), 49 * COIN)])
    chain.add_block(build_block(chain, [payment], lock(MINER)))
    client = LightClient(TINY)
    client.sync(chain)
    block_hash, index, proof = prove_transaction(chain, payment.hash())
    never_sent = spend(chain, ALICE, alice_coin, [(lock(BOB), 50 * COIN - 1)],
                       coin_script=lock(ALICE))
    assert client.verify_payment(never_sent, block_hash, index, proof) == 0
    assert client.verify_payment(payment, bytes(32), index, proof) == 0  # unknown block
    assert client.verify_payment(payment, block_hash, index, [sha256d(b"lie")]) == 0


def test_a_reorg_unconfirms_a_payment():
    chain, alice_coin = funded_chain()
    fork_point = chain.tip
    payment = spend(chain, ALICE, alice_coin, [(lock(BOB), 49 * COIN)])
    chain.add_block(build_block(chain, [payment], lock(MINER), extra=b"A"))
    client = LightClient(TINY)
    client.sync(chain)
    proof = prove_transaction(chain, payment.hash())
    assert client.verify_payment(payment, *proof) == 1
    mine_blocks(chain, 2, parent=fork_point, extra=b"B")
    client.sync(chain)
    assert client.verify_payment(payment, *proof) == 0  # its block left the best chain


def test_checkpoint_the_whole_game(capsys):
    """Final checkpoint: `python -m tinybitcoin.demo` runs on your implementation."""
    from tinybitcoin import demo

    demo.main()
    story = capsys.readouterr().out
    assert "All nodes agree on block 110: True" in story
    assert "as far as Bitcoin knows, mallory never paid him" in story
    assert "confirms alice's book payment" in story
