# The course

Every chapter has the same parts:

* **Why.** The problem this mechanism solves, and where the whitepaper
  argues for it (§ numbers refer to its sections).
* **You implement.** The functions to fill in. Their docstrings are the
  specification.
* **Checkpoint.** The test that shows you are done, usually against real
  Bitcoin data.
* **Break it.** An attack, or a bug from Bitcoin's history, to reproduce.
* **Real Bitcoin.** What the full system adds, and where to read it in
  Bitcoin Core.

Run a chapter's tests with `pytest tests/test_ch05_*.py`. Keep the
[whitepaper](https://bitcoin.org/bitcoin.pdf) open beside you; it is nine
pages long. Before chapter 1, run `python -m tinybitcoin.demo` to see where
you are heading.

---

## Chapter 1 · Bytes and hashes

**Why.** Everything Bitcoin agrees on is a hash of some bytes. If two nodes
serialise the same transaction differently, they compute different ids and
disagree. So the first job is getting bytes exactly right. "A timestamp
server works by taking a hash of a block of items to be timestamped and
widely publishing the hash" (§3).

**Concepts.** Little-endian integers. CompactSize "varints", and why a node
must reject non-canonical encodings. SHA-256d for ids and checksums. HASH160
(RIPEMD-160 of SHA-256) for short public-key hashes. Hashes are *displayed*
byte-reversed.

**You implement** (`encoding.py`, `hashing.py`): `int_to_little_endian`,
`little_endian_to_int`, `encode_varint`, `read_varint`, `hash_to_hex`,
`hex_to_hash`, `sha256d`, `hash160`.

**Checkpoint.** `test_checkpoint_hash_the_genesis_block`: hash Satoshi's
80-byte header and get `000000000019d668…`, the id every block explorer
shows for block 0.

**Break it.** Feed `read_varint` the bytes `fd0100`: the number 1, written
the long way. What could go wrong if a node accepted it? (Hint: what is a
txid a hash of?)

**Real Bitcoin.** `src/serialize.h` (CompactSize), `src/hash.h` (`CHash256`,
`CHash160`), and `uint256::GetHex`, which does the byte reversal.

---

## Chapter 2 · Block headers and proof-of-work

**Why.** A timestamp server needs someone to decide the order of events.
Proof-of-work lets anyone take part, as long as they spend real resources.
"The majority decision is represented by the longest chain, which has the
greatest proof-of-work effort invested in it" (§4).

**Concepts.** The 80-byte header. The target, and its compact `bits`
encoding: a tiny floating-point format with a sign bit inherited from
OpenSSL. Hashes read as 256-bit numbers. *Work*, the expected number of
hashes, which is 2²⁵⁶ / (target + 1). Mining: trying nonces.

**You implement** (`header.py`): `BlockHeader.serialize`, `.parse`, `.hash`,
`bits_to_target`, `target_to_bits`, `check_pow`, `block_work`, `mine`.

**Checkpoint.** `test_checkpoint_build_the_genesis_header_from_its_fields`.
Rebuild Satoshi's header field by field and get the famous hash. Also check
that the genesis block's work is exactly `0x100010001`, as Bitcoin Core
reports it.

**Break it.** Change the genesis timestamp by one second and check the
proof-of-work again. Then estimate how long your Python miner, at about one
microsecond per hash, would take to find a block at today's mainnet
difficulty.

**Real Bitcoin.** `src/primitives/block.h`, `src/arith_uint256.cpp`
(`SetCompact`, `GetCompact`), `src/pow.cpp` (`CheckProofOfWork`) and
`src/chain.cpp` (`GetBlockProof`). Real miners run out of nonces in a
fraction of a second, so they also change an "extra nonce" in the coinbase,
the timestamp and some version bits.

---

## Chapter 3 · Elliptic curves and ECDSA

**Why.** "We define an electronic coin as a chain of digital signatures"
(§2). Coins move when their owner signs. The signature must prove ownership
of a key without revealing the key.

**Concepts.** The curve y² = x³ + 7 over the integers modulo a prime.
Point addition (chord and tangent), the point at infinity, and scalar
multiplication by double-and-add. Why k·G is fast to compute and believed
to be infeasible to reverse. ECDSA signing and verification. Deterministic
nonces (RFC 6979) and low-S signatures.

**You implement** (`ecc.py`): `Point.__add__`, `Point.__rmul__`, `sign`,
`verify`, `recover_secret_from_reused_nonce`.

**Checkpoint.** `test_checkpoint_rfc6979_vector`: private key 1 signing
"Satoshi Nakamoto" gives the signature every RFC 6979 implementation
agrees on.

**Break it.** `test_break_it_nonce_reuse_reveals_the_private_key`: two
signatures that share a nonce give two linear equations, and you solve them
for the private key. This mistake exposed Sony's PlayStation 3 signing key
in 2010, and let thieves steal bitcoin from Android wallets in 2013.

**Real Bitcoin.** Bitcoin Core uses libsecp256k1. It is constant-time, so
it leaks nothing through timing, and it avoids a division at every step
(Jacobian coordinates). With precomputed tables and a special property of
this curve, it runs hundreds of times faster than your code. Taproot
(BIP 340) adds Schnorr signatures on the same curve.

---

## Chapter 4 · Keys, addresses and encodings

**Why.** Keys and signatures travel inside transactions as bytes, and
people must copy addresses without typos. "As an additional firewall, a new
key pair should be used for each transaction to keep them from being linked
to a common owner" (§10).

**Concepts.** SEC public keys, compressed (33 bytes) or uncompressed (65),
and recovering y from x. DER signatures, and why their integers sometimes
need a 0x00 byte in front. Base58 (no 0, O, I or l) and the Base58Check
checksum. A P2PKH address is Base58Check(version byte + HASH160(public key)).
Why brain wallets are dangerous.

**You implement** (`keys.py`): `encode_sec`, `decode_sec`, `encode_der`,
`base58_encode`, `base58check_encode`, `base58check_decode`,
`p2pkh_address`.

**Checkpoint.** `test_checkpoint_famous_addresses`: from public keys inside
2009 blocks, derive `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` (the genesis block),
Satoshi's address from block 9 and Hal Finney's.

**Break it.** Change one character of an address: how often would a typo
slip past a 4-byte checksum? Then compute the address of
`PrivateKey.from_passphrase("password")`. Bots sweep coins sent to
addresses like that within seconds.

**Real Bitcoin.** BIP 66 made strict DER a consensus rule, because
OpenSSL's parser accepted non-standard encodings and could split the
network. Modern wallets use Bech32 and Bech32m addresses (BIP 173,
BIP 350), and derive every key from one seed (BIP 32, BIP 39). See
`src/base58.cpp` and `src/key_io.cpp`.

---

## Chapter 5 · Transactions and the UTXO model

**Why.** "To allow value to be split and combined, transactions contain
multiple inputs and outputs" (§9). Bitcoin has no accounts. A transaction
consumes old outputs and creates new ones, and its id is the hash of its
bytes.

**Concepts.** Outpoints (txid, index), inputs, outputs, satoshis. The
coinbase transaction. Txids in internal versus display byte order.
*Malleability*: anything that changes a transaction's bytes without
invalidating it also changes its txid. That is why low-S signatures and
strict encodings matter, and it is the main reason SegWit exists.

**You implement** (`tx.py`): `serialize` and `parse` for `OutPoint`, `TxIn`,
`TxOut` and `Tx`, then `Tx.hash` and `Tx.is_coinbase`.

**Checkpoint.** `test_checkpoint_parse_the_first_payment`: decode the
transaction in block 170, where Satoshi pays Hal Finney 10 BTC and keeps
40 BTC as change, and recompute its txid `f4184fc5…`.

**Break it.** Where is the sender's address in a transaction? There is
none: why not? Where is the fee? There is no field for it either. Work out
the fee of the first payment.

**Real Bitcoin.** SegWit (BIP 141, BIP 144) moves signatures into a separate
*witness* that is not hashed into the txid. Modern transactions start with
marker and flag bytes; tiny-bitcoin rejects them with a clear error. See
`src/primitives/transaction.h`.

---

## Chapter 6 · Script

**Why.** An output should be able to say *how* it may be spent, not just
"by this key". So Bitcoin locks each output with a small program, and the
spender supplies that program's input.

**Concepts.** A stack machine without loops. Data pushes and opcodes.
Script numbers and truthiness. P2PK and P2PKH. The *signature hash*: what
exactly is signed, and why each input signs a copy of the transaction with
the spent output's script inserted. Running scriptSig and scriptPubKey as
separate programs.

**You implement** (`script.py`): `parse_script`, `serialize_script`,
`op_dup`, `op_equal`, `op_verify`, `op_hash160`, `evaluate`, `sig_hash`,
`TxSignatureChecker.__call__`, `verify_input`, `p2pkh_script`, `sign_p2pkh`.

**Checkpoint.** `test_checkpoint_verify_the_first_payment`: verify the
signature Satoshi made in January 2009, exactly as every node did then.
Then change one satoshi and watch it fail.

**Break it.** A hash puzzle, `OP_SHA256 <hash> OP_EQUAL`, can be spent by
anyone who knows the preimage, including a miner who copies it out of your
transaction. And in July 2010 the scriptSig `OP_1 OP_RETURN` could spend
anybody's coins, because both scripts ran as one program and `OP_RETURN`
ended it early. Make sure your `verify_input` refuses it.

**Real Bitcoin.** `src/script/interpreter.cpp` (`EvalScript`,
`SignatureHash`, `VerifyScript`). Full Script adds conditionals, multisig,
timelocks (BIP 65, BIP 112) and P2SH (BIP 16). There are more signature-hash
types, and new signature-hash algorithms for SegWit (BIP 143) and Taproot
(BIP 341). The legacy algorithm also involves `OP_CODESEPARATOR` and
`FindAndDelete`, which tiny-bitcoin omits.

---

## Chapter 7 · Blocks, Merkle trees and context-free validation

**Why.** An 80-byte header has to commit to every transaction in its block.
A Merkle tree does it, and lets a light client check one transaction without
downloading the rest (§7, §8).

**Concepts.** Block serialisation. Merkle roots, Bitcoin's "duplicate the
last hash" rule, and the ambiguity it creates. Checks that need nothing but
the block itself: proof-of-work, Merkle root, size, the coinbase's place,
and transaction sanity (amounts, duplicate inputs).

**You implement** (`block.py`): `Block.serialize`, `Block.parse`,
`merkle_root`, `check_transaction`, `check_block`.

**Checkpoint.** `test_checkpoint_rebuild_block_170`: compute block 170's
Merkle root from its two txids, rebuild its header and check its
proof-of-work.

**Break it.** Duplicate a block's last transaction: the Merkle root stays
the same (CVE-2012-2459), so `check_block` has to catch it another way.
Recreate the value overflow of August 2010, two outputs of 92 billion BTC
each (`test_break_it_the_value_overflow_incident`). In 2018, CVE-2018-17144
revealed that Bitcoin Core had stopped checking blocks for duplicate inputs.
What would a block that spends one coin twice do to the money supply?

**Real Bitcoin.** `src/consensus/merkle.cpp`, `src/consensus/tx_check.cpp`
(`CheckTransaction`), `src/validation.cpp` (`CheckBlock`). SegWit adds a
second Merkle tree, for witnesses, committed to inside the coinbase.
64-byte transactions are a known weakness: they look like inner Merkle
nodes.

---

## Chapter 8 · The UTXO set and block connection

**Why.** "The only way to confirm the absence of a transaction is to be
aware of all transactions" (§2). A node keeps the set of unspent outputs and
checks every new block against it. That set is what stops double spending.

**Concepts.** The UTXO set and its coins. Connecting a block atomically.
Fees, the block subsidy and its halvings (§6). Coinbase maturity. BIP 34,
the block height in the coinbase. Median time past and the two-hour limit
on future timestamps. Undo data, which chapter 9 needs.

**You implement** (`chain.py`): `block_subsidy`, `check_tx_inputs`,
`Chain.median_time_past`, `Chain.check_header`, `Chain.connect_block`.

**Checkpoint.** `test_checkpoint_alice_pays_bob`: mine 100 blocks so Alice's
reward matures, then pay Bob and watch the UTXO set and the miner's fee.
Also check that the subsidy schedule adds up to exactly 20,999,999.9769 BTC.

**Break it.** Try every way to cheat. Spend a coin twice in one block, then
in two blocks. Spend an immature coinbase, claim one satoshi too much, sign
with the wrong key. Each attempt must fail with Bitcoin Core's reject reason
and leave the UTXO set untouched.

**Real Bitcoin.** `src/validation.cpp` (`ConnectBlock`, `GetBlockSubsidy`),
`src/consensus/tx_verify.cpp` (`CheckTxInputs`) and `src/coins.h`, a layered
cache of coins over a database. BIP 30 and BIP 34 dealt with duplicate
coinbases, and BIP 42 fixed what would have happened after 64 halvings.
Core also limits the number of signature checks per block.

---

## Chapter 9 · Forks, reorganisations and difficulty

**Why.** Two miners sometimes find a block at the same moment. "If two
nodes broadcast different versions of the next block simultaneously, some
nodes may receive one or the other first. In that case, they work on the
first one they received, but save the other branch in case it becomes
longer" (§5). "Longer" really means *more work*. And the work per block
must follow the network's hash power, "a moving average targeting an
average number of blocks per hour" (§4).

**Concepts.** The block tree, side branches and first-seen tie-breaking.
Finding the fork point. Disconnecting blocks with undo data. Reorganising,
and what to do when the new branch turns out to be invalid. Difficulty
retargeting every 2016 blocks, the 4x clamp, and the famous off-by-one.

**You implement** (`chain.py`, `header.py`): `Chain.find_fork`,
`Chain.disconnect_block`, `Chain.activate_best_chain`, `Chain.next_bits`,
`retarget`.

**Checkpoint.** `test_checkpoint_retarget_matches_bitcoin_core`: four real
mainnet difficulty adjustments, from Bitcoin Core's own unit tests. And
`test_checkpoint_a_reorg_reverses_a_payment`: after a reorganisation your
UTXO set must equal that of a fresh node that only ever saw the winning
branch.

**Break it.** `test_most_work_wins_not_most_blocks`: a short branch of
hard blocks beats a long branch of easy ones. Then read about the
*time-warp attack*. How does the off-by-one in `next_bits` help it?
Could a majority of miners use it against your chain?

**Real Bitcoin.** `src/validation.cpp` (`ActivateBestChain`,
`DisconnectBlock`), `src/undo.h`, `src/pow.cpp` (`GetNextWorkRequired`) and
`src/chain.cpp` (`GetMedianTimePast`). Core keeps candidate tips in a set
sorted by work instead of scanning, and stores undo data in `rev*.dat` files.

---

## Chapter 10 · Wallet, mempool and mining

**Why.** "New transactions are broadcast to all nodes. Each node collects
new transactions into a block" (§5). Something has to hold unconfirmed
transactions, decide which to mine, and build payments in the first place.

**Concepts.** *Policy versus consensus*: mempool rules are each node's own
choice, block rules are everyone's. First-seen conflicts. Minimum fee rates.
Following the chain: dropping confirmed and conflicting transactions, and
re-adding them after a reorg. Coin selection, change and dust. Choosing
transactions by fee rate.

**You implement** (`mempool.py`, `wallet.py`, `miner.py`): `Mempool.accept`,
`Mempool.update`, `Wallet.create_payment`, `select_transactions`.

**Checkpoint.** `test_checkpoint_mine_the_mempool`: Alice pays Bob from her
wallet, a miner fills a block from the mempool, and the coinbase collects
exactly the subsidy plus the fee.

**Break it.** `test_policy_is_not_consensus`: every mempool refuses a
transaction that pays no fee, yet a miner may still put it in a valid block.
What does that say about "the rules of Bitcoin"?

**Real Bitcoin.** `src/validation.cpp` (`MemPoolAccept`), `src/txmempool.cpp`,
`src/node/miner.cpp` and `src/wallet/spend.cpp`, where several coin-selection
algorithms compete and the best result wins. Core allows chains of
unconfirmed transactions, so it selects groups of related transactions by
fee rate. It accepts fee-bumping replacements (BIP 125, and since version 28
any replacement by default). It also caps the mempool's size and evicts the
cheapest transactions.

---

## Chapter 11 · The peer-to-peer network

**Why.** There is no server. Blocks and transactions spread by gossip, and
"nodes can leave and rejoin the network at will, accepting the proof-of-work
chain as proof of what happened while they were gone" (§12). The network
must converge even after it splits. Now you can also attack it.

**Concepts.** The message envelope: magic, command, length, checksum.
`inv`/`getdata` gossip, and relaying only what you have validated. Orphan
blocks and catching up. Network partitions. The double-spend attack, and
the whitepaper's calculation of its odds (§11).

**You implement** (`network.py`): `Message.serialize`, `Message.parse`,
`Node.on_inv`, `Node.on_getdata`, `Node.on_tx`, `Node.on_block`,
`attacker_success_probability`.

**Checkpoint.** `test_checkpoint_partition_and_heal`: split the network,
let both halves mine, heal it, and watch every node converge on the side
with more work. A payment confirmed only on the losing side goes back to
the mempool and confirms again. `test_whitepaper_attacker_success_probability`
reproduces the tables printed in §11.

**Break it.** `test_break_it_double_spend_with_a_secret_chain`: Mallory pays
a merchant, waits for one confirmation, then releases a longer secret branch
that refunds her. Next, give her a share q of the hash rate and run the race
with `Network.mine_round` a few thousand times. Does her success rate match
the whitepaper's formula?

**Real Bitcoin.** `src/net.cpp` and `src/net_processing.cpp`. Real nodes
start with a `version`/`verack` handshake, and since version 0.10 (2015)
they download headers first instead of chasing orphans. They also relay
compact blocks (BIP 152), gossip peer addresses, encrypt connections
(BIP 324) and defend against denial-of-service and eclipse attacks. Your
`verack` message, though, is byte-for-byte the real one.

---

## Chapter 12 · Light clients

**Why.** A phone cannot store every block. "It is possible to verify
payments without running a full network node" (§8): keep only the headers,
follow the most work, and ask full nodes for Merkle proofs.

**Concepts.** Header chains. Merkle proofs, about log₂(n) hashes per
transaction. Confirmations. What a light client can check, what it cannot,
and whom it trusts.

**You implement** (`spv.py`): `merkle_proof`, `verify_merkle_proof`,
`LightClient.add_header`, `LightClient.confirmations`,
`LightClient.verify_payment`.

**Checkpoint.** `test_checkpoint_verify_a_payment_with_headers_only`, then
the final checkpoint, `test_checkpoint_the_whole_game`. Once
`python -m tinybitcoin.demo` runs on your workbook, you have built Bitcoin.

**Break it.** Play a lying full node: send a proof for a transaction that
was never mined, or for a block the client has never seen. Then consider
what a light client *cannot* detect: an invalid transaction inside a block
with valid proof-of-work.

**Real Bitcoin.** BIP 37 bloom filters (bad for privacy, and off by default
in Bitcoin Core since 2019), BIP 157 and BIP 158 compact block filters, and
the 64-byte transaction weakness from chapter 7.

---

## After the course

Read the Bitcoin Core functions named in each chapter. Run Core with
`-regtest` and recreate each chapter's scenario with `bitcoin-cli`. Then
pick a feature from [simplifications.md](simplifications.md) and add it to
tiny-bitcoin. [instructors.md](instructors.md#extensions) has project ideas.
