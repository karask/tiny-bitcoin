# What tiny-bitcoin leaves out

tiny-bitcoin *simplifies scope, never semantics*. What it implements follows
Bitcoin's real formats and rules, which is why it can check real blocks.
This page lists what it leaves out. Every row is a possible extension
project.

## Transactions and Script

| Area | tiny-bitcoin | Real Bitcoin |
|---|---|---|
| Serialisation | Legacy only. SegWit transactions are rejected with a clear error. | SegWit marker, flag and witness (BIP 141, BIP 144). Witness txid (`wtxid`). |
| Opcodes | Pushes, `OP_0`-`OP_16`, `OP_NOP`, `OP_VERIFY`, `OP_RETURN`, `OP_DROP`, `OP_DUP`, `OP_EQUAL(VERIFY)`, `OP_SHA256`, `OP_HASH160`, `OP_HASH256`, `OP_CHECKSIG(VERIFY)` | About 100 opcodes, including `OP_IF`, `OP_CHECKMULTISIG` and timelocks, with limits on script size, stack size and opcode count. |
| Output types | P2PK, P2PKH, bare scripts | Also P2SH (BIP 16), P2WPKH and P2WSH (BIP 141), P2TR (BIP 341). |
| Signature hash | Legacy `SIGHASH_ALL`. No `OP_CODESEPARATOR` or `FindAndDelete`. | `ALL`, `NONE`, `SINGLE`, each optionally `ANYONECANPAY`. New algorithms for SegWit (BIP 143) and Taproot (BIP 341). |
| Signatures | ECDSA with strict DER parsing. Low-S when signing. | Same, plus Schnorr (BIP 340). Low-S (BIP 146) and other strictness rules are relay policy for legacy scripts. |
| Timelocks | `locktime` and `sequence` are carried but not enforced. | Final-transaction rules, BIP 65, BIP 68, BIP 112, BIP 113. |
| Amounts | Read as unsigned 64-bit integers. | Signed 64-bit (`CAmount`), so negative values can be parsed and are then rejected. |

## Blocks and consensus

| Area | tiny-bitcoin | Real Bitcoin |
|---|---|---|
| Size limit | 1,000,000 serialised bytes | 4,000,000 weight units (BIP 141) and a signature-operation budget. |
| Version | Not checked. Blocks use 0x20000000, like Bitcoin Core's miner. | Minimum versions after BIP 34, 66 and 65. Version bits signal soft forks (BIP 9). |
| Coinbase | BIP 34 height from block 1. Genesis output unspendable. | BIP 34 since block 227,931; BIP 30 duplicate checks before that. SegWit witness commitment. |
| Difficulty | Bitcoin's algorithm, off-by-one included. The TINY chain has an easy limit and keeps retargeting. | Same algorithm on mainnet. Testnet has special minimum-difficulty rules; regtest never retargets. |
| Time | Simulated network clock. Median time past and the 2-hour future limit are enforced. | The same rules, against the node's own clock. |
| Chain state | Python dictionaries, all in memory. | LevelDB chainstate, block and undo files on disk, pruning, assumeutxo snapshots. |
| Fork choice | Scans every known block for the most work. Blocks must arrive in full. | A work-sorted set of candidates. Headers are downloaded and checked first. |

## Mempool, mining and wallet

| Area | tiny-bitcoin | Real Bitcoin |
|---|---|---|
| Mempool | Confirmed inputs only, first-seen wins, 1 sat/byte minimum, no size limit. | Chains of unconfirmed transactions within limits, replace-by-fee (BIP 125, full RBF by default since v28), package relay, a size cap with eviction, expiry. |
| Block templates | Greedy by fee rate (valid because no transaction depends on another). | Groups of related transactions by fee rate. `getblocktemplate` (BIP 22/23) and mining pools. |
| Wallet | One key per wallet, P2PKH, largest-first coin selection, a fixed fee rate. Scans the UTXO set directly. | Descriptor wallets, HD keys (BIP 32), several competing coin-selection algorithms, fee estimation, privacy-aware change. |

## Network and light clients

| Area | tiny-bitcoin | Real Bitcoin |
|---|---|---|
| Transport | Deterministic in-process message queue with the real message envelope. | TCP (also Tor and I2P), the `version`/`verack` handshake, encrypted v2 transport (BIP 324). |
| Messages | `inv`, `getdata`, `tx`, `block` | Dozens: `headers`, `getheaders`, `addr`, compact blocks (BIP 152), `feefilter`, `ping`… |
| Sync | Orphan blocks: ask for each missing parent. | Headers-first since version 0.10 (2015), then parallel block download. |
| Defences | None. | Peer scoring, eviction, anti-eclipse logic, rate limits, protection against DoS. |
| Light clients | Check header linkage and proof-of-work, and verify Merkle proofs. | Also check difficulty transitions. Compact block filters (BIP 157, BIP 158); BIP 37 bloom filters are deprecated. |

## Cryptography and safety

| Area | tiny-bitcoin | Real Bitcoin |
|---|---|---|
| Elliptic curves | Pure Python, affine coordinates, not constant-time. | libsecp256k1: constant-time and heavily optimised. |
| Randomness | `secrets` for new keys. Brain wallets for reproducible tests. | Secure seeds (BIP 39), hardware wallets. |
| Signature cache | `functools.lru_cache` | A salted cache with care against DoS. |
