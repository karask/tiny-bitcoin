# tiny-bitcoin

Learn how Bitcoin works by building a small but **real** Bitcoin node, one
mechanism at a time, in plain Python.

By the last chapter you will have written a node that verifies Satoshi's
first payment to Hal Finney, agrees with Bitcoin Core about difficulty
adjustments on mainnet history, mines, gossips with peers and survives a
network split. You will also watch it fall to the double-spend attack that
section 11 of the whitepaper analyses. It takes about 1,500 lines of code,
has no dependencies, and runs anywhere Python 3.10+ does.

```console
$ python -m tinybitcoin.demo        # watch the finished system run
```

## How the course works

There are twelve chapters, and each one adds one mechanism. In each chapter you:

1. **Read why Bitcoin needs it.** [`docs/course.md`](docs/course.md) follows
   the argument of the whitepaper: every mechanism fixes a problem that the
   previous ones left open.
2. **Implement it.** Fill in a handful of functions in your *workbook*. The
   docstrings are the specification.
3. **Run the chapter's tests until they pass.** Every chapter ends with a
   *checkpoint* test against real Bitcoin data.
4. **Break it.** Every chapter has an attack or a historic bug to reproduce,
   because the rules make sense once you have seen what they prevent.

| # | Chapter | You build | Checkpoint |
|---|---|---|---|
| 1 | Bytes and hashes | little-endian, varints, SHA-256d, HASH160 | hash the genesis block |
| 2 | Proof-of-work | 80-byte headers, targets and `bits`, mining | rebuild Satoshi's genesis header |
| 3 | Elliptic curves | secp256k1 point arithmetic, ECDSA | recover a key from a reused nonce |
| 4 | Keys and addresses | SEC, DER, Base58Check, P2PKH | derive the genesis, Satoshi and Hal addresses |
| 5 | Transactions | inputs, outputs, txids | decode the first payment between people |
| 6 | Script | a stack machine, sighash, signing | verify Satoshi's signature from block 170 |
| 7 | Blocks | Merkle trees, consensus sanity checks | rebuild block 170; reject a mutated block |
| 8 | The UTXO set | connecting blocks, subsidy, maturity | run a chain where Alice pays Bob |
| 9 | Forks and difficulty | reorganisations, most work wins, retargeting | match Bitcoin Core's difficulty tests |
| 10 | Wallet, mempool, miner | coin selection, policy, block templates | mine the mempool and collect the fees |
| 11 | The network | gossip, orphan blocks, partitions | heal a split network; double-spend attack |
| 12 | Light clients | Merkle proofs, header chains | verify a payment from headers alone |

## Quick start

**Students.** Make a workbook (or use the one your instructor gives you), then
work through it chapter by chapter:

```console
$ python tools/make_workbook.py workbook
$ cd workbook
$ pip install pytest
$ pytest tests/test_ch01_hashes.py     # fails until you finish chapter 1
```

Stuck, or joining late? `python tools/make_workbook.py workbook --chapter 6`
makes a workbook with chapters 1-5 already solved.

**Instructors.** Read [`docs/instructors.md`](docs/instructors.md) for session
plans, common stumbling blocks and extension projects.

## Design principles

* **Simplify the scope, never the semantics.** tiny-bitcoin uses Bitcoin's
  real byte formats, hashes, Script and consensus rules for the subset it
  covers. That is why your code can check real blocks. Everything it leaves
  out (SegWit, P2SH, timelocks, RBF and more) is listed in
  [`docs/simplifications.md`](docs/simplifications.md).
* **Real data as checkpoints.** The genesis block, block 170, Bitcoin Core's
  test vectors and the whitepaper's own tables.
* **Tests are the specification.** Over 200 tests, one file per chapter.
* **One source of truth.** The reference solution in `tinybitcoin/` marks
  each exercise with `# BEGIN SOLUTION chNN` / `# END SOLUTION`.
  `tools/make_workbook.py` generates student workbooks from it, and CI
  checks that every chapter can be taken in order.
* **Build the system, then attack it.** Chapters 9-11 put many nodes in one
  deterministic, simulated network where you can cut links, race miners and
  replay attacks.
* **Point at the real thing.** Validation errors use Bitcoin Core's reject
  reasons, such as `bad-txns-inputs-missingorspent`, so you can find the same
  rule in Core's source. Each chapter ends with what Core does differently.

## Layout

```
tinybitcoin/        the reference implementation, one module per chapter
tests/              test_chNN_*.py: one test file per chapter
docs/course.md      the chapters: why, what to build, checkpoint, break it
docs/simplifications.md   what real Bitcoin does that we do not
docs/instructors.md how to teach with this
tools/              workbook generator and the chapter-by-chapter CI check
```

Run everything with `pytest` (the reference passes), `pytest tools`, and
`python tools/check_workbooks.py`.

> **Not for real money.** The elliptic-curve code is not constant-time and
> leaks secrets through timing. There is no protection against
> denial-of-service. TINY addresses use the testnet prefix (`m…`/`n…`) so
> nobody mistakes them for mainnet ones.
