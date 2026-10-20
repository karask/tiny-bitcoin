# Teaching with tiny-bitcoin

## Who it is for

Developers who are comfortable with Python functions, classes and `bytes`.
No Bitcoin or cryptography background is needed. Chapter 3 uses modular
arithmetic, so plan a 20-minute refresher on remainders and inverses.

## Formats

| Format | Plan |
|---|---|
| University course | One chapter a week: a lecture, then a lab. Twelve weeks, plus session 0 and a project. |
| Five-day bootcamp | Day 1: chapters 1-3. Day 2: 4-6. Day 3: 7-8. Day 4: 9-10. Day 5: 11-12 and the demo. |
| Self-study | Two to four hours per chapter. Chapters 3, 6, 8 and 9 take longest. |

## Session 0: play the whole game

Before any theory, run `python -m tinybitcoin.demo` and walk through its
output: mining, a payment, a network split that heals, a double spend that
succeeds, and a phone that checks a payment with headers alone. Show the
chapter table in the README. Learners stay motivated when they can see
the whole system they are about to build.

## A typical session

1. **The problem** (10 min). Read the whitepaper passage quoted in the
   chapter's *Why*. Ask what would break without this mechanism.
2. **Concepts** (15-20 min). Work at the board. Add two points on a tiny
   curve such as y² = x³ + 7 mod 17, or draw a Merkle tree with five leaves.
3. **Build** (60-90 min). Students work in pairs in their workbooks. The
   docstrings are the specification, and the tests give feedback.
4. **Break it** (15 min). Run the chapter's attack or historic bug together.
5. **Debrief** (10 min). Open Bitcoin Core at the function named under
   *Real Bitcoin* and compare it with what the class just wrote.

## Workbooks

The reference solution lives in `tinybitcoin/`. Each exercise is marked
`# BEGIN SOLUTION chNN` … `# END SOLUTION` inside a function.

```console
$ python tools/make_workbook.py workbook             # every exercise stubbed
$ python tools/make_workbook.py workbook --chapter 8 # chapters 1-7 solved
```

* **Distribute** the generated workbook as a template repository (GitHub
  Classroom works well), a branch or an archive. The reference solutions
  are in this repository. If students must not see them, keep the reference
  in a private repository and publish only workbooks.
* **Catch-up workbooks** solve the problem of the student who missed a week.
  They start the next chapter from a working base instead of staying behind.
* **Grading** is the test suite. Each file covers one chapter, so CI on a
  student repository shows their progress chapter by chapter.

## Where students get stuck

| Ch | Common mistakes |
|---|---|
| 1 | Mixing up displayed and internal byte order. Off by one at the varint boundary (0xfc or 0xfd). Comparing `bytes` with hex strings. |
| 2 | Comparing the hash to the target as big-endian. Forgetting the sign-bit adjustment in `target_to_bits`. |
| 3 | Confusing P (field arithmetic, coordinates) with N (scalars, signatures). Forgetting to reduce modulo P. Treating the point at infinity as (0, 0). |
| 4 | DER integers with the high bit set need a 0x00 byte. The parity of y for compressed keys. Base58's leading "1"s. |
| 5 | Script lengths and counts are varints. Outpoints store the txid in internal byte order. |
| 6 | In the sighash, only the input being signed gets the script code. The hash type is 1 byte on the signature but 4 bytes in the preimage. z is read big-endian. |
| 7 | Odd Merkle levels. Checks in the wrong order give the wrong reject reason. |
| 8 | Modifying the UTXO set before every check has passed. Coins created and spent in the same block. Off-by-one in coinbase maturity. |
| 9 | Ties: the block seen first wins. Restoring the old chain when the new branch is invalid. The retarget measures from `interval - 1` blocks back. |
| 10 | Treating policy as consensus. Change below the dust limit. |
| 11 | Relay loops: only announce what was newly accepted. Orphans that never connect. Iterating over a `set`, which makes simulations non-deterministic. |
| 12 | Left or right in a Merkle proof comes from the index bits. A proof must end with the index at 0. |

## Discussion questions

* Chapter 2: why is "longest chain" really "most work"? Construct a chain
  that is longer but weaker.
* Chapter 5: Bitcoin has no accounts. What does the UTXO model make easy,
  and what does it make hard?
* Chapter 8: why can nobody spend the genesis block's 50 BTC?
* Chapter 10: the mempool is policy. Who decides the rules, and what
  happens when nodes disagree?
* Chapter 11: how many confirmations would you wait for, buying coffee or
  buying a house?
* Chapter 12: a light client trusts the most-work chain to be valid. What
  could a miner majority do to light clients that it cannot do to full
  nodes?

## Extensions

Projects for after the course, in rough order of difficulty:

1. **Monte Carlo of whitepaper §11.** Race an attacker with `Network.mine_round`
   and compare the results with `attacker_success_probability`.
2. **Selfish mining** (Eyal and Sirer, 2013). Simulate it and find the
   hash-rate share at which it pays off.
3. **A fee market.** Give users random fee rates and more demand than block
   space, then watch the fees that get included.
4. **P2SH and multisig.** BIP 16, then `OP_CHECKMULTISIG`, including its
   extra "dummy" stack element (an off-by-one bug from 2009).
5. **Timelocks.** Enforce `locktime`, then `OP_CHECKLOCKTIMEVERIFY` (BIP 65).
6. **Replace-by-fee and child-pays-for-parent.** Allow unconfirmed parents
   in the mempool, then let a higher-fee transaction replace a conflict.
7. **SegWit.** Witness serialisation, `wtxid`, and the BIP 143 signature
   hash, then parse modern mainnet blocks.
8. **Schnorr and Taproot.** BIP 340 signatures on top of `ecc.py`.
9. **HD wallets.** BIP 32 key derivation.
10. **A real network.** TCP sockets and the `version`/`verack` handshake.
    TINY uses the same genesis block as Bitcoin Core's regtest, so try
    `bitcoin-cli -regtest submitblock <hex>` with your blocks. When Core
    refuses one, its reject reason names the rule tiny-bitcoin skipped.

## Maintaining the course

* Change the reference implementation and its tests. Never edit a
  workbook by hand: regenerate it.
* Keep every solution region inside a function and tag it with its
  chapter. Explain the exercise in the docstring, because students see the
  docstring and not the code.
* Name checkpoint tests `test_checkpoint_*` and attack tests
  `test_break_it_*`.
* CI runs `pytest`, `pytest tools`, `python tools/check_workbooks.py` and
  the demo. The workbook check proves that each chapter's tests pass with
  only earlier chapters solved, and fail while the chapter is stubbed.
