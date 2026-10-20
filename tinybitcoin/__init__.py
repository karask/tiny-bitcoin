"""tiny-bitcoin: a small but real Bitcoin, built one chapter at a time.

Each module is one step of the course (see docs/course.md):

    ch01  encoding.py, hashing.py   bytes, endianness, varints, SHA-256d, HASH160
    ch02  header.py                 block headers, targets, proof-of-work, mining
    ch03  ecc.py                    secp256k1 and ECDSA from scratch
    ch04  keys.py                   SEC/DER encodings, Base58Check, addresses
    ch05  tx.py                     transactions and the UTXO model
    ch06  script.py                 Script, signature hashes, P2PKH
    ch07  block.py                  blocks, Merkle trees, context-free validation
    ch08  chain.py                  the UTXO set and block connection
    ch09  chain.py, header.py       forks, reorgs and difficulty adjustment
    ch10  mempool.py, wallet.py, miner.py
    ch11  network.py                a peer-to-peer network (and attacks on it)
    ch12  spv.py                    light clients and Merkle proofs

`python -m tinybitcoin.demo` runs the finished system.

The code favours clarity over speed and is NOT safe for real money: the
elliptic-curve code is not constant-time and there is no protection against
denial-of-service. Use it to learn, then read Bitcoin Core.
"""

__version__ = "0.1.0"
