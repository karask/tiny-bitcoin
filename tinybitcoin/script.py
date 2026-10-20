"""Chapter 6 · Script: programmable spending conditions.

Every output is locked by a small program, its scriptPubKey. To spend the
output, an input supplies another program, the scriptSig. A node runs the
scriptSig, then runs the scriptPubKey on the stack it left behind. The spend
is valid if this ends with a true value on top of the stack.

Script is a stack language with no loops, so every script terminates.
tiny-bitcoin implements the subset needed for P2PK, P2PKH and hash puzzles.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
from io import BytesIO

from .ecc import verify
from .encoding import int_to_little_endian, little_endian_to_int, read_exact
from .hashing import hash160, sha256, sha256d
from .keys import PrivateKey, decode_der, decode_sec, encode_der
from .tx import Tx, TxIn

OP_0 = 0x00
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1NEGATE = 0x4F
OP_1 = 0x51  # OP_2 ... OP_16 follow: 0x52 ... 0x60
OP_16 = 0x60
OP_NOP = 0x61
OP_VERIFY = 0x69
OP_RETURN = 0x6A
OP_DROP = 0x75
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_SHA256 = 0xA8
OP_HASH160 = 0xA9
OP_HASH256 = 0xAA
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD

SIGHASH_ALL = 0x01
MAX_PUSH_SIZE = 520  # bytes; the largest element a script may push

Cmd = int | bytes  # an opcode, or data to push
SignatureChecker = Callable[[bytes, bytes], bool]  # (signature + hash type, pubkey) -> valid?


# ---------------------------------------------------------------- parsing


def parse_script(script: bytes) -> list[Cmd]:
    """Split raw script bytes into commands.

    A byte n with 0x01 <= n <= 0x4b means "push the next n bytes".
    OP_PUSHDATA1/2/4 are followed by a 1/2/4-byte little-endian length, then
    that many bytes to push. Every other byte is an opcode (an int).
    Raise ValueError if a push runs past the end of the script.
    """
    # BEGIN SOLUTION ch06
    cmds: list[Cmd] = []
    s = BytesIO(script)
    while byte := s.read(1):
        op = byte[0]
        if 0x01 <= op <= 0x4B:
            cmds.append(read_exact(s, op))
        elif op == OP_PUSHDATA1:
            cmds.append(read_exact(s, little_endian_to_int(read_exact(s, 1))))
        elif op == OP_PUSHDATA2:
            cmds.append(read_exact(s, little_endian_to_int(read_exact(s, 2))))
        elif op == OP_PUSHDATA4:
            cmds.append(read_exact(s, little_endian_to_int(read_exact(s, 4))))
        else:
            cmds.append(op)
    return cmds
    # END SOLUTION


def serialize_script(cmds: list[Cmd]) -> bytes:
    """The inverse of parse_script.

    An int is one opcode byte. Bytes are pushed with the shortest encoding:
    a length byte for up to 75 bytes, OP_PUSHDATA1 for up to 255, and
    OP_PUSHDATA2 for up to MAX_PUSH_SIZE. Anything longer is a ValueError.
    """
    # BEGIN SOLUTION ch06
    out = b""
    for cmd in cmds:
        if isinstance(cmd, int):
            out += bytes([cmd])
        elif len(cmd) <= 0x4B:
            out += bytes([len(cmd)]) + cmd
        elif len(cmd) <= 0xFF:
            out += bytes([OP_PUSHDATA1, len(cmd)]) + cmd
        elif len(cmd) <= MAX_PUSH_SIZE:
            out += bytes([OP_PUSHDATA2]) + int_to_little_endian(len(cmd), 2) + cmd
        else:
            raise ValueError("push too large")
    return out
    # END SOLUTION


# ---------------------------------------------------------------- numbers and booleans


def encode_num(n: int) -> bytes:
    """Script's number format (provided): the magnitude as minimal little-endian
    bytes, with the sign in the top bit of the last byte. Zero is b""."""
    if n == 0:
        return b""
    magnitude, out = abs(n), bytearray()
    while magnitude:
        out.append(magnitude & 0xFF)
        magnitude >>= 8
    if out[-1] & 0x80:  # the top bit is taken, so add a byte to hold the sign
        out.append(0x80 if n < 0 else 0x00)
    elif n < 0:
        out[-1] |= 0x80
    return bytes(out)


def decode_num(b: bytes) -> int:
    """Inverse of encode_num (provided)."""
    if not b:
        return 0
    n = int.from_bytes(b, "little")
    if b[-1] & 0x80:
        return -(n & ~(0x80 << (8 * (len(b) - 1))))
    return n


def cast_to_bool(b: bytes) -> bool:
    """Script's truth (provided): false is all zero bytes, or "negative zero" (…0x80)."""
    for i, byte in enumerate(b):
        if byte:
            return not (i == len(b) - 1 and byte == 0x80)
    return False


def push_int(n: int) -> bytes:
    """The script that pushes the number n, like Bitcoin Core's `CScript() << n` (provided)."""
    if n == 0:
        return bytes([OP_0])
    if n == -1 or 1 <= n <= 16:
        return bytes([OP_1 + n - 1])
    return serialize_script([encode_num(n)])


# ---------------------------------------------------------------- opcodes
# Each takes the stack (a list of bytes, top at the end), changes it in place,
# and returns False if the script must fail.


def op_nop(stack: list[bytes]) -> bool:
    return True


def op_dup(stack: list[bytes]) -> bool:
    """Duplicate the top element. Fail on an empty stack."""
    # BEGIN SOLUTION ch06
    if not stack:
        return False
    stack.append(stack[-1])
    return True
    # END SOLUTION


def op_drop(stack: list[bytes]) -> bool:
    if not stack:
        return False
    stack.pop()
    return True


def op_equal(stack: list[bytes]) -> bool:
    """Pop two elements; push encode_num(1) if they are equal, else encode_num(0)."""
    # BEGIN SOLUTION ch06
    if len(stack) < 2:
        return False
    stack.append(encode_num(1 if stack.pop() == stack.pop() else 0))
    return True
    # END SOLUTION


def op_verify(stack: list[bytes]) -> bool:
    """Pop the top element; the script fails unless it is true (cast_to_bool)."""
    # BEGIN SOLUTION ch06
    if not stack:
        return False
    return cast_to_bool(stack.pop())
    # END SOLUTION


def op_equalverify(stack: list[bytes]) -> bool:
    return op_equal(stack) and op_verify(stack)


def op_return(stack: list[bytes]) -> bool:
    return False  # marks an output as provably unspendable


def op_sha256(stack: list[bytes]) -> bool:
    if not stack:
        return False
    stack.append(sha256(stack.pop()))
    return True


def op_hash160(stack: list[bytes]) -> bool:
    """Replace the top element with its HASH160."""
    # BEGIN SOLUTION ch06
    if not stack:
        return False
    stack.append(hash160(stack.pop()))
    return True
    # END SOLUTION


def op_hash256(stack: list[bytes]) -> bool:
    if not stack:
        return False
    stack.append(sha256d(stack.pop()))
    return True


OPS: dict[int, Callable[[list[bytes]], bool]] = {
    OP_NOP: op_nop,
    OP_VERIFY: op_verify,
    OP_RETURN: op_return,
    OP_DROP: op_drop,
    OP_DUP: op_dup,
    OP_EQUAL: op_equal,
    OP_EQUALVERIFY: op_equalverify,
    OP_SHA256: op_sha256,
    OP_HASH160: op_hash160,
    OP_HASH256: op_hash256,
}


def evaluate(cmds: list[Cmd], stack: list[bytes], check_sig: SignatureChecker) -> bool:
    """Run `cmds` on `stack`, changing it in place. Return False as soon as
    anything fails, True if the end is reached.

    * bytes: push them.
    * OP_0 pushes b"". OP_1NEGATE and OP_1..OP_16 push encode_num(-1) and
      encode_num(1)..encode_num(16).
    * OP_CHECKSIG: pop the public key, then the signature. Push
      encode_num(1) if check_sig(signature, public_key) else b"".
      OP_CHECKSIGVERIFY does the same, then op_verify.
    * Any other opcode: call its function in OPS. An opcode that is not in
      OPS makes the script fail.
    """
    # BEGIN SOLUTION ch06
    for cmd in cmds:
        if isinstance(cmd, bytes):
            stack.append(cmd)
        elif cmd == OP_0:
            stack.append(b"")
        elif cmd == OP_1NEGATE or OP_1 <= cmd <= OP_16:
            stack.append(encode_num(cmd - (OP_1 - 1)))
        elif cmd in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
            if len(stack) < 2:
                return False
            public_key, signature = stack.pop(), stack.pop()
            stack.append(encode_num(1) if check_sig(signature, public_key) else b"")
            if cmd == OP_CHECKSIGVERIFY and not op_verify(stack):
                return False
        elif cmd in OPS:
            if not OPS[cmd](stack):
                return False
        else:
            return False
    return True
    # END SOLUTION


# ---------------------------------------------------------------- signatures


def sig_hash(tx: Tx, index: int, script_code: bytes, hash_type: int = SIGHASH_ALL) -> int:
    """The number z that input `index`'s signature signs (legacy SIGHASH_ALL).

    Make a copy of the transaction in which every scriptSig is empty, except
    input `index`, whose scriptSig is replaced by `script_code` (the
    scriptPubKey being spent). Serialize the copy, append hash_type as 4
    little-endian bytes, take sha256d, and read it as a big-endian integer.
    """
    # BEGIN SOLUTION ch06
    inputs = [
        TxIn(txin.prevout, script_code if i == index else b"", txin.sequence)
        for i, txin in enumerate(tx.inputs)
    ]
    preimage = Tx(tx.version, inputs, tx.outputs, tx.locktime).serialize()
    return int.from_bytes(sha256d(preimage + int_to_little_endian(hash_type, 4)), "big")
    # END SOLUTION


@lru_cache(maxsize=1 << 16)
def verify_signature(public_key: bytes, der_signature: bytes, z: int) -> bool:
    """Decode and check one ECDSA signature (provided).

    Results are cached, like Bitcoin Core's signature cache: a transaction is
    checked when it enters the mempool and again when it arrives in a block.
    """
    try:
        return verify(decode_sec(public_key), z, decode_der(der_signature))
    except ValueError:
        return False


class TxSignatureChecker:
    """Checks signatures for one input of one transaction (Core's TransactionSignatureChecker)."""

    def __init__(self, tx: Tx, index: int, script_code: bytes):
        self.tx, self.index, self.script_code = tx, index, script_code

    def __call__(self, signature: bytes, public_key: bytes) -> bool:
        """`signature` is a DER signature followed by one hash-type byte.

        tiny-bitcoin supports only SIGHASH_ALL. Any other hash type, or an
        empty signature, is invalid. Compute z with sig_hash and check it
        with verify_signature.
        """
        # BEGIN SOLUTION ch06
        if not signature or signature[-1] != SIGHASH_ALL:
            return False
        z = sig_hash(self.tx, self.index, self.script_code)
        return verify_signature(public_key, signature[:-1], z)
        # END SOLUTION


def verify_input(tx: Tx, index: int, script_pubkey: bytes) -> bool:
    """May input `index` of `tx` spend an output locked by `script_pubkey`?

    Parse both scripts (a parse error means no). Evaluate the scriptSig on an
    empty stack, then the scriptPubKey on the same stack. Use one
    TxSignatureChecker(tx, index, script_pubkey). Valid if both succeed and
    the top of the final stack is true.

    Run them one after the other, not as one program. In July 2010 someone
    noticed that a scriptSig of OP_1 OP_RETURN could spend anybody's coins:
    the two scripts ran as one program, and OP_RETURN ended it early with a
    true value on the stack.
    """
    # BEGIN SOLUTION ch06
    try:
        script_sig = parse_script(tx.inputs[index].script_sig)
        locking = parse_script(script_pubkey)
    except ValueError:
        return False
    check_sig = TxSignatureChecker(tx, index, script_pubkey)
    stack: list[bytes] = []
    if not evaluate(script_sig, stack, check_sig) or not evaluate(locking, stack, check_sig):
        return False
    return bool(stack) and cast_to_bool(stack[-1])
    # END SOLUTION


# ---------------------------------------------------------------- standard scripts


def p2pk_script(public_key: bytes) -> bytes:
    """Pay-to-public-key, as in Bitcoin's first blocks: <pubkey> OP_CHECKSIG (provided)."""
    return serialize_script([public_key, OP_CHECKSIG])


def p2pkh_script(pubkey_hash: bytes) -> bytes:
    """Pay-to-public-key-hash: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG."""
    # BEGIN SOLUTION ch06
    return serialize_script([OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG])
    # END SOLUTION


def sign_p2pkh(tx: Tx, index: int, key: PrivateKey, script_pubkey: bytes) -> None:
    """Sign input `index`, which spends the P2PKH output `script_pubkey`.

    Set its scriptSig to: <DER signature + SIGHASH_ALL byte> <SEC public key>.
    """
    # BEGIN SOLUTION ch06
    z = sig_hash(tx, index, script_pubkey)
    signature = encode_der(key.sign(z)) + bytes([SIGHASH_ALL])
    tx.inputs[index].script_sig = serialize_script([signature, key.sec()])
    # END SOLUTION
