"""Chapter 6 · Script."""

from io import BytesIO

import pytest
from vectors import HAL_PUBKEY_HEX, SATOSHI_PUBKEY_HEX, SATOSHI_TO_HAL_TX_HEX

from tinybitcoin.hashing import hash160, sha256
from tinybitcoin.keys import PrivateKey
from tinybitcoin.script import (
    OP_0,
    OP_1,
    OP_1NEGATE,
    OP_16,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_PUSHDATA1,
    OP_PUSHDATA2,
    OP_RETURN,
    OP_SHA256,
    encode_num,
    evaluate,
    op_dup,
    op_equal,
    op_hash160,
    op_verify,
    p2pk_script,
    p2pkh_script,
    parse_script,
    serialize_script,
    sig_hash,
    sign_p2pkh,
    verify_input,
)
from tinybitcoin.tx import OutPoint, Tx, TxIn, TxOut


def satoshi_p2pk() -> bytes:
    """The P2PK output (from block 9) that the first payment spends."""
    return p2pk_script(bytes.fromhex(SATOSHI_PUBKEY_HEX))


def first_payment() -> Tx:
    return Tx.parse(BytesIO(bytes.fromhex(SATOSHI_TO_HAL_TX_HEX)))


def spend_of(script_sig: bytes) -> Tx:
    """A transaction whose only input has the given scriptSig."""
    return Tx(1, [TxIn(OutPoint(b"\x11" * 32, 0), script_sig)], [TxOut(1000, b"")])


def no_signatures(signature: bytes, public_key: bytes) -> bool:
    raise AssertionError("this script should not check signatures")


def test_parse_p2pk_script():
    assert parse_script(satoshi_p2pk()) == [bytes.fromhex(SATOSHI_PUBKEY_HEX), OP_CHECKSIG]


def test_pushdata_round_trips():
    for size, prefix in [(75, bytes([75])), (100, bytes([OP_PUSHDATA1, 100]))]:
        script = prefix + bytes(size) + bytes([OP_DUP])
        assert parse_script(script) == [bytes(size), OP_DUP]
        assert serialize_script([bytes(size), OP_DUP]) == script
    script = bytes([OP_PUSHDATA2]) + (300).to_bytes(2, "little") + bytes(300)
    assert parse_script(script) == [bytes(300)]
    assert serialize_script([bytes(300)]) == script


def test_parse_rejects_truncated_pushes():
    with pytest.raises(ValueError):
        parse_script(bytes([5, 1, 2]))


def test_serialize_rejects_oversized_pushes():
    with pytest.raises(ValueError):
        serialize_script([bytes(521)])


def test_stack_operations():
    stack = [b"a"]
    assert op_dup(stack) and stack == [b"a", b"a"]
    assert op_equal(stack) and stack == [encode_num(1)]
    assert op_verify(stack) and stack == []
    assert not op_verify([encode_num(0)])
    assert not op_dup([])
    stack = [b"hello"]
    assert op_hash160(stack) and stack == [hash160(b"hello")]


def test_evaluate_pushes_numbers():
    stack: list[bytes] = []
    assert evaluate([OP_0, OP_1NEGATE, OP_1, OP_16, b"\xab"], stack, no_signatures)
    assert stack == [b"", encode_num(-1), encode_num(1), encode_num(16), b"\xab"]


def test_unknown_or_disabled_opcodes_fail():
    assert not evaluate([OP_1, 0x7E], [], no_signatures)  # OP_CAT, disabled in 2010


def test_hash_puzzle():
    # Anyone who knows the preimage can spend this, including a miner who copies
    # it out of your transaction. That is why real outputs require signatures.
    locking = serialize_script([OP_SHA256, sha256(b"open sesame"), OP_EQUAL])
    assert verify_input(spend_of(serialize_script([b"open sesame"])), 0, locking)
    assert not verify_input(spend_of(serialize_script([b"open barley"])), 0, locking)


def test_op_return_outputs_are_unspendable():
    locking = serialize_script([OP_RETURN, b"hello, world"])
    assert not verify_input(spend_of(serialize_script([OP_1])), 0, locking)


def test_break_it_the_1_return_bug_is_fixed():
    # In July 2010 this scriptSig could spend *any* output.
    locking = p2pkh_script(hash160(PrivateKey.from_passphrase("victim").sec()))
    assert not verify_input(spend_of(serialize_script([OP_1, OP_RETURN])), 0, locking)


def test_sig_hash_of_the_first_payment():
    expected = 0x7A05C6145F10101E9D6325494245ADF1297D80F8F38D4D576D57CDBA220BCB19
    assert sig_hash(first_payment(), 0, satoshi_p2pk()) == expected


def test_checkpoint_verify_the_first_payment():
    """Checkpoint: verify Satoshi's signature from block 170, as every node did in 2009."""
    assert verify_input(first_payment(), 0, satoshi_p2pk())


def test_tampering_breaks_the_signature():
    tx = first_payment()
    tx.outputs[0].amount += 1  # Hal tries to give himself one more satoshi
    assert not verify_input(tx, 0, satoshi_p2pk())
    hal_p2pk = p2pk_script(bytes.fromhex(HAL_PUBKEY_HEX))
    assert not verify_input(first_payment(), 0, hal_p2pk)  # not Hal's coin to spend


def test_only_sighash_all_is_supported():
    tx = first_payment()
    [signature] = parse_script(tx.inputs[0].script_sig)
    tx.inputs[0].script_sig = serialize_script([signature[:-1] + b"\x03"])  # SIGHASH_SINGLE
    assert not verify_input(tx, 0, satoshi_p2pk())


def test_p2pkh_script_layout():
    h = bytes(range(20))
    assert p2pkh_script(h).hex() == "76a914" + h.hex() + "88ac"


def test_sign_and_spend_p2pkh():
    alice, bob = PrivateKey.from_passphrase("alice"), PrivateKey.from_passphrase("bob")
    locking = p2pkh_script(hash160(alice.sec()))
    tx = Tx(1, [TxIn(OutPoint(b"\x22" * 32, 3))], [TxOut(4000, p2pkh_script(hash160(bob.sec())))])
    sign_p2pkh(tx, 0, alice, locking)
    assert verify_input(tx, 0, locking)

    stolen = Tx(1, [TxIn(OutPoint(b"\x22" * 32, 3))], [TxOut(4000, b"")])
    sign_p2pkh(stolen, 0, bob, locking)  # Bob's key does not hash to Alice's hash
    assert not verify_input(stolen, 0, locking)

    tx.outputs[0].amount = 4001  # changing the transaction after signing
    assert not verify_input(tx, 0, locking)
