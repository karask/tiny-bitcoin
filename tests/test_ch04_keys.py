"""Chapter 4 · Keys and addresses."""

import pytest
from vectors import (
    GENESIS_ADDRESS,
    GENESIS_PUBKEY_HEX,
    HAL_ADDRESS,
    HAL_PUBKEY_HEX,
    SATOSHI_ADDRESS,
    SATOSHI_PUBKEY_HEX,
)

from tinybitcoin.ecc import G, Signature
from tinybitcoin.keys import (
    PrivateKey,
    base58_encode,
    base58check_decode,
    base58check_encode,
    decode_der,
    decode_sec,
    encode_der,
    encode_sec,
    p2pkh_address,
)
from tinybitcoin.params import MAINNET, TINY

G_COMPRESSED = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
G_UNCOMPRESSED = (
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)


def test_encode_sec():
    assert encode_sec(G, compressed=True).hex() == G_COMPRESSED
    assert encode_sec(G, compressed=False).hex() == G_UNCOMPRESSED
    assert encode_sec(2 * G)[0] in (2, 3)


def test_decode_sec_round_trip():
    for k in (1, 2, 3, 0xDEADBEEF):
        point = k * G
        assert decode_sec(encode_sec(point, compressed=True)) == point
        assert decode_sec(encode_sec(point, compressed=False)) == point


@pytest.mark.parametrize("bad", ["", "05" + "11" * 32, "02" + "ff" * 32, G_COMPRESSED[:-2]])
def test_decode_sec_rejects_garbage(bad):
    with pytest.raises(ValueError):
        decode_sec(bytes.fromhex(bad))


def test_encode_der():
    sig = Signature(r=1, s=0x80)
    assert encode_der(sig).hex() == "3007" + "020101" + "02020080"  # 0x80 needs a 0x00 pad
    big = Signature(r=2**255, s=2**200)
    der = encode_der(big)
    assert der[0] == 0x30 and der[1] == len(der) - 2
    assert decode_der(der) == big


def test_der_round_trip_of_a_real_signature():
    # The signature Satoshi made in block 170 (chapter 6 verifies it).
    der = bytes.fromhex(
        "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41"
        "0220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09"
    )
    assert encode_der(decode_der(der)) == der


# Bitcoin Core's base58_encode_decode.json vectors.
@pytest.mark.parametrize(
    "hex_data, encoded",
    [
        ("", ""),
        ("61", "2g"),
        ("626262", "a3gV"),
        ("636363", "aPEr"),
        ("73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"),
        (
            "00eb15231dfceb60925886b67d065299925915aeb172c06647",
            "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
        ),
        ("516b6fcd0f", "ABnLTmg"),
        ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
        ("572e4794", "3EFU7m"),
        ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
        ("10c8511e", "Rt5zm"),
        ("00000000000000000000", "1111111111"),
    ],
)
def test_base58(hex_data, encoded):
    assert base58_encode(bytes.fromhex(hex_data)) == encoded


def test_base58check_round_trip_and_typo_detection():
    payload = bytes.fromhex("00751e76e8199196d454941c45d1b3a323f1433bd6")
    encoded = base58check_encode(payload)
    assert base58check_decode(encoded) == payload
    typo = encoded[:10] + ("2" if encoded[10] != "2" else "3") + encoded[11:]
    with pytest.raises(ValueError):
        base58check_decode(typo)


def test_addresses_of_private_key_1():
    assert PrivateKey(1).address(MAINNET.p2pkh_prefix) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    uncompressed = PrivateKey(1, compressed=False)
    assert uncompressed.address(MAINNET.p2pkh_prefix) == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"


def test_checkpoint_famous_addresses():
    """Checkpoint: derive the addresses of real public keys from 2009."""
    for pubkey_hex, address in [
        (GENESIS_PUBKEY_HEX, GENESIS_ADDRESS),  # the genesis block's coinbase
        (SATOSHI_PUBKEY_HEX, SATOSHI_ADDRESS),  # mined block 9
        (HAL_PUBKEY_HEX, HAL_ADDRESS),  # received the first payment
    ]:
        assert p2pkh_address(bytes.fromhex(pubkey_hex), MAINNET.p2pkh_prefix) == address


def test_tiny_addresses_look_like_testnet_ones():
    assert PrivateKey.from_passphrase("alice").address(TINY.p2pkh_prefix)[0] in "mn"
