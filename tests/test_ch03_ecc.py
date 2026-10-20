"""Chapter 3 · Elliptic curves and ECDSA."""

import pytest

from tinybitcoin.ecc import (
    GX,
    GY,
    INFINITY,
    G,
    N,
    P,
    Point,
    Signature,
    recover_secret_from_reused_nonce,
    sign,
    verify,
)
from tinybitcoin.hashing import sha256

TWO_G = Point(
    0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
    0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
)
THREE_G = Point(
    0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
    0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672,
)


def z_of(message: bytes) -> int:
    return int.from_bytes(sha256(message), "big")


def test_points_off_the_curve_are_rejected():
    with pytest.raises(ValueError):
        Point(GX, GY + 1)


def test_infinity_is_the_identity():
    assert G + INFINITY == G
    assert INFINITY + G == G


def test_adding_a_point_to_its_negation_gives_infinity():
    assert G + Point(GX, P - GY) == INFINITY


def test_point_doubling_and_addition():
    assert G + G == TWO_G
    assert TWO_G + G == THREE_G
    assert G + TWO_G == THREE_G


def test_scalar_multiplication():
    assert 1 * G == G
    assert 2 * G == TWO_G
    assert 3 * G == THREE_G
    assert 0 * G == INFINITY
    assert N * G == INFINITY  # the group has exactly N elements
    assert (N + 2) * G == TWO_G
    a, b = 0xDEADBEEF, 0xC0FFEE
    assert (a + b) * G == a * G + b * G


def test_sign_and_verify():
    secret = 0x1234567890ABCDEF
    public_key = secret * G
    z = z_of(b"tiny-bitcoin")
    sig = sign(secret, z)
    assert verify(public_key, z, sig)
    assert not verify(public_key, z + 1, sig)  # a different message
    assert not verify(2 * public_key, z, sig)  # a different key
    assert not verify(public_key, z, Signature(sig.r, sig.s + 1))


def test_checkpoint_rfc6979_vector():
    # A widely used test vector (private key 1, message "Satoshi Nakamoto").
    sig = sign(1, z_of(b"Satoshi Nakamoto"))
    assert sig.r == 0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8
    assert sig.s == 0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5


def test_signatures_are_deterministic_and_low_s():
    for secret in range(1, 6):
        z = z_of(secret.to_bytes(4, "big"))
        assert sign(secret, z) == sign(secret, z)
        assert sign(secret, z).s <= N // 2


def test_out_of_range_signatures_are_invalid():
    z = z_of(b"x")
    assert not verify(G, z, Signature(0, 1))
    assert not verify(G, z, Signature(1, N))


def test_break_it_nonce_reuse_reveals_the_private_key():
    secret = 0xC0FFEE1234
    k = 0xBADBAD  # the bug: the same nonce for two different messages
    z1, z2 = z_of(b"pay Alice 1 BTC"), z_of(b"pay Bob 2 BTC")
    sig1, sig2 = sign(secret, z1, k=k), sign(secret, z2, k=k)
    assert sig1.r == sig2.r  # the tell-tale sign
    assert recover_secret_from_reused_nonce(z1, sig1, z2, sig2, secret * G) == secret
