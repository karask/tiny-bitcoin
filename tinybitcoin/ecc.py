"""Chapter 3 · Elliptic-curve cryptography: secp256k1 and ECDSA from scratch.

Bitcoin's signatures live on the curve y² = x³ + 7, with all arithmetic done
modulo the prime P. Points can be added together. Adding a point G to itself
k times (written k*G) is fast, but undoing it (finding k from k*G) is
believed to be infeasible. So a private key is a number k and its public key
is the point k*G.

WARNING: this code is for learning. It is not constant-time and leaks
secrets through timing. Never use it to protect real money.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from hashlib import sha256

P = 2**256 - 2**32 - 977  # the field prime
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # the group order
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


@dataclass(frozen=True)
class Point:
    """A point on secp256k1. Point(None, None) is the point at infinity: the "zero"."""

    x: int | None
    y: int | None

    def __post_init__(self) -> None:
        if self.x is not None and (self.y * self.y - self.x**3 - 7) % P != 0:
            raise ValueError("point is not on the curve")

    @property
    def is_infinity(self) -> bool:
        return self.x is None

    def __add__(self, other: Point) -> Point:
        """Add two points (all arithmetic modulo P; pow(a, -1, P) is 1/a).

        * Infinity is the identity: INFINITY + Q == Q.
        * If the points share x but are not equal, or are equal with y == 0,
          the line through them is vertical and the sum is INFINITY.
        * Otherwise draw the line with slope s through both points (the
          tangent if they are equal: s = 3x² / 2y). It meets the curve in a
          third point. Reflect that point across the x-axis:
              x3 = s² - x1 - x2,    y3 = s * (x1 - x3) - y1
        """
        # BEGIN SOLUTION ch03
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        if self.x == other.x and (self.y + other.y) % P == 0:
            return INFINITY
        if self == other:
            s = 3 * self.x * self.x * pow(2 * self.y, -1, P) % P
        else:
            s = (other.y - self.y) * pow(other.x - self.x, -1, P) % P
        x3 = (s * s - self.x - other.x) % P
        y3 = (s * (self.x - x3) - self.y) % P
        return Point(x3, y3)
        # END SOLUTION

    def __rmul__(self, k: int) -> Point:
        """Scalar multiplication k * point, by "double-and-add".

        Walk through the bits of k from least significant. Keep a running
        `result` (start: INFINITY) and an `addend` (start: self). For each
        bit: if it is 1, add addend to result. Then double addend.
        Reduce k modulo N first. The group has N elements, so N * P == INFINITY.
        """
        # BEGIN SOLUTION ch03
        k %= N
        result, addend = INFINITY, self
        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result
        # END SOLUTION


INFINITY = Point(None, None)
G = Point(GX, GY)  # the generator


@dataclass(frozen=True)
class Signature:
    r: int
    s: int


def deterministic_k(secret: int, z: int) -> int:
    """RFC 6979 nonce (provided): derive k from the private key and the message.

    The nonce must be secret and must never repeat (see the exercise at the
    end of this chapter). RFC 6979 derives it with HMAC-SHA256 from the key
    and the message hash, so no random number generator is involved.
    """
    x = secret.to_bytes(32, "big")
    h = (z % N).to_bytes(32, "big")
    k, v = b"\x00" * 32, b"\x01" * 32
    k = hmac.new(k, v + b"\x00" + x + h, sha256).digest()
    v = hmac.new(k, v, sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, sha256).digest()
    v = hmac.new(k, v, sha256).digest()
    while True:
        v = hmac.new(k, v, sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", sha256).digest()
        v = hmac.new(k, v, sha256).digest()


def sign(secret: int, z: int, k: int | None = None) -> Signature:
    """ECDSA-sign the message hash `z` with the private key `secret`.

        k = deterministic_k(secret, z)   (unless a k is passed in)
        r = x-coordinate of k*G, mod N
        s = (z + r * secret) / k  mod N

    Then if s > N // 2, replace it with N - s. Both are valid, but Bitcoin
    relays only "low-S" signatures (BIP 146) so a third party cannot flip s
    and change the transaction id (malleability, chapter 5).
    Only the nonce-reuse exercise below should ever pass `k` explicitly.
    """
    # BEGIN SOLUTION ch03
    if k is None:
        k = deterministic_k(secret, z)
    r = (k * G).x % N
    s = (z + r * secret) * pow(k, -1, N) % N
    if s > N // 2:
        s = N - s
    return Signature(r, s)
    # END SOLUTION


def verify(public_key: Point, z: int, sig: Signature) -> bool:
    """Check that `sig` is a valid signature of `z` by `public_key`.

    Require 1 <= r, s < N. Then compute
        u = z / s,  v = r / s   (mod N)
        R = u*G + v*public_key
    The signature is valid if R is not infinity and R.x mod N == r.
    """
    # BEGIN SOLUTION ch03
    if not (1 <= sig.r < N and 1 <= sig.s < N):
        return False
    s_inv = pow(sig.s, -1, N)
    R = (z * s_inv % N) * G + (sig.r * s_inv % N) * public_key
    return not R.is_infinity and R.x % N == sig.r
    # END SOLUTION


def recover_secret_from_reused_nonce(
    z1: int, sig1: Signature, z2: int, sig2: Signature, public_key: Point
) -> int:
    """Break it: two signatures made with the same nonce k reveal the private key.

    The same k gives the same r. From s1 = (z1 + r*e)/k and s2 = (z2 + r*e)/k:
        k = (z1 - z2) / (s1 - s2)       e = (s1*k - z1) / r      (mod N)
    Low-S normalisation may have flipped either s to N - s, so also try
    s2 -> N - s2. Return the candidate e for which e*G == public_key, or
    raise ValueError. (In 2010 this mistake exposed Sony's PlayStation 3
    signing key. In 2013 a broken random number generator on Android let
    thieves steal bitcoin the same way.)
    """
    # BEGIN SOLUTION ch03
    if sig1.r != sig2.r:
        raise ValueError("the signatures do not share a nonce")
    for s2 in (sig2.s, N - sig2.s):
        if (sig1.s - s2) % N == 0:
            continue
        k = (z1 - z2) * pow(sig1.s - s2, -1, N) % N
        secret = (sig1.s * k - z1) * pow(sig1.r, -1, N) % N
        if secret * G == public_key:
            return secret
    raise ValueError("could not recover the private key")
    # END SOLUTION
