"""Working reference implementation of edwards25519 group and scalar arithmetic.

Point arithmetic and encode/decode are derived from the RFC 8032 reference code
(Revised BSD, IETF Trust). This is a deliberately simple, NON-constant-time
implementation for prototyping, testing and education -- do not use it in
production.

Conventions fixed by this library:
* Points encode as the 32-byte RFC 8032 format (little-endian y, sign of x in
  the top bit). The identity encodes natively as 0x01 || 31*0x00.
* Scalars are integers mod L, serialized as 32-byte little-endian strings.
* from_bytes_compressed enforces canonical encoding AND prime-order subgroup
  membership. It accepts the identity (which is in the subgroup); callers reject
  it where their site policy requires, via `P.infinity`.
* Hash outputs become scalars only via from_bytes_wide (64-byte wide reduction).
  A checked 32-byte parse of a hash output fails with probability ~15/16 on this
  curve and must never be used for that purpose.
"""

from __future__ import annotations
from typing import Optional, Self, Tuple

# The field prime and the order of the prime-order subgroup.
p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493

# Curve constant d and a precomputed square root of -1.
_d = (-121665 * pow(121666, p - 2, p)) % p
_sqrtm1 = pow(2, (p - 1) // 4, p)

# Points are represented in extended twisted Edwards coordinates (X, Y, Z, T),
# with x = X/Z, y = Y/Z and x*y = T/Z.
_Point = Tuple[int, int, int, int]
_IDENTITY: _Point = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(_d * y * y + 1, p - 2, p) % p
    if x2 == 0:
        # x == 0: valid only with sign bit 0 (the +0 encoding is canonical).
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * _sqrtm1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


def _add(P: _Point, Q: _Point) -> _Point:
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    Bb = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * _d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, H = Bb - A, D - C, D + C, Bb + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def _mul(s: int, P: _Point) -> _Point:
    """Scalar multiplication by a non-negative integer s (double-and-add)."""
    Q = _IDENTITY
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P: _Point, Q: _Point) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True


class Scalar:
    """An integer modulo L. Serializes as 32-byte little-endian."""

    SIZE = L

    def __init__(self, v: int = 0) -> None:
        self.v = v % L

    @classmethod
    def _wrap(cls, v: int) -> Self:
        s = cls.__new__(cls)
        s.v = v % L
        return s

    @classmethod
    def from_bytes_checked(cls, b: bytes) -> Self:
        """32-byte little-endian scalar; raise ValueError if >= L."""
        if len(b) != 32:
            raise ValueError("scalar must be 32 bytes")
        v = int.from_bytes(b, "little")
        if v >= L:
            raise ValueError("scalar out of range")
        return cls._wrap(v)

    @classmethod
    def from_bytes_nonzero_checked(cls, b: bytes) -> Self:
        """As from_bytes_checked, but also raise ValueError if zero."""
        s = cls.from_bytes_checked(b)
        if s.v == 0:
            raise ValueError("scalar is zero")
        return s

    @classmethod
    def from_bytes_wide(cls, b: bytes) -> Self:
        """64-byte input (e.g. a SHA-512 output) interpreted little-endian and
        reduced mod L. The length assert turns misuse of a 32-byte hash into a
        loud error instead of a silent 15/16 failure."""
        if len(b) != 64:
            raise ValueError("wide reduction expects 64 bytes")
        return cls._wrap(int.from_bytes(b, "little") % L)

    def to_bytes(self) -> bytes:
        return self.v.to_bytes(32, "little")

    @classmethod
    def sum(cls, *ss: Self) -> Self:
        return cls._wrap(sum(s.v for s in ss))

    def __add__(self, a: int | Self) -> Self:
        if isinstance(a, Scalar):
            return type(self)._wrap(self.v + a.v)
        if isinstance(a, int):
            return type(self)._wrap(self.v + a)
        return NotImplemented

    def __sub__(self, a: int | Self) -> Self:
        if isinstance(a, Scalar):
            return type(self)._wrap(self.v - a.v)
        if isinstance(a, int):
            return type(self)._wrap(self.v - a)
        return NotImplemented

    def __mul__(self, a: int | Self) -> Self:
        if isinstance(a, Scalar):
            return type(self)._wrap(self.v * a.v)
        if isinstance(a, int):
            return type(self)._wrap(self.v * a)
        return NotImplemented

    def __truediv__(self, a: int | Self) -> Self:
        av = a.v if isinstance(a, Scalar) else (a % L)
        return type(self)._wrap(self.v * pow(av, L - 2, L))

    def __neg__(self) -> Self:
        return type(self)._wrap(-self.v)

    def __int__(self) -> int:
        return self.v

    def __eq__(self, a: object) -> bool:
        if isinstance(a, Scalar):
            return self.v == a.v
        if isinstance(a, int):
            return self.v == a % L
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.v)


class GE:
    """A point on edwards25519. GE() is the identity element (0, 1)."""

    ORDER = L

    def __init__(self, _pt: Optional[_Point] = None) -> None:
        # _pt is for internal construction; callers use GE() for the identity.
        self._pt: _Point = _IDENTITY if _pt is None else _pt

    @property
    def infinity(self) -> bool:
        """Whether this is the identity element (the Edwards neutral point)."""
        return _equal(self._pt, _IDENTITY)

    def to_bytes_compressed(self) -> bytes:
        """32-byte RFC 8032 encoding. The identity encodes as 0x01 || 31*0x00."""
        X, Y, Z, _ = self._pt
        zinv = pow(Z, p - 2, p)
        x = X * zinv % p
        y = Y * zinv % p
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    @staticmethod
    def from_bytes_compressed(b: bytes) -> GE:
        """Decode 32 RFC 8032 bytes -- strict. Raises ValueError on a wrong
        length, a non-canonical encoding (y >= p, or x = 0 with sign bit 1), an
        off-curve point, or a point outside the prime-order subgroup."""
        if len(b) != 32:
            raise ValueError("point must be 32 bytes")
        raw = int.from_bytes(b, "little")
        sign = raw >> 255
        y = raw & ((1 << 255) - 1)
        if y >= p:
            raise ValueError("non-canonical point encoding")
        x = _recover_x(y, sign)
        if x is None:
            raise ValueError("not a valid point")
        pt = (x, y, 1, x * y % p)
        # Prime-order subgroup check: [L]P must be the identity.
        if not _equal(_mul(L, pt), _IDENTITY):
            raise ValueError("point not in the prime-order subgroup")
        return GE(pt)

    @staticmethod
    def sum(*ps: GE) -> GE:
        acc = _IDENTITY
        for P in ps:
            acc = _add(acc, P._pt)
        return GE(acc)

    @staticmethod
    def batch_mul(*aps: Tuple[Scalar, GE]) -> GE:
        acc = _IDENTITY
        for a, P in aps:
            acc = _add(acc, _mul(a.v, P._pt))
        return GE(acc)

    def __add__(self, a: GE) -> GE:
        return GE(_add(self._pt, a._pt))

    def __neg__(self) -> GE:
        X, Y, Z, T = self._pt
        return GE((-X % p, Y, Z, -T % p))

    def __sub__(self, a: GE) -> GE:
        return self + (-a)

    def __rmul__(self, a: int | Scalar) -> GE:
        s = a.v if isinstance(a, Scalar) else (a % L)
        return GE(_mul(s, self._pt))

    def __eq__(self, a: object) -> bool:
        if isinstance(a, GE):
            return _equal(self._pt, a._pt)
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.to_bytes_compressed())


# The RFC 8032 base point (generator of the prime-order subgroup).
_g_y = 4 * pow(5, p - 2, p) % p
_g_x = _recover_x(_g_y, 0)
assert _g_x is not None
B = GE((_g_x, _g_y, 1, _g_x * _g_y % p))
