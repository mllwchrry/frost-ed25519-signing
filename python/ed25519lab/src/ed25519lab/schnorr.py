"""Signature schemes for ed25519lab.

Two distinct schemes with distinct domains:

* internal_sign/internal_verify -- the protocol-internal, domain-separated
  Schnorr scheme (used by ChillDKG for PoP and CertEq). The domain tag comes
  BEFORE R and the public key, which makes these signatures structurally
  unverifiable by any standard Ed25519 verifier.
* ed25519_sign/ed25519_verify -- standard RFC 8032 single-signer Ed25519.
  ed25519_sign is seed-based (with clamping) and exists for test cross-checks
  only; it is never called by the protocol. ed25519_verify is the COFACTORLESS
  check matching Solana / ed25519-dalek verify_strict.
"""

from .ed25519 import B, GE, Scalar
from .util import sha512, tagged_hash


def ed25519_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    """Standard Ed25519 verification, COFACTORLESS: [s]B == R + [e]A.

    Matches ed25519-dalek verify_strict / Solana: rejects s >= L, off-curve or
    small-order A and R (within the checked prime-order subgroup the only small-
    order element is the identity), then checks the cofactorless equation. This,
    not the cofactored RFC 8032 appendix equation, is the normative verifier for
    the fork's outputs.
    """
    if len(sig) != 64:
        return False
    try:
        A = GE.from_bytes_compressed(pubkey)
        R = GE.from_bytes_compressed(sig[0:32])
        s = Scalar.from_bytes_checked(sig[32:64])
    except ValueError:
        return False
    if A.infinity or R.infinity:
        return False
    e = Scalar.from_bytes_wide(sha512(sig[0:32] + pubkey + msg))
    return s * B == R + e * A


def ed25519_sign(msg: bytes, seed: bytes) -> bytes:
    """Standard RFC 8032 Ed25519 signing from a 32-byte seed (with clamping).

    Test cross-check helper ONLY -- the protocol has no seeds anywhere.
    """
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = sha512(seed)
    a_int = int.from_bytes(h[0:32], "little")
    a_int &= (1 << 254) - 8
    a_int |= 1 << 254
    a = Scalar(a_int)
    prefix = h[32:64]
    A_bytes = (a * B).to_bytes_compressed()
    r = Scalar.from_bytes_wide(sha512(prefix + msg))
    R_bytes = (r * B).to_bytes_compressed()
    e = Scalar.from_bytes_wide(sha512(R_bytes + A_bytes + msg))
    s = r + e * a
    return R_bytes + s.to_bytes()


def internal_sign(msg: bytes, seckey: bytes, aux_rand: bytes, tag_prefix: str) -> bytes:
    """Sign with the internal domain-separated Schnorr scheme; returns 64 bytes.

    seckey is a raw scalar (32 bytes LE, in [1, L)) -- no seed, no clamping. The
    domain tag precedes R and the public key, so the signature is structurally
    unverifiable outside the protocol. Deterministic nonce (single-party use):
        k = from_bytes_wide(tagged_hash(tag_prefix + "/nonce",
                                        seckey || aux_rand || msg))
    """
    d = Scalar.from_bytes_nonzero_checked(seckey)
    D_bytes = (d * B).to_bytes_compressed()
    k = Scalar.from_bytes_wide(
        tagged_hash(tag_prefix + "/nonce", seckey + aux_rand + msg)
    )
    R_bytes = (k * B).to_bytes_compressed()
    e = Scalar.from_bytes_wide(
        tagged_hash(tag_prefix + "/challenge", R_bytes + D_bytes + msg)
    )
    s = k + e * d
    return R_bytes + s.to_bytes()


def internal_verify(msg: bytes, pubkey: bytes, sig: bytes, tag_prefix: str) -> bool:
    """Verify an internal_sign signature (checks [s]B == R + [e]A)."""
    if len(sig) != 64:
        return False
    try:
        D = GE.from_bytes_compressed(pubkey)
        R = GE.from_bytes_compressed(sig[0:32])
        s = Scalar.from_bytes_checked(sig[32:64])
    except ValueError:
        return False
    e = Scalar.from_bytes_wide(
        tagged_hash(tag_prefix + "/challenge", sig[0:32] + pubkey + msg)
    )
    return s * B == R + e * D
