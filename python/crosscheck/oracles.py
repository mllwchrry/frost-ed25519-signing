"""External Ed25519 verifiers for the interop cross-check.

Each has the signature verify(msg, pubkey, sig) -> bool, or None when its
optional package is not installed:

  fork     ed25519lab.ed25519_verify: cofactorless, strict decode (the fork)
  solders  solders Signature.verify: Solana's ed25519-dalek verify_strict
  pynacl   libsodium crypto_sign_open: an independent second engine

dalek verify and verify_strict come from the Rust oracle (see run_crosscheck.py).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)  # python/

import frost_ref  # noqa: F401  (puts ed25519lab on sys.path)

from ed25519lab.verify import ed25519_verify

__all__ = [
    "fork_verify",
    "solders_verify",
    "pynacl_verify",
]


def fork_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    """The fork's verifier: cofactorless, rejecting non-prime-order A and R."""
    return ed25519_verify(msg, pubkey, sig)


def solders_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool | None:
    """Solana's own ed25519-dalek verify_strict, via the solders bindings."""
    try:
        from solders.pubkey import Pubkey
        from solders.signature import Signature
    except ImportError:
        return None
    try:
        pk = Pubkey(pubkey)
        s = Signature.from_bytes(sig)
    except Exception:  # bad key or signature bytes
        return False
    return bool(s.verify(pk, msg))


def pynacl_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool | None:
    """libsodium's crypto_sign_open, a fully independent second engine."""
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:
        return None
    try:
        VerifyKey(pubkey).verify(msg, sig)
        return True
    except (BadSignatureError, ValueError):
        return False
