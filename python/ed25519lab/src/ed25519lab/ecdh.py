"""ECDH for ed25519lab (used by the ChillDKG fork, not by signing)."""

from .ed25519 import GE, Scalar


def ecdh_ed25519(seckey: bytes, pubkey: bytes) -> bytes:
    """Return the 32-byte RFC 8032 encoding of [seckey]P_peer.

    pubkey is decoded with the strict rules (canonical, subgroup check), which
    closes the small-subgroup attack that would otherwise leak seckey mod 8 to a
    torsioned peer key. seckey is a raw scalar (32 bytes LE, in [1, L)),
    unclamped. Returns the raw shared-point encoding; the caller derives the
    symmetric key by hashing it together with both public keys and the session
    context (the KDF composition lives at the EncPedPop layer).
    """
    d = Scalar.from_bytes_nonzero_checked(seckey)
    P = GE.from_bytes_compressed(pubkey)
    return (d * P).to_bytes_compressed()
