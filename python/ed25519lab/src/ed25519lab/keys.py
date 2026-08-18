"""Key derivation for ed25519lab."""

from .ed25519 import B, Scalar


def pubkey_gen(seckey: bytes) -> bytes:
    """Public key [seckey]B from a raw 32-byte little-endian scalar.

    NO seed expansion and NO clamping: the scalar is used as is. This is the
    fundamental departure from standard Ed25519 key generation -- FROST secret
    material is raw scalars (clamping is not linear and would break Lagrange
    interpolation of shares).
    """
    d = Scalar.from_bytes_checked(seckey)
    return (d * B).to_bytes_compressed()
