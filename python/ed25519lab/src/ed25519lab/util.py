"""Hash and byte utilities for ed25519lab."""

import hashlib


def sha512(msg: bytes) -> bytes:
    """Plain SHA-512(msg), 64 bytes.

    Used for the untagged challenge e = SHA-512(R || A || m) mod L, which must
    match RFC 8032 / Solana byte-for-byte. Every other hash-to-scalar site uses
    tagged_hash instead.
    """
    return hashlib.sha512(msg).digest()


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """SHA-512(tag.encode() || msg), 64 bytes.

    A plain prefix, NOT the BIP340 double-hash construction (SHA-512's 128-byte
    block makes the midstate trick moot). Callers pass the full namespaced tag,
    e.g. "FROST3-ed25519-v1/nonce".
    """
    return hashlib.sha512(tag.encode() + msg).digest()


def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(b0, b1))


def bytes_from_int(x: int) -> bytes:
    """Serialize an integer in [0, L) to 32 bytes, little-endian."""
    return x.to_bytes(32, "little")
