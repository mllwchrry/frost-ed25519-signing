# ed25519lab

A small, pure-Python implementation of edwards25519 group and scalar arithmetic
and Ed25519 signatures, used by the FROST Ed25519 signing reference
implementation. It mirrors the API shape of `secp256k1lab` (`GE`, `Scalar`,
`tagged_hash`, ...) so the port from secp256k1 stays close to the original.

The point arithmetic and encode/decode are derived from the RFC 8032 reference
code (Revised BSD, IETF Trust). On top of that this library adds `GE`/`Scalar`
class wrappers, strict decoding (canonical-encoding rejection and a prime-order
subgroup check), 64-byte wide reduction for hash-to-scalar, tagged SHA-512,
raw-scalar key generation and the internal/standard signature schemes.

**Not for production.** This code is deliberately simple and is NOT
constant-time; it is intended for prototyping, test-vector generation and
education only.

## Modules

- `ed25519.py` — `GE` (points), `Scalar` (integers mod L), constants `B`, `L`, `p`
- `util.py` — `sha512`, `tagged_hash`, `xor_bytes`, `bytes_from_int`
- `schnorr.py` — `internal_sign`/`internal_verify` (protocol-internal, domain
  separated), `ed25519_sign` (RFC 8032, test cross-checks only), `ed25519_verify`
  (cofactorless, matching Solana / ed25519-dalek `verify_strict`)
- `ecdh.py` — `ecdh_ed25519` (used by the ChillDKG fork)
- `keys.py` — `pubkey_gen` (raw scalar → public key, no clamping)

## Conventions

- Points encode as the 32-byte RFC 8032 format; the identity encodes natively as
  `0x01 || 31*0x00` (there is no zero-byte sentinel).
- Scalars are integers mod L, serialized 32-byte little-endian.
- `from_bytes_compressed` is strict: it rejects non-canonical encodings and
  points outside the prime-order subgroup. It accepts the identity; callers
  reject it per-site via `P.infinity`.
- Hash outputs become scalars only via `Scalar.from_bytes_wide` (64-byte wide
  reduction). A checked 32-byte parse of a hash output fails ~15/16 of the time
  on this curve and must never be used for that purpose.
