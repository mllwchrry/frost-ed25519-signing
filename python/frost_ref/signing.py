# FROST Ed25519 Signing reference implementation
#
# It's worth noting that many functions, types, and exceptions were directly
# copied or modified from the MuSig2 (BIP 327) reference code, found at:
# https://github.com/bitcoin/bips/blob/master/bip-0327/reference.py
#
# WARNING: This implementation is for demonstration purposes only and _not_ to
# be used in production environments. The code is vulnerable to timing attacks,
# for example.

from typing import List, Optional, Tuple, NewType, NamedTuple, Literal
import secrets

from ed25519lab.ed25519 import B, GE, Scalar
from ed25519lab.util import hash_sha512, tagged_hash, xor_bytes

PlainPk = NewType("PlainPk", bytes)
ContribKind = Literal["aggothernonce", "aggnonce", "psig", "pubnonce"]

# Tagged hash domain-separation tags for this fork's internal hashes, under the
# FROST3-ed25519-v1/ namespace (SHA-512 via tagged_hash). The challenge is NOT
# tagged: it is a plain SHA-512(R || A || m) so the aggregate signature verifies
# as a standard RFC 8032 / Solana Ed25519 signature (see get_session_values).
FROST_TAG_AUX = "FROST3-ed25519-v1/aux"
FROST_TAG_NONCE = "FROST3-ed25519-v1/nonce"
FROST_TAG_NONCECOEF = "FROST3-ed25519-v1/noncecoef"
FROST_TAG_DETERMINISTIC_NONCE = "FROST3-ed25519-v1/deterministic/nonce"

# There are two types of exceptions that can be raised by this implementation:
#   - ValueError for indicating that an input doesn't conform to some function
#     precondition (e.g. an input array is the wrong length, a serialized
#     representation doesn't have the correct format).
#   - InvalidContributionError for indicating that a signer (or the
#     coordinator) is misbehaving in the protocol.
#
# Assertions are used to (1) satisfy the type-checking system, and (2) check for
# inconvenient events that can't happen except with negligible probability (e.g.
# output of a hash function is 0) and can't be manually triggered by any
# signer.


# This exception is raised if a party (signer or nonce coordinator) sends invalid
# values. Actual implementations should not crash when receiving invalid
# contributions. Instead, they should hold the offending party accountable.
class InvalidContributionError(Exception):
    def __init__(self, signer_index: Optional[int], contrib: ContribKind) -> None:
        # index of the signer who sent the invalid value, or None for coordinator
        self.signer_index = signer_index
        self.contrib = contrib


def has_duplicates(lst: List[int]) -> bool:
    return len(set(lst)) != len(lst)


def derive_interpolating_value(ids: List[int], my_id: int) -> Scalar:
    assert my_id in ids
    assert 0 <= my_id < 2**32
    assert not has_duplicates(ids)
    num = Scalar(1)
    deno = Scalar(1)
    for curr_id in ids:
        if curr_id == my_id:
            continue
        num *= Scalar(curr_id + 1)
        deno *= Scalar(curr_id - my_id)
    return num / deno


def derive_thresh_pubkey(ids: List[int], pubshares: List[GE]) -> PlainPk:
    assert len(ids) == len(pubshares)
    A = GE()
    for my_id, X_i in zip(ids, pubshares):
        lam_i = derive_interpolating_value(ids, my_id)
        A += lam_i * X_i
    if A.is_identity:
        raise ValueError("The threshold pubkey must not be the identity element.")
    return PlainPk(A.to_bytes())


class SignersContext(NamedTuple):
    n: int
    t: int
    ids: List[int]
    pubshares: List[PlainPk]
    thresh_pk: PlainPk


def validate_signers_ctx(signers_ctx: SignersContext) -> None:
    n, t, ids, pubshares, thresh_pk = signers_ctx
    if t < 1 or t > n:
        raise ValueError("The threshold must be 1 <= t <= n.")
    if not t <= len(ids) <= n:
        raise ValueError("The number of signers must be between t and n.")
    if len(pubshares) != len(ids):
        raise ValueError("The pubshares and ids arrays must have the same length.")
    pubshare_points = []
    for idx, (i, pubshare) in enumerate(zip(ids, pubshares)):
        if not 0 <= i <= n - 1:
            raise ValueError(
                f"The participant identifier at index {idx} is out of range."
            )
        try:
            P = GE.from_bytes(pubshare)
        except ValueError:
            # A malformed pubshare is invalid pre-protocol input, not a protocol
            # contribution: the signers context is agreed upon before signing
            # begins, so we signal it with ValueError rather than blaming a
            # signer via InvalidContributionError.
            raise ValueError(f"Invalid pubshare at index {idx}.")
        pubshare_points.append(P)
    if has_duplicates(ids):
        raise ValueError("The participant identifier list contains duplicate elements.")
    if derive_thresh_pubkey(ids, pubshare_points) != thresh_pk:
        raise ValueError("The provided key material is incorrect.")


def nonce_hash(
    rand_: bytes,
    pubshare: PlainPk,
    thresh_pk: PlainPk,
    i: int,
    msg_prefixed: bytes,
    extra_in: bytes,
) -> bytes:
    buf = b""
    buf += rand_
    buf += len(pubshare).to_bytes(1, "big")
    buf += pubshare
    buf += len(thresh_pk).to_bytes(1, "big")
    buf += thresh_pk
    buf += msg_prefixed
    buf += len(extra_in).to_bytes(4, "big")
    buf += extra_in
    buf += i.to_bytes(1, "big")
    return tagged_hash(FROST_TAG_NONCE, buf)


def nonce_gen_internal(
    rand: bytes,
    secshare: Optional[bytes],
    pubshare: Optional[PlainPk],
    thresh_pk: Optional[PlainPk],
    msg: Optional[bytes],
    extra_in: Optional[bytes],
) -> Tuple[bytearray, bytes]:
    if secshare is not None:
        # XOR mask over the 32-byte secshare: truncate the hash to the secshare
        # width. It is a raw byte mask, never reduced to a scalar.
        rand_ = xor_bytes(secshare, tagged_hash(FROST_TAG_AUX, rand)[:32])
    else:
        rand_ = rand
    if pubshare is None:
        pubshare = PlainPk(b"")
    if thresh_pk is None:
        thresh_pk = PlainPk(b"")
    if msg is None:
        msg_prefixed = b"\x00"
    else:
        msg_prefixed = b"\x01"
        msg_prefixed += len(msg).to_bytes(8, "big")
        msg_prefixed += msg
    if extra_in is None:
        extra_in = b""
    k_1 = Scalar.from_bytes_wide(
        nonce_hash(rand_, pubshare, thresh_pk, 0, msg_prefixed, extra_in)
    )
    k_2 = Scalar.from_bytes_wide(
        nonce_hash(rand_, pubshare, thresh_pk, 1, msg_prefixed, extra_in)
    )
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0
    R1_partial = k_1 * B
    R2_partial = k_2 * B
    assert not R1_partial.is_identity
    assert not R2_partial.is_identity
    pubnonce = R1_partial.to_bytes() + R2_partial.to_bytes()
    # use mutable `bytearray` since secnonce need to be replaced with zeros during signing.
    secnonce = bytearray(k_1.to_bytes() + k_2.to_bytes())
    return secnonce, pubnonce


def nonce_gen(
    secshare: Optional[bytes],
    pubshare: Optional[PlainPk],
    thresh_pk: Optional[PlainPk],
    msg: Optional[bytes],
    extra_in: Optional[bytes],
) -> Tuple[bytearray, bytes]:
    if secshare is not None and len(secshare) != 32:
        raise ValueError("The optional byte array secshare must have length 32.")
    if pubshare is not None and len(pubshare) != 32:
        raise ValueError("The optional byte array pubshare must have length 32.")
    if thresh_pk is not None and len(thresh_pk) != 32:
        raise ValueError("The optional byte array thresh_pk must have length 32.")
    rand = secrets.token_bytes(32)
    return nonce_gen_internal(rand, secshare, pubshare, thresh_pk, msg, extra_in)


def nonce_agg(pubnonces: List[bytes]) -> bytes:
    aggnonce = b""
    for j in (1, 2):
        R_j = GE()
        for idx, pubnonce in enumerate(pubnonces):
            try:
                R_ij = GE.from_bytes(pubnonce[(j - 1) * 32 : j * 32])
            except ValueError:
                raise InvalidContributionError(idx, "pubnonce")
            R_j += R_ij
        aggnonce += R_j.to_bytes_with_identity()
    return aggnonce


class SessionContext(NamedTuple):
    signers_ctx: SignersContext
    aggnonce: bytes
    msg: bytes


def get_session_values(
    session_ctx: SessionContext,
) -> Tuple[List[int], List[PlainPk], Scalar, GE, Scalar]:
    (signers_ctx, aggnonce, msg) = session_ctx
    validate_signers_ctx(signers_ctx)
    _, _, ids, pubshares, thresh_pk = signers_ctx
    # sort the ids before serializing because ROAST paper considers them as a set
    ser_ids = serialize_ids(ids)
    b = Scalar.from_bytes_wide(
        tagged_hash(
            FROST_TAG_NONCECOEF,
            len(ids).to_bytes(4, "big") + ser_ids + aggnonce + thresh_pk + msg,
        )
    )
    assert b != 0
    try:
        R1 = GE.from_bytes_with_identity(aggnonce[0:32])
        R2 = GE.from_bytes_with_identity(aggnonce[32:64])
    except ValueError:
        # coordinator sent invalid aggnonce
        raise InvalidContributionError(None, "aggnonce")
    R_ = R1 + b * R2
    # If the aggregate nonce is the identity point, substitute the base point B. On
    # Ed25519 the identity point is encodable, but Solana's verifier rejects a small-
    # order R, so an identity-R signature could never verify; substituting B
    # keeps blame attribution runnable via partial_sig_verify.
    R = R_ if not R_.is_identity else B
    assert not R.is_identity
    e = Scalar.from_bytes_wide(hash_sha512(R.to_bytes() + thresh_pk + msg))
    assert e != 0
    return (ids, pubshares, b, R, e)


def serialize_ids(ids: List[int]) -> bytes:
    sorted_ids = sorted(ids)
    ser_ids = b"".join(i.to_bytes(4, byteorder="big", signed=False) for i in sorted_ids)
    return ser_ids


def sign(
    secnonce: bytearray, secshare: bytes, my_id: int, session_ctx: SessionContext
) -> bytes:
    (ids, pubshares, b, _, e) = get_session_values(
        session_ctx
    )  # internally validates signers_ctx
    try:
        k_1 = Scalar.from_bytes_nonzero_checked(bytes(secnonce[0:32]))
    except ValueError:
        raise ValueError("first secnonce value is out of range.")
    try:
        k_2 = Scalar.from_bytes_nonzero_checked(bytes(secnonce[32:64]))
    except ValueError:
        raise ValueError("second secnonce value is out of range.")
    # Overwrite the secnonce argument with zeros, so the subsequent calls of
    # sign with the same secnonce raise a ValueError.
    secnonce[:] = bytearray(b"\x00" * 64)
    try:
        d = Scalar.from_bytes_nonzero_checked(secshare)
    except ValueError:
        raise ValueError("The signer's secret share value is out of range.")
    P = d * B
    assert not P.is_identity
    my_pubshare = P.to_bytes()
    if my_pubshare not in pubshares:
        raise ValueError(
            "The signer's pubshare must be included in the list of pubshares."
        )
    if my_id not in ids:
        raise ValueError(
            "The signer's id must be present in the participant identifier list."
        )
    a = derive_interpolating_value(ids, my_id)
    s = k_1 + b * k_2 + e * a * d
    psig = s.to_bytes()
    R1_partial = k_1 * B
    R2_partial = k_2 * B
    assert not R1_partial.is_identity
    assert not R2_partial.is_identity
    pubnonce = R1_partial.to_bytes() + R2_partial.to_bytes()
    # Optional correctness check. The result of signing should pass signature verification.
    assert partial_sig_verify_internal(psig, my_id, pubnonce, my_pubshare, session_ctx)
    return psig


def det_nonce_hash(
    secshare_: bytes,
    my_id: int,
    ids: List[int],
    aggothernonce: bytes,
    thresh_pk: bytes,
    msg: bytes,
    i: int,
) -> bytes:
    buf = b""
    buf += secshare_
    buf += my_id.to_bytes(4, "big")
    buf += len(ids).to_bytes(4, "big")
    buf += serialize_ids(ids)
    buf += aggothernonce
    buf += thresh_pk
    buf += len(msg).to_bytes(8, "big")
    buf += msg
    buf += i.to_bytes(1, "big")
    return tagged_hash(FROST_TAG_DETERMINISTIC_NONCE, buf)


def deterministic_sign(
    secshare: bytes,
    my_id: int,
    aggothernonce: Optional[bytes],
    signers_ctx: SignersContext,
    msg: bytes,
    aux_rand: Optional[bytes],
) -> Tuple[bytes, bytes]:
    if aux_rand is not None:
        secshare_ = xor_bytes(secshare, tagged_hash(FROST_TAG_AUX, aux_rand)[:32])
    else:
        secshare_ = secshare
    validate_signers_ctx(signers_ctx)
    _, _, ids, _, thresh_pk = signers_ctx

    # A sole signer (u = 1) has no other nonces to aggregate, so aggothernonce is
    # omitted. Bind the empty byte string into the nonce hash and use the signer's
    # own pubnonce as the aggregate nonce below.
    if aggothernonce is None:
        aggothernonce_ = b""
    else:
        aggothernonce_ = aggothernonce

    k_1 = Scalar.from_bytes_wide(
        det_nonce_hash(secshare_, my_id, ids, aggothernonce_, thresh_pk, msg, 0)
    )
    k_2 = Scalar.from_bytes_wide(
        det_nonce_hash(secshare_, my_id, ids, aggothernonce_, thresh_pk, msg, 1)
    )
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0

    R1_partial = k_1 * B
    R2_partial = k_2 * B
    assert not R1_partial.is_identity
    assert not R2_partial.is_identity
    pubnonce = R1_partial.to_bytes() + R2_partial.to_bytes()
    secnonce = bytearray(k_1.to_bytes() + k_2.to_bytes())
    if aggothernonce is None:
        aggnonce = pubnonce
    else:
        try:
            aggnonce = nonce_agg([pubnonce, aggothernonce])
        except InvalidContributionError:
            # pubnonce is always valid, so any failure is due to aggothernonce.
            raise InvalidContributionError(None, "aggothernonce")
    session_ctx = SessionContext(signers_ctx, aggnonce, msg)
    psig = sign(secnonce, secshare, my_id, session_ctx)
    return (pubnonce, psig)


def partial_sig_verify(
    psig: bytes,
    pubnonces: List[bytes],
    signers_ctx: SignersContext,
    msg: bytes,
    i: int,
) -> bool:
    validate_signers_ctx(signers_ctx)
    _, _, ids, pubshares, _ = signers_ctx
    if len(pubnonces) != len(ids):
        raise ValueError("The pubnonces and ids arrays must have the same length.")
    aggnonce = nonce_agg(pubnonces)
    session_ctx = SessionContext(signers_ctx, aggnonce, msg)
    return partial_sig_verify_internal(
        psig, ids[i], pubnonces[i], pubshares[i], session_ctx
    )


def partial_sig_verify_internal(
    psig: bytes,
    my_id: int,
    pubnonce: bytes,
    pubshare: bytes,
    session_ctx: SessionContext,
) -> bool:
    (ids, pubshares, b, _, e) = get_session_values(session_ctx)
    try:
        s = Scalar.from_bytes_checked(psig)
    except ValueError:
        return False
    if pubshare not in pubshares:
        return False
    if my_id not in ids:
        return False
    try:
        R1_partial = GE.from_bytes(pubnonce[0:32])
        R2_partial = GE.from_bytes(pubnonce[32:64])
    except ValueError:
        return False
    Re_s = R1_partial + b * R2_partial
    try:
        P = GE.from_bytes(pubshare)
    except ValueError:
        return False
    a = derive_interpolating_value(ids, my_id)
    return s * B == Re_s + (e * a) * P


def partial_sig_agg(psigs: List[bytes], session_ctx: SessionContext) -> bytes:
    (ids, _, _, R, _) = get_session_values(session_ctx)
    if len(psigs) != len(ids):  # get_session_values asserts len(pubshares) == len(ids)
        raise ValueError("The psigs and ids arrays must have the same length.")
    s = Scalar(0)
    for idx, psig in enumerate(psigs):
        try:
            s_i = Scalar.from_bytes_checked(psig)
        except ValueError:
            raise InvalidContributionError(idx, "psig")
        s += s_i
    return R.to_bytes() + s.to_bytes()
