from frost_ref import InvalidContributionError, nonce_agg
from frost_ref.signing import nonce_gen_internal

from ed25519lab.ed25519 import B, Scalar

from generators.common import (
    COMMON_MSGS,
    COMMON_RAND,
    NONCANONICAL_POINT,
    OFFCURVE_POINT,
    SECKEY_2OF3,
    TORSION_POINT,
    bytes_list_to_hex,
    bytes_to_hex,
    expect_exception,
    frost_keygen,
    write_test_vectors,
)


def generate_nonce_gen_vectors():
    vectors = {}
    vectors["valid_tests"] = []
    tc_id = 1

    _, _, thresh_pk, _, secshares, pubshares = frost_keygen(SECKEY_2OF3)
    extra_in = bytes.fromhex(
        "0808080808080808080808080808080808080808080808080808080808080808"
    )

    # --- Valid Test Case 1 ---
    msg = bytes.fromhex(
        "0101010101010101010101010101010101010101010101010101010101010101"
    )
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND, secshares[0], pubshares[0], thresh_pk, msg, extra_in
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "All optional defense-in-depth arguments present",
            "rand": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(thresh_pk),
            "msg": bytes_to_hex(msg),
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 2 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND,
        secshares[0],
        pubshares[0],
        thresh_pk,
        COMMON_MSGS[1],
        extra_in,
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Empty message",
            "rand": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(thresh_pk),
            "msg": bytes_to_hex(COMMON_MSGS[1]),
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 3 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND,
        secshares[0],
        pubshares[0],
        thresh_pk,
        COMMON_MSGS[2],
        extra_in,
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Non-standard message length (38 bytes)",
            "rand": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(thresh_pk),
            "msg": bytes_to_hex(COMMON_MSGS[2]),
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 4 ---
    secnonce, pubnonce = nonce_gen_internal(COMMON_RAND, None, None, None, None, None)
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "All optional defense-in-depth arguments omitted",
            "rand": bytes_to_hex(COMMON_RAND),
            "secshare": None,
            "pubshare": None,
            "thresh_pk": None,
            "msg": None,
            "extra_in": None,
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 5 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND, secshares[0], pubshares[0], thresh_pk, None, extra_in
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Message omitted, other optional arguments present",
            "rand": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(thresh_pk),
            "msg": None,
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1

    write_test_vectors("nonce_gen_vectors.json", vectors)


def generate_nonce_agg_vectors():
    vectors = {}

    # Special pubnonce indices for test cases
    FIRST_HALF_NONCANONICAL_IDX = 4
    SECOND_HALF_OFFCURVE_IDX = 5
    SECOND_HALF_TORSION_IDX = 6

    # Constructed Ed25519 pubnonces (each 64 bytes = two 32-byte points). The
    # first four are well-formed; the last three each carry a different invalid
    # half so nonce_agg rejects them (non-canonical / off-curve / torsion).
    # Indices 2 and 3 have second halves that are negatives of each other, so
    # their aggregate second half is the identity point.
    def _pt(k):
        return (Scalar(k) * B).to_bytes()

    _P = Scalar(7) * B
    pubnonces = [
        _pt(2) + _pt(3),
        _pt(4) + _pt(5),
        _pt(6) + _P.to_bytes(),
        _pt(8) + (-_P).to_bytes(),
        NONCANONICAL_POINT + _pt(9),
        _pt(10) + OFFCURVE_POINT,
        _pt(11) + TORSION_POINT,
    ]
    vectors["pubnonces"] = bytes_list_to_hex(pubnonces)

    tc_id = 1
    vectors["valid_tests"] = []
    # --- Valid Test Case 1 ---
    pubnonce_indices = [0, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    aggnonce = nonce_agg(curr_pubnonces)
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Two well-formed public nonces",
            "pubnonce_indices": pubnonce_indices,
            "expected": bytes_to_hex(aggnonce),
        }
    )
    tc_id += 1
    # --- Valid Test Case 2 ---
    pubnonce_indices = [2, 3]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    aggnonce = nonce_agg(curr_pubnonces)
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Second halves sum to the identity element",
            "pubnonce_indices": pubnonce_indices,
            "expected": bytes_to_hex(aggnonce),
        }
    )
    tc_id += 1

    vectors["error_tests"] = []
    # --- Error Test Case 1 ---
    pubnonce_indices = [0, FIRST_HALF_NONCANONICAL_IDX]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Public nonce is invalid: first half's y-coordinate exceeds the field size",
            "pubnonce_indices": pubnonce_indices,
            "error": error,
        }
    )
    tc_id += 1
    # --- Error Test Case 2 ---
    pubnonce_indices = [SECOND_HALF_OFFCURVE_IDX, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Public nonce is invalid: second half is not a point on the curve",
            "pubnonce_indices": pubnonce_indices,
            "error": error,
        }
    )
    tc_id += 1
    # --- Error Test Case 3 ---
    pubnonce_indices = [SECOND_HALF_TORSION_IDX, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Public nonce is invalid: second half is not in the prime-order subgroup",
            "pubnonce_indices": pubnonce_indices,
            "error": error,
        }
    )
    tc_id += 1

    write_test_vectors("nonce_agg_vectors.json", vectors)
