#!/usr/bin/env python3
"""Interop cross-check: the fork's signatures are accepted by every verifier.

Runs the fork's real aggregated FROST signatures (from ../vectors/sig_agg_vectors.json)
plus the RFC 8032 section 7.1 known-answer vector through five verifiers and asserts
each one accepts every signature. This substantiates that what the fork produces is a
valid Ed25519 signature accepted everywhere, permissive and strict alike:

  fork                 ed25519lab.ed25519_verify   cofactorless, strict decode
  dalek_verify         ed25519-dalek verify        permissive path (Rust oracle)
  dalek_verify_strict  ed25519-dalek verify_strict Solana's equation (Rust oracle)
  solders              solders Signature.verify    Solana's crate, Python bindings
  pynacl               libsodium crypto_sign_open  independent second engine

The two dalek columns are the point of the check: a valid signature must clear both
the permissive `verify` and the strict `verify_strict`.

Cases are built in memory; nothing is written to disk. The dalek columns need the
Rust oracle built (cd oracle_dalek && cargo build --release); solders and pynacl are
optional (pip install; run this script with that interpreter). Exit status is
non-zero if any verifier rejects any signature, or if the dalek oracle is missing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)  # python/

import frost_ref  # noqa: F401  (puts ed25519lab on sys.path)

from oracles import fork_verify, pynacl_verify, solders_verify

HERE = os.path.dirname(os.path.abspath(__file__))
SIG_AGG_VECTORS = os.path.join(HERE, "..", "vectors", "sig_agg_vectors.json")
ORACLE_DIR = os.path.join(HERE, "oracle_dalek")
ORACLE_BIN = os.path.join(ORACLE_DIR, "target", "release", "oracle_dalek")

COLUMNS = ["fork", "dalek_verify", "dalek_verify_strict", "solders", "pynacl"]


# --- Case construction ---


def build_cases() -> list[dict]:
    """The signatures to check: the fork's real FROST outputs plus the RFC KAT."""
    cases: list[dict] = []

    # Real aggregated FROST signatures lifted from the project's own vectors.
    with open(SIG_AGG_VECTORS) as f:
        data = json.load(f)
    for g in data["test_groups"]:
        thresh_pk = g["thresh_pk"]
        for tc in g["valid_tests"]:
            cases.append(
                {
                    "id": f"frost-{g['tg_id']}-{tc['tc_id']}",
                    "msg": tc["msg"].lower(),
                    "pubkey": thresh_pk.lower(),
                    "sig": tc["expected"].lower(),
                }
            )

    # RFC 8032 section 7.1 known-answer vector (empty message): an external anchor
    # to the standard, independent of the fork's own machinery.
    cases.append(
        {
            "id": "rfc8032-7.1-empty",
            "msg": "",
            "pubkey": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "sig": (
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
        }
    )
    return cases


# --- Oracle bridge ---


def dalek_verdicts(doc_text: str) -> dict[str, dict[str, bool]] | None:
    """Run the Rust oracle, building it first if needed. None if unavailable."""
    if not os.path.exists(ORACLE_BIN):
        print("Rust oracle not built; running `cargo build --release`...")
        try:
            subprocess.run(["cargo", "build", "--release"], cwd=ORACLE_DIR, check=True)
        except (OSError, subprocess.CalledProcessError) as e:
            print(f"  could not build the dalek oracle ({e}); skipping its columns.")
            return None
    proc = subprocess.run([ORACLE_BIN], input=doc_text.encode(), capture_output=True)
    if proc.returncode != 0:
        print(f"  dalek oracle failed: {proc.stderr.decode()}")
        return None
    return json.loads(proc.stdout)


def collate() -> list[dict]:
    """Every case with each verifier's verdict attached (None if unavailable)."""
    cases = build_cases()
    dalek = dalek_verdicts(json.dumps({"cases": cases})) or {}
    merged: list[dict] = []
    for c in cases:
        msg = bytes.fromhex(c["msg"])
        pk = bytes.fromhex(c["pubkey"])
        sig = bytes.fromhex(c["sig"])
        d = dalek.get(c["id"], {})
        merged.append(
            {
                "id": c["id"],
                "fork": fork_verify(msg, pk, sig),
                "dalek_verify": d.get("dalek_verify"),
                "dalek_verify_strict": d.get("dalek_verify_strict"),
                "solders": solders_verify(msg, pk, sig),
                "pynacl": pynacl_verify(msg, pk, sig),
            }
        )
    return merged


# --- Reporting ---

_CELL = {True: "yes", False: "no", None: "n/a"}
_COLW = max(len(c) for c in COLUMNS)


def print_table(cases: list[dict]) -> None:
    idw = max(len(c["id"]) for c in cases)
    header = f"{'case':<{idw}}  " + "  ".join(f"{col:>{_COLW}}" for col in COLUMNS)
    print(header)
    print("-" * len(header))
    for c in cases:
        cells = "  ".join(f"{_CELL[c[col]]:>{_COLW}}" for col in COLUMNS)
        print(f"{c['id']:<{idw}}  {cells}")
    print()


def main() -> int:
    cases = collate()
    have = {col: any(c[col] is not None for c in cases) for col in COLUMNS}
    print(
        "engines: "
        + " ".join(f"{col}={'yes' if have[col] else 'MISSING'}" for col in COLUMNS)
        + "\n"
    )
    print_table(cases)

    # The invariant: every available verifier accepts every signature.
    rejected = [(c["id"], col) for c in cases for col in COLUMNS if c[col] is False]
    if rejected:
        print("REJECTED (a verifier refused a valid signature):")
        for cid, col in rejected:
            print(f"  {cid} rejected by {col}")
        return 1

    # The dalek oracle carries the "valid for both verify and verify_strict" claim,
    # so its absence is a failure; solders/pynacl are optional confirmations.
    if not (have["dalek_verify"] and have["dalek_verify_strict"]):
        print(
            "dalek oracle unavailable; build it: "
            "(cd oracle_dalek && cargo build --release)"
        )
        return 1
    optional_missing = [c for c in ("solders", "pynacl") if not have[c]]
    if optional_missing:
        print(f"NOTE: optional verifiers unavailable: {', '.join(optional_missing)}.")

    print("All signatures accepted by every available verifier.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
