# Interop cross-check

The fork's `ed25519_verify` only answers "is this valid under *the fork's* rules."
This directory is the outside check: it runs the fork's real signatures through
independent Ed25519 verifiers and confirms every one of them accepts. 
It substantiates the claim the fork rests on: **what we produce is a valid Ed25519 
signature, accepted everywhere, permissive and strict alike.**

## The verifiers

| Column                | Engine                          | Semantics                                   |
| --------------------- | ------------------------------- | ------------------------------------------- |
| `fork`                | `ed25519lab.ed25519_verify`     | cofactorless, strict decode (the fork)      |
| `dalek_verify`        | `ed25519-dalek` `verify`        | the permissive Verifier-trait path          |
| `dalek_verify_strict` | `ed25519-dalek` `verify_strict` | **Solana's equation**                       |
| `solders`             | `solders` `Signature.verify`    | Solana's own crate, via its Python bindings |
| `pynacl`              | libsodium `crypto_sign_open`    | a fully independent second engine           |

The two dalek columns are the reason the Rust oracle exists: a valid signature must
clear **both** `verify` (permissive) and `verify_strict` (strict / Solana). `solders`
and `pynacl` are further independent confirmations.

## The cases

`run_crosscheck.py` builds the cases in memory each run, nothing is written to disk,
and this is not a vector set for other implementations. All cases are valid
signatures that every verifier must accept:

- **FROST outputs**: the real aggregated FROST signatures from
  `../vectors/sig_agg_vectors.json`.
- **RFC 8032 §7.1**: the standard's known-answer vector (empty message), an external
  anchor independent of the fork's own machinery.

## Running it

```sh
# 1. build the Rust oracle (needs a Rust toolchain) — provides both dalek verdicts
(cd oracle_dalek && cargo build --release)

# 2. install the two extra Python engines (not fork dependencies)
pip3 install solders pynacl

# 3. run the cross-check
python3 run_crosscheck.py
```

`solders` and `pynacl` are the only Python packages the fork does not otherwise
need; step 2 adds them. If your Python is "externally managed" and refuses that
`pip3 install` (PEP 668 — common on Homebrew/Debian), use an isolated venv instead:

```sh
python3 -m venv .venv
.venv/bin/pip install solders pynacl
.venv/bin/python run_crosscheck.py
```

`run_crosscheck.py` builds the oracle on demand if it is missing, prints the full
verdict table, and exits non-zero if any verifier rejects any signature or if the
dalek oracle is unavailable. `solders` and `pynacl` are optional. If absent, their
columns read `n/a` and the run notes them; the dalek oracle carries the
"valid for both `verify` and `verify_strict`" claim, so it is required.
