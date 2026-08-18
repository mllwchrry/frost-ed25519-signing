from pathlib import Path
import sys

# Add the vendored copies of ed25519lab (used by the reference implementation)
# and secp256k1lab (still used by the test helpers / generators until they are
# migrated with the real library) to path.
sys.path.append(str(Path(__file__).parent / "../ed25519lab/src"))
sys.path.append(str(Path(__file__).parent / "../secp256k1lab/src"))

from .signing import (
    # Functions
    validate_signers_ctx,
    nonce_gen,
    nonce_agg,
    sign,
    deterministic_sign,
    partial_sig_verify,
    partial_sig_agg,
    # Exceptions
    InvalidContributionError,
    # Types
    PlainPk,
    SignersContext,
    SessionContext,
)

__all__ = [
    # Functions
    "validate_signers_ctx",
    "nonce_gen",
    "nonce_agg",
    "sign",
    "deterministic_sign",
    "partial_sig_verify",
    "partial_sig_agg",
    # Exceptions
    "InvalidContributionError",
    # Types
    "PlainPk",
    "SignersContext",
    "SessionContext",
]
