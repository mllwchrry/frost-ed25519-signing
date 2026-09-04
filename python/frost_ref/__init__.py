from pathlib import Path
import sys

# Add the vendored copy of ed25519lab to path.
sys.path.append(str(Path(__file__).parent / "../ed25519lab/src"))

from .signing import (
    # Functions
    validate_threshold_info,
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
    ThresholdInfo,
    SessionContext,
)

__all__ = [
    # Functions
    "validate_threshold_info",
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
    "ThresholdInfo",
    "SessionContext",
]
