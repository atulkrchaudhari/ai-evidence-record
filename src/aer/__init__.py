"""Reference implementation of the AI Evidence Record (AER) specification."""

from .canonical import CanonicalizationError, canonicalize, strict_loads
from .chain import ChainWriter, Finding, VerificationResult, verify_log, verify_records
from .checkpoint import generate_keypair, load_private_key, load_public_key, make_checkpoint
from .record import (
    GENESIS_HASH,
    SPEC,
    build_record,
    compute_record_hash,
    content_digest,
    validate_record,
)

__version__ = "0.1.0"

__all__ = [
    "GENESIS_HASH",
    "SPEC",
    "CanonicalizationError",
    "ChainWriter",
    "Finding",
    "VerificationResult",
    "build_record",
    "canonicalize",
    "compute_record_hash",
    "content_digest",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "make_checkpoint",
    "strict_loads",
    "validate_record",
    "verify_log",
    "verify_records",
]
