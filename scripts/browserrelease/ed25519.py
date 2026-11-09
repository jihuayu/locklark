"""Ed25519 verification wrapper over pinned ``cryptography`` + libsodium.

This module contains verification only. It exposes no signing or private-key
API and never touches a key store, a network socket, or a subprocess.

Signature math is delegated to ``cryptography`` (OpenSSL). OpenSSL's Ed25519
verification is cofactorless and does **not** reject a public key that is not a
canonical prime-subgroup point: for the identity point ``01`` followed by 31
zero bytes, ``R = <basepoint encoding>`` and ``S = 1`` verifies *any* message
without any private key. Published implementations therefore validate the
public key and ``R`` before (or instead of) trusting the backend.

That point validation is delegated to mature libsodium through ``PyNaCl``'s
``crypto_core_ed25519_is_valid_point``, which accepts a point only when its
encoding is canonical, the point is on the curve, it is in the prime-order
subgroup, and it does not have small order. No curve arithmetic and no
point blacklist is implemented here; this module only calls libsodium and, for
the signature scalar, rejects a non-canonical ``S`` (``S >= L``) encoding.

Both ``cryptography`` and ``PyNaCl`` are explicit, pinned optional
dependencies for the detached attestation verifier only. If either is
unavailable, verification raises the fixed ``DEPENDENCY_ERROR`` refusal
instead of accepting or silently skipping a signature.
"""

from __future__ import annotations

from .errors import ReleaseError

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - exercised by the fail-closed test
    InvalidSignature = None
    Ed25519PublicKey = None

try:
    from nacl.bindings import crypto_core_ed25519_is_valid_point
except ImportError:  # pragma: no cover - exercised by the fail-closed test
    crypto_core_ed25519_is_valid_point = None

DEPENDENCY_ERROR = (
    "Ed25519 verification dependency is unavailable; install "
    "scripts/browserrelease/requirements.txt"
)
PUBLIC_KEY_ERROR = "owner public key is not usable"

POINT_BYTES = 32
SIGNATURE_BYTES = 64

# Order L of the Ed25519 prime-order subgroup, little-endian:
# 2**252 + 27742317777372353535851937790883648493.
_GROUP_ORDER = bytes.fromhex(
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
)
_GROUP_ORDER_INT = int.from_bytes(_GROUP_ORDER, "little")


def _require_point_dependency() -> None:
    if crypto_core_ed25519_is_valid_point is None:
        raise ReleaseError(DEPENDENCY_ERROR)


def _is_valid_point(encoded: object) -> bool:
    """True only for a canonical prime-subgroup non-small-order Ed25519 point.

    Delegated to libsodium. Raises the fixed dependency refusal when libsodium
    is unavailable, and returns False for a short, long, non-``bytes``, or
    otherwise unusable encoding. It never accepts on error.
    """
    _require_point_dependency()
    if not isinstance(encoded, (bytes, bytearray)) or len(encoded) != POINT_BYTES:
        return False
    try:
        return bool(crypto_core_ed25519_is_valid_point(bytes(encoded)))
    except (TypeError, ValueError):
        return False
    except RuntimeError as error:
        # nacl.exceptions.UnavailableError (minimal libsodium build) subclasses
        # RuntimeError; treat any residual libsodium failure as fail-closed.
        raise ReleaseError(DEPENDENCY_ERROR) from error


def public_key_is_usable(public_key: object) -> bool:
    """True only when the 32-byte public key is a usable Ed25519 point."""
    return _is_valid_point(public_key)


def require_usable_public_key(public_key: object) -> None:
    """Refuse a pinned public key that is not a canonical prime-subgroup point."""
    if not public_key_is_usable(public_key):
        raise ReleaseError(PUBLIC_KEY_ERROR)


def _is_canonical_scalar(scalar: bytes) -> bool:
    """True only for a canonical little-endian ``S`` below the group order."""
    return int.from_bytes(scalar, "little") < _GROUP_ORDER_INT


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Return True only when the detached Ed25519 signature verifies.

    The pinned public key and the signature's ``R`` must both be valid
    canonical prime-subgroup non-small-order points before the backend is
    consulted, which rejects the forged-identity key/signature case. The
    signature equation itself stays delegated to ``cryptography``.
    """
    if Ed25519PublicKey is None or InvalidSignature is None:
        raise ReleaseError(DEPENDENCY_ERROR)
    _require_point_dependency()
    if not isinstance(public_key, bytes) or len(public_key) != POINT_BYTES:
        return False
    if not isinstance(signature, bytes) or len(signature) != SIGNATURE_BYTES:
        return False
    if not isinstance(message, bytes):
        return False
    if not _is_valid_point(public_key):
        return False
    if not _is_valid_point(signature[:POINT_BYTES]):
        return False
    if not _is_canonical_scalar(signature[POINT_BYTES:]):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
