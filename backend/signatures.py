"""
Vitalis EHR — RSA-2048 Digital Signatures for Non-Repudiation
==============================================================
Generates RSA key pairs per user, signs health records on creation,
and verifies signatures to prove authorship mathematically.

A digital signature proves:
  (a) WHO created the record (authenticity)
  (b) The content has NOT been altered since signing (integrity)
  (c) The author CANNOT deny having signed it (non-repudiation)

Even if the database is compromised and `created_by` is modified,
the signature still ties the content to the original author's private key.

Standards Reference: NIST SP 800-89 (Recommendation for Digital Signature Applications)

Usage:
    from signatures import generate_keypair, sign_record, verify_signature

    # On user creation:
    private_pem, public_pem = generate_keypair()

    # On record creation:
    sig = sign_record({"diagnosis": "...", "treatment": "..."}, private_pem)

    # On verification:
    is_valid = verify_signature({"diagnosis": "...", "treatment": "..."}, sig, public_pem)
"""

import json
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from encryption import encrypt_field, decrypt_field


# ─── Key Pair Generation ─────────────────────────────────────────────

def generate_keypair() -> tuple[str, str]:
    """
    Generate an RSA-2048 key pair for a user.

    Returns:
        (private_key_pem: str, public_key_pem: str)
        Both are PEM-encoded strings.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


# ─── Record Signing ────────────────────────────────────���─────────────

def sign_record(record_fields: dict, private_key_pem: str) -> str:
    """
    Sign the canonical JSON representation of record fields with RSA-SHA256.

    Args:
        record_fields: Dict of plaintext fields to sign
                       (e.g., {"diagnosis": "...", "treatment": "...", "notes": "..."})
        private_key_pem: PEM-encoded RSA private key string

    Returns:
        Base64-encoded RSA-SHA256 signature string
    """
    canonical = _canonicalize(record_fields)
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )

    signature = private_key.sign(
        canonical,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    return base64.b64encode(signature).decode("utf-8")


def sign_lab_results(lab_results: str, private_key_pem: str) -> str:
    """
    Sign lab results specifically (for Lab Technician chain of custody).

    Args:
        lab_results: Plaintext lab results string
        private_key_pem: Lab technician's private key (PEM)

    Returns:
        Base64-encoded RSA-SHA256 signature
    """
    data = {"lab_results": lab_results}
    return sign_record(data, private_key_pem)


# ─── Signature Verification ──────────────────────────────────────────

def verify_signature(record_fields: dict, signature_b64: str, public_key_pem: str) -> dict:
    """
    Verify an RSA-SHA256 signature against record fields.

    Args:
        record_fields: Dict of plaintext fields that were signed
        signature_b64: Base64-encoded signature to verify
        public_key_pem: PEM-encoded RSA public key of the claimed author

    Returns:
        {
            "valid": bool,
            "algorithm": "RSA-SHA256",
            "key_size": 2048,
            "signature_b64": "...",
            "public_key_pem": "...",
            "signed_data_hash": "...",  # SHA-256 of the canonical data
            "error": str or None
        }
    """
    result = {
        "valid": False,
        "algorithm": "RSA-SHA256",
        "key_size": 2048,
        "signature_b64": signature_b64[:40] + "..." if signature_b64 else "",
        "public_key_pem": public_key_pem[:60] + "..." if public_key_pem else "",
        "signed_data_hash": "",
        "error": None,
    }

    if not signature_b64 or not public_key_pem:
        result["error"] = "Missing signature or public key"
        return result

    try:
        canonical = _canonicalize(record_fields)

        # Show what was signed (hash of the canonical data)
        import hashlib
        result["signed_data_hash"] = hashlib.sha256(canonical).hexdigest()

        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"),
        )
        signature = base64.b64decode(signature_b64)

        public_key.verify(
            signature,
            canonical,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        result["valid"] = True

    except InvalidSignature:
        result["error"] = "Signature verification FAILED — content may have been tampered with"
    except Exception as e:
        result["error"] = f"Verification error: {str(e)}"

    return result


# ─── Key Management Helpers ──────────────────────────────────────────

def encrypt_private_key(private_key_pem: str) -> str:
    """
    Encrypt a private key with the system AES key for secure storage.
    The private key is sensitive — never store it in plain text in the database.
    """
    return encrypt_field(private_key_pem)


def decrypt_private_key(encrypted_key: str) -> str:
    """
    Decrypt a stored private key using the system AES key.
    Called when a user needs to sign a new record.
    """
    return decrypt_field(encrypted_key)


def get_user_keys(supabase_client, user_id: str) -> tuple[str, str]:
    """
    Retrieve a user's key pair from the database.

    Returns:
        (decrypted_private_key_pem, public_key_pem)

    Raises:
        ValueError if user has no keys
    """
    result = (
        supabase_client.table("users")
        .select("public_key, private_key_enc")
        .eq("id", user_id)
        .execute()
    )

    if not result.data:
        raise ValueError(f"User {user_id} not found")

    public_key = result.data[0].get("public_key", "")
    private_key_enc = result.data[0].get("private_key_enc", "")

    if not public_key or not private_key_enc:
        raise ValueError(f"User {user_id} has no RSA key pair")

    private_key = decrypt_private_key(private_key_enc)
    return private_key, public_key


# ─── Internal Helpers ────────────────────────────────────────────────

def _canonicalize(record_fields: dict) -> bytes:
    """
    Create a canonical byte representation of record fields for signing.
    Uses sorted JSON keys to ensure deterministic representation.
    """
    return json.dumps(record_fields, sort_keys=True, ensure_ascii=True).encode("utf-8")
