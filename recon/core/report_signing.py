"""
Report signing — hash + optionally sign report output (JSON/Markdown) so a
report handed to a client can be verified untampered later.

Uses Ed25519 (via the `cryptography` package, already a hard dependency
for JWT key-confusion — see modules/jwt.py). A local keypair is generated
once on first use and reused for every future signature, stored at
~/.yata-recon/signing_key.pem (private, 0600) / signing_key.pub (public,
safe to hand to whoever needs to verify a report).
"""
import base64
import hashlib
import os
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

KEY_DIR = Path.home() / ".yata-recon"
PRIVATE_KEY_PATH = KEY_DIR / "signing_key.pem"
PUBLIC_KEY_PATH = KEY_DIR / "signing_key.pub"


def available() -> bool:
    return _CRYPTO_AVAILABLE


def _load_or_create_key():
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY_PATH.exists():
        with open(PRIVATE_KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    key = Ed25519PrivateKey.generate()
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    try:
        os.chmod(PRIVATE_KEY_PATH, 0o600)
    except Exception:
        pass  # best-effort on platforms without POSIX permissions (Windows)

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return key


def sign_file(file_path: str) -> str | None:
    """Hash + sign a report file, writing a `<file_path>.sig` sidecar.
    Returns the sidecar path, or None if `cryptography` isn't available."""
    if not _CRYPTO_AVAILABLE:
        return None
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        digest = hashlib.sha256(content).hexdigest()

        key = _load_or_create_key()
        signature = key.sign(content)
        pub_raw = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        fingerprint = hashlib.sha256(pub_raw).hexdigest()[:16]

        sig_path = f"{file_path}.sig"
        with open(sig_path, "w", encoding="utf-8") as f:
            f.write(
                "YATA RECON Report Signature\n"
                f"File: {Path(file_path).name}\n"
                f"SHA-256: {digest}\n"
                f"Signature (Ed25519, base64): {base64.b64encode(signature).decode()}\n"
                f"Public key fingerprint: {fingerprint}\n"
                f"Public key path: {PUBLIC_KEY_PATH}\n"
            )
        return sig_path
    except Exception:
        return None  # signing is best-effort — never break the save flow


def verify_file(file_path: str, sig_path: str | None = None) -> dict:
    """Verify a report file against its `.sig` sidecar.
    Returns {"valid": bool, "reason": str}."""
    if not _CRYPTO_AVAILABLE:
        return {"valid": False, "reason": "The 'cryptography' package is not installed."}

    sig_path = sig_path or f"{file_path}.sig"
    if not Path(sig_path).exists():
        return {"valid": False, "reason": f"No signature file found at {sig_path}"}
    if not Path(file_path).exists():
        return {"valid": False, "reason": f"Report file not found: {file_path}"}

    sig_data = {}
    with open(sig_path, "r", encoding="utf-8") as f:
        for line in f:
            if ":" in line:
                k, _, v = line.partition(":")
                sig_data[k.strip()] = v.strip()

    expected_hash = sig_data.get("SHA-256", "")
    signature_b64 = sig_data.get("Signature (Ed25519, base64)", "")
    if not expected_hash or not signature_b64:
        return {"valid": False, "reason": "Malformed signature file"}

    with open(file_path, "rb") as f:
        content = f.read()
    actual_hash = hashlib.sha256(content).hexdigest()
    if actual_hash != expected_hash:
        return {"valid": False,
                "reason": f"Hash mismatch — the file has been modified since it was signed "
                          f"(expected {expected_hash[:16]}…, got {actual_hash[:16]}…)"}

    if not PUBLIC_KEY_PATH.exists():
        return {"valid": True,
                "reason": "SHA-256 hash matches — no local public key available to also verify "
                          "the Ed25519 signature (hash-only integrity check passed)."}

    try:
        with open(PUBLIC_KEY_PATH, "rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())
        signature = base64.b64decode(signature_b64)
        pub_key.verify(signature, content)
        return {"valid": True, "reason": "SHA-256 hash and Ed25519 signature both verified."}
    except InvalidSignature:
        return {"valid": False,
                "reason": "Signature verification FAILED — the file may have been tampered "
                          "with, or was signed by a different key than the one on this machine."}
    except Exception as e:
        return {"valid": False, "reason": f"Verification error: {e}"}
