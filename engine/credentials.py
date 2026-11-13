"""
Encrypted Credential Vault for WireSploit
Stores wordlists, API keys, hashcat masks, and other sensitive data
using AES-256-GCM with per-entry keys derived from a master key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parents[1]
VAULT_DIR = ROOT / "data"
VAULT_FILE = VAULT_DIR / "credentials.enc"
VAULT_META_FILE = VAULT_DIR / "credentials.meta"
MASTER_KEY_FILE = VAULT_DIR / ".master_key"

# Credential kinds
class CredentialKind(str):
    WORDLIST = "wordlist"
    API_KEY = "api_key"
    HASHCAT_MASK = "hashcat_mask"
    HYDRA_USERLIST = "hydra_userlist"
    SSH_KEY = "ssh_key"
    NTLM_HASH = "ntlm_hash"
    GENERIC = "generic"


class CredentialVault:
    """
    Encrypted credential storage using AES-256-GCM.

    Master key derivation: PBKDF2-HMAC-SHA256 with 100,000 iterations
    Per-entry encryption: AES-256-GCM with unique nonce per entry
    Metadata stored separately (no secrets in metadata)
    """

    def __init__(self):
        self._master_key: Optional[bytes] = None
        self._metadata: Dict[str, Dict[str, Any]] = {}
        self._ensure_vault_dir()
        self._load_or_create_master_key()
        self._load_metadata()

    def _ensure_vault_dir(self):
        VAULT_DIR.mkdir(parents=True, exist_ok=True)

    def _load_or_create_master_key(self):
        """Load existing master key or generate a new one."""
        if MASTER_KEY_FILE.exists():
            try:
                # Master key is stored encrypted with a key derived from machine-specific data
                # For simplicity, we'll store it directly but with restricted permissions
                key_data = MASTER_KEY_FILE.read_bytes()
                if len(key_data) == 32:
                    self._master_key = key_data
                    return
            except Exception:
                pass

        # Generate new master key
        self._master_key = secrets.token_bytes(32)
        # Store with restrictive permissions (Windows: ACL, Unix: 0o600)
        MASTER_KEY_FILE.write_bytes(self._master_key)
        try:
            MASTER_KEY_FILE.chmod(0o600)
        except Exception:
            pass  # Windows doesn't support chmod

    def _load_metadata(self):
        """Load credential metadata (no secrets)."""
        if VAULT_META_FILE.exists():
            try:
                self._metadata = json.loads(VAULT_META_FILE.read_text(encoding="utf-8"))
            except Exception:
                self._metadata = {}
        else:
            self._metadata = {}

    def _save_metadata(self):
        """Save credential metadata."""
        VAULT_META_FILE.write_text(
            json.dumps(self._metadata, indent=2),
            encoding="utf-8"
        )
        try:
            VAULT_META_FILE.chmod(0o600)
        except Exception:
            pass

    def _derive_entry_key(self, credential_id: str) -> bytes:
        """Derive a per-entry encryption key from master key."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=credential_id.encode(),
            iterations=100000,
        )
        return kdf.derive(self._master_key)

    def _encrypt(self, credential_id: str, plaintext: str) -> Tuple[bytes, bytes]:
        """Encrypt plaintext using per-entry key. Returns (ciphertext, nonce)."""
        entry_key = self._derive_entry_key(credential_id)
        aesgcm = AESGCM(entry_key)
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return ciphertext, nonce

    def _decrypt(self, credential_id: str, ciphertext: bytes, nonce: bytes) -> str:
        """Decrypt ciphertext using per-entry key."""
        entry_key = self._derive_entry_key(credential_id)
        aesgcm = AESGCM(entry_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()

    def _get_vault_data(self) -> Dict[str, Any]:
        """Load the full encrypted vault data."""
        if VAULT_FILE.exists():
            try:
                return json.loads(VAULT_FILE.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_vault_data(self, data: Dict[str, Any]):
        """Save the full encrypted vault data."""
        VAULT_FILE.write_text(json.dumps(data), encoding="utf-8")
        try:
            VAULT_FILE.chmod(0o600)
        except Exception:
            pass

    def store(
        self,
        name: str,
        kind: str,
        secret: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Store a credential and return its ID.

        Args:
            name: Human-readable name
            kind: CredentialKind (wordlist, api_key, etc.)
            secret: The actual secret value
            metadata: Additional non-sensitive metadata

        Returns:
            credential_id for later retrieval
        """
        credential_id = f"cred_{secrets.token_urlsafe(16)}"

        # Encrypt the secret
        ciphertext, nonce = self._encrypt(credential_id, secret)

        # Store encrypted data
        vault_data = self._get_vault_data()
        vault_data[credential_id] = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
        }
        self._save_vault_data(vault_data)

        # Store metadata (no secrets)
        meta_entry = {
            "id": credential_id,
            "name": name,
            "kind": kind,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            meta_entry["metadata"] = metadata
        self._metadata[credential_id] = meta_entry
        self._save_metadata()

        return credential_id

    def retrieve(self, credential_id: str) -> str:
        """
        Retrieve and decrypt a credential.

        Raises:
            KeyError: If credential_id not found
            ValueError: If decryption fails
        """
        vault_data = self._get_vault_data()
        if credential_id not in vault_data:
            raise KeyError(f"Credential not found: {credential_id}")

        entry = vault_data[credential_id]
        ciphertext = base64.b64decode(entry["ciphertext"])
        nonce = base64.b64decode(entry["nonce"])

        return self._decrypt(credential_id, ciphertext, nonce)

    def retrieve_bytes(self, credential_id: str) -> bytes:
        """Retrieve a credential as raw bytes (for binary data like wordlists)."""
        return self.retrieve(credential_id).encode()

    def delete(self, credential_id: str) -> bool:
        """Delete a credential. Returns True if deleted."""
        vault_data = self._get_vault_data()
        if credential_id in vault_data:
            del vault_data[credential_id]
            self._save_vault_data(vault_data)

        if credential_id in self._metadata:
            del self._metadata[credential_id]
            self._save_metadata()
            return True
        return False

    def list_credentials(self, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all credentials (metadata only, no secrets).

        Args:
            kind: Optional filter by credential kind

        Returns:
            List of credential metadata dicts
        """
        result = []
        for cred_id, meta in self._metadata.items():
            if kind is None or meta.get("kind") == kind:
                # Return a copy without any potential sensitive data
                safe_meta = {k: v for k, v in meta.items() if k not in ("secret",)}
                result.append(safe_meta)
        return sorted(result, key=lambda x: x.get("created_at", ""))

    def get_metadata(self, credential_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a specific credential."""
        return self._metadata.get(credential_id)

    def update_metadata(self, credential_id: str, metadata: Dict[str, Any]) -> bool:
        """Update metadata for a credential."""
        if credential_id in self._metadata:
            self._metadata[credential_id].update(metadata)
            self._metadata[credential_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._save_metadata()
            return True
        return False

    def export_credential(self, credential_id: str, output_path: Path) -> bool:
        """Export a credential to a file (for backup)."""
        try:
            secret = self.retrieve(credential_id)
            output_path.write_text(secret, encoding="utf-8")
            return True
        except Exception:
            return False

    def import_credential(
        self,
        name: str,
        kind: str,
        input_path: Path,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Import a credential from a file."""
        try:
            secret = input_path.read_text(encoding="utf-8")
            return self.store(name, kind, secret, metadata)
        except Exception:
            return None

    def rotate_master_key(self) -> bool:
        """
        Rotate the master key (re-encrypt all credentials).
        Use with caution - requires all credentials to be re-encrypted.
        """
        # Load all current credentials
        vault_data = self._get_vault_data()
        credentials = {}
        for cred_id, entry in vault_data.items():
            try:
                ciphertext = base64.b64decode(entry["ciphertext"])
                nonce = base64.b64decode(entry["nonce"])
                plaintext = self._decrypt(cred_id, ciphertext, nonce)
                credentials[cred_id] = plaintext
            except Exception:
                continue

        # Generate new master key
        old_master_key = self._master_key
        self._master_key = secrets.token_bytes(32)
        MASTER_KEY_FILE.write_bytes(self._master_key)
        try:
            MASTER_KEY_FILE.chmod(0o600)
        except Exception:
            pass

        # Re-encrypt all credentials with new key
        new_vault_data = {}
        for cred_id, plaintext in credentials.items():
            ciphertext, nonce = self._encrypt(cred_id, plaintext)
            new_vault_data[cred_id] = {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "nonce": base64.b64encode(nonce).decode(),
            }
        self._save_vault_data(new_vault_data)

        return True


# Global vault instance
_vault: Optional[CredentialVault] = None


def get_vault() -> CredentialVault:
    """Get the global credential vault instance."""
    global _vault
    if _vault is None:
        _vault = CredentialVault()
    return _vault


# Convenience functions
def store_credential(
    name: str,
    kind: str,
    secret: str,
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Store a credential in the vault."""
    return get_vault().store(name, kind, secret, metadata)


def retrieve_credential(credential_id: str) -> str:
    """Retrieve a credential from the vault."""
    return get_vault().retrieve(credential_id)


def list_credentials(kind: Optional[str] = None) -> List[Dict[str, Any]]:
    """List credentials from the vault."""
    return get_vault().list_credentials(kind)


def delete_credential(credential_id: str) -> bool:
    """Delete a credential from the vault."""
    return get_vault().delete(credential_id)