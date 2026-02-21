from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"CRSYS1"  # file header marker


@dataclass(frozen=True)
class EncryptedBlob:
    salt: bytes
    nonce: bytes
    ciphertext: bytes


def derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, passphrase: str, iterations: int) -> bytes:
    salt = os.urandom(16)
    key = derive_key(passphrase, salt, iterations)
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return MAGIC + salt + nonce + ciphertext


def decrypt_bytes(blob: bytes, passphrase: str, iterations: int) -> bytes:
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 16 + 12 + 16:
        raise ValueError("Invalid encrypted blob")
    salt = blob[len(MAGIC) : len(MAGIC) + 16]
    nonce = blob[len(MAGIC) + 16 : len(MAGIC) + 16 + 12]
    ciphertext = blob[len(MAGIC) + 16 + 12 :]
    key = derive_key(passphrase, salt, iterations)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)


def encrypt_file(src_path: Path, dst_path: Path, passphrase: str, iterations: int) -> None:
    data = src_path.read_bytes()
    dst_path.write_bytes(encrypt_bytes(data, passphrase, iterations))


def decrypt_file(src_path: Path, dst_path: Path, passphrase: str, iterations: int) -> None:
    blob = src_path.read_bytes()
    dst_path.write_bytes(decrypt_bytes(blob, passphrase, iterations))
