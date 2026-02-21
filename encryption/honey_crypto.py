"""Primary honey encryption API.

The enhanced implementation lives in `honey_crypto_v2.py`.
This module exists as the stable import path for the rest of the codebase.
"""

from __future__ import annotations

from .honey_crypto_v2 import *  # noqa: F403
from .honey_crypto_v2 import _load_schema as _load_schema


def pack_honey_blob(nonce: bytes, ciphertext: bytes, plaintext_len: int) -> bytes:
    # Format: MAGIC(4) + LEN(4 big-endian) + NONCE(12) + CIPHERTEXT
    if plaintext_len < 0 or plaintext_len > 10_000_000:
        raise ValueError("Invalid plaintext length")
    return HONEY_MAGIC_V1 + int(plaintext_len).to_bytes(4, "big") + nonce + ciphertext


def unpack_honey_blob(blob: bytes) -> tuple[int, bytes, bytes]:
    if len(blob) < 4 + 4 + 12 + 16:
        raise ValueError("Invalid honey blob")
    if not blob.startswith(HONEY_MAGIC_V1):
        raise ValueError("Invalid honey blob magic")
    ln = int.from_bytes(blob[4:8], "big")
    nonce = blob[8:20]
    ciphertext = blob[20:]
    return ln, nonce, ciphertext


def pack_honey_blob_v2(template: dict, salt: bytes, nonce: bytes, ciphertext: bytes, plaintext_len: int) -> bytes:
    tmpl = dict(template)
    tmpl["ln"] = int(plaintext_len)
    tmpl_bytes = json.dumps(tmpl, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return (
        HONEY_MAGIC_V2
        + int(len(tmpl_bytes)).to_bytes(4, "big")
        + tmpl_bytes
        + salt
        + nonce
        + ciphertext
    )


def unpack_honey_blob_v2(blob: bytes) -> tuple[dict, bytes, bytes, bytes]:
    if len(blob) < 4 + 4 + 16 + 12 + 16:
        raise ValueError("Invalid honey blob")
    if not blob.startswith(HONEY_MAGIC_V2):
        raise ValueError("Invalid honey blob magic")
    o = 4
    tmpl_len = int.from_bytes(blob[o : o + 4], "big")
    o += 4
    tmpl_bytes = blob[o : o + tmpl_len]
    o += tmpl_len
    template = json.loads(tmpl_bytes.decode("utf-8"))
    salt = blob[o : o + 16]
    nonce = blob[o + 16 : o + 16 + 12]
    ciphertext = blob[o + 16 + 12 :]
    return template, salt, nonce, ciphertext


def honey_encrypt_real_text(plaintext: bytes, correct_passphrase: str, iterations: int, filename: str) -> bytes:
    """Encrypt real plaintext but enable believable decoys for wrong keys.

    Stores a public text-structure template. Correct key decrypts to original.
    Wrong key returns DTE-decoded decoy with same structure/length.
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(correct_passphrase, salt=salt, iterations=iterations)
    aes = AESGCM(key)

    # Build template from original plaintext for structured decoys.
    try:
        text = plaintext.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    template = _infer_template_from_text(text, filename=filename)
    template["it"] = int(iterations)
    aad = json.dumps(template, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    return pack_honey_blob_v2(template=template, salt=salt, nonce=nonce, ciphertext=ciphertext, plaintext_len=len(plaintext))


def honey_decrypt_or_fake(blob: bytes, passphrase: str, filename: str) -> bytes:
    """Honey behavior: attacker uses any passphrase and still gets plausible plaintext.

    We attempt decryption with a pseudo-key derived from the passphrase; if auth fails,
    we deterministically generate a fake plaintext of the recorded length.
    """
    # V2: template-based decoys
    if blob.startswith(HONEY_MAGIC_V2):
        template, salt, nonce, ciphertext = unpack_honey_blob_v2(blob)
        ln = int(template.get("ln", 2048))
        try:
            it = int(template.get("it", 250_000))
            key = _derive_key(passphrase, salt=salt, iterations=it)
            aes = AESGCM(key)
            aad = json.dumps({k: v for (k, v) in template.items() if k != "ln"}, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            # Note: ln is included in template; exclude it from AAD to avoid mismatch if we normalize it.
            pt = aes.decrypt(nonce, ciphertext, aad)
            return pt
        except Exception:
            seed = _seed_from_passphrase(passphrase, salt=salt, nonce=nonce)
            return _dte_decode(seed, template=template, target_len=ln, filename=filename)

    # V1 fallback
    ln, nonce, ciphertext = unpack_honey_blob(blob)
    pseudo_key = _derive_pseudo_key(passphrase, salt=nonce)
    aes = AESGCM(pseudo_key)
    try:
        pt = aes.decrypt(nonce, ciphertext, None)
        return pt
    except Exception:
        seed = _seed_from_passphrase(passphrase, salt=b"\x00" * 16, nonce=nonce)
        rnd_state = random.getstate()
        try:
            random.seed(seed)
            return _plausible_english_text(ln, filename)
        finally:
            random.setstate(rnd_state)
