from __future__ import annotations

import os
import json
import re
import random
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass(frozen=True)
class HoneyResult:
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    template: dict


HONEY_MAGIC_V1 = b"HNY1"
HONEY_MAGIC_V2 = b"HNY2"


_KV_RE = re.compile(r"^\s*([A-Za-z_][\w.\-]{0,80})\s*=\s*(.*?)\s*$")
_INT_RE = re.compile(r"^[+-]?\d+$")
_FLOAT_RE = re.compile(r"^[+-]?(?:\d+\.\d+|\d+\.\d*|\.\d+)$")
_BOOL_RE = re.compile(r"^(true|false|yes|no|on|off)$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _is_text_extension(path: Path) -> bool:
    return path.suffix.lower() in {".txt", ".md", ".csv", ".log", ".json", ".xml", ".ini", ".conf", ".cfg"}


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _seed_from_passphrase(passphrase: str, salt: bytes, nonce: bytes) -> int:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(passphrase.encode("utf-8"))
    digest.update(salt)
    digest.update(nonce)
    return int.from_bytes(digest.finalize()[:8], "big")


def _infer_value_kind(value: str) -> tuple[str, dict]:
    v = value.strip()
    meta: dict = {"orig_len": len(value)}
    if _BOOL_RE.match(v):
        meta["orig"] = v.lower()
        return "bool", meta
    if _INT_RE.match(v):
        try:
            n = int(v)
        except Exception:
            n = 0
        meta["orig"] = n
        meta["digits"] = max(1, len(v.lstrip("+-")))
        return "int", meta
    if _FLOAT_RE.match(v):
        try:
            f = float(v)
        except Exception:
            f = 0.0
        meta["orig"] = f
        meta["precision"] = max(0, len(v.split(".", 1)[1]) if "." in v else 0)
        return "float", meta
    if _EMAIL_RE.match(v):
        return "email", meta
    if all(32 <= ord(ch) < 127 for ch in v) and any(c.isdigit() for c in v) and any(c.isalpha() for c in v):
        # Looks like a token/password-ish value
        return "token", meta
    return "text", meta


def _infer_template_from_text(text: str, filename: str) -> dict:
    lines = text.splitlines(keepends=False)
    templates: list[dict] = []
    for line in lines:
        if not line.strip():
            templates.append({"kind": "blank"})
            continue

        m = _KV_RE.match(line)
        if m:
            key, raw_val = m.group(1), m.group(2)
            kind, meta = _infer_value_kind(raw_val)
            templates.append(
                {
                    "kind": "kv",
                    "key": key,
                    "value_kind": kind,
                    "meta": meta,
                }
            )
            continue

        # CSV-ish: preserve column count and numeric-like columns.
        if "," in line and line.count(",") >= 1:
            cols = [c.strip() for c in line.split(",")]
            col_kinds = []
            for c in cols:
                k, _ = _infer_value_kind(c)
                col_kinds.append(k)
            templates.append({"kind": "csv", "cols": len(cols), "col_kinds": col_kinds})
            continue

        templates.append({"kind": "free", "len": max(16, len(line))})

    return {
        "v": 2,
        "filename": filename,
        "line_count": len(templates),
        "lines": templates,
    }


def _words() -> list[str]:
    return [
        "user",
        "admin",
        "guest",
        "timeout",
        "retry",
        "secure",
        "session",
        "token",
        "endpoint",
        "enabled",
        "disabled",
        "level",
        "debug",
        "info",
        "warn",
        "error",
        "region",
        "host",
        "port",
        "service",
        "policy",
        "quota",
        "limit",
    ]


def _dte_decode(seed: int, template: dict, target_len: int, filename: str) -> bytes:
    rnd_state = random.getstate()
    try:
        random.seed(seed)
        lines_out: list[str] = []

        for entry in template.get("lines", []):
            kind = entry.get("kind")
            if kind == "blank":
                lines_out.append("")
                continue

            if kind == "kv":
                key = entry.get("key", "key")
                value_kind = entry.get("value_kind", "text")
                meta = entry.get("meta", {})
                if value_kind == "bool":
                    val = random.choice(["true", "false", "yes", "no", "on", "off"])
                elif value_kind == "int":
                    orig = int(meta.get("orig", 0))
                    digits = int(meta.get("digits", 2))
                    spread = max(3, int(abs(orig) * 0.5) + 7)
                    val_i = orig + random.randint(-spread, spread)
                    val = str(val_i)
                    # Preserve rough digit width for nicer-looking configs
                    if digits >= 2 and val_i >= 0:
                        val = val.zfill(min(digits, 6))
                elif value_kind == "float":
                    orig = float(meta.get("orig", 0.0))
                    prec = int(meta.get("precision", 2))
                    spread = max(1.0, abs(orig) * 0.4 + 3.5)
                    val_f = orig + (random.random() * 2 - 1) * spread
                    val = f"{val_f:.{max(0, min(prec, 6))}f}"
                elif value_kind == "email":
                    val = f"user{random.randint(10, 9999)}@example.com"
                elif value_kind == "token":
                    ln = int(meta.get("orig_len", 12))
                    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                    val = "".join(random.choice(alphabet) for _ in range(max(8, min(ln, 48))))
                else:
                    ln = int(meta.get("orig_len", 18))
                    ws = _words()
                    out = []
                    while len(" ".join(out)) < ln:
                        out.append(random.choice(ws))
                    val = " ".join(out)[:ln]
                lines_out.append(f"{key}={val}")
                continue

            if kind == "csv":
                cols = int(entry.get("cols", 3))
                col_kinds = entry.get("col_kinds", ["text"] * cols)
                row = []
                for i in range(cols):
                    ck = col_kinds[i] if i < len(col_kinds) else "text"
                    if ck == "int":
                        row.append(str(random.randint(0, 9999)))
                    elif ck == "float":
                        row.append(f"{random.random() * 1000:.2f}")
                    elif ck == "bool":
                        row.append(random.choice(["true", "false"]))
                    elif ck == "email":
                        row.append(f"user{random.randint(10, 9999)}@example.com")
                    else:
                        ws = _words()
                        row.append(random.choice(ws))
                lines_out.append(", ".join(row))
                continue

            # free line
            ln = int(entry.get("len", 64))
            ws = _words()
            out = []
            while len(" ".join(out)) < ln:
                out.append(random.choice(ws))
            lines_out.append(" ".join(out)[:ln])

        payload = "\n".join(lines_out)
        header = (
            f"{payload}\n"
            f"\n# NOTE: This is decoy content (honey encryption demo)\n"
            f"# File: {filename}\n"
        )
        data = header.encode("utf-8", errors="replace")
        if len(data) < target_len:
            # Pad with more plausible words
            ws = _words()
            while len(data) < target_len:
                data += (random.choice(ws) + " ").encode("utf-8")
        return data[:target_len]
    finally:
        random.setstate(rnd_state)


def _plausible_english_text(target_len: int, filename: str) -> bytes:
    seed = (
        f"Academic Demo Document\n"
        f"File: {filename}\n"
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "This document contains administrative notes, meeting summaries, and short project updates. "
        "All data shown is synthetic and intended for demonstration purposes only.\n\n"
    )

    phrases = [
        "Action items were reviewed and closed.",
        "Budget summary and quarterly targets were updated.",
        "Risk register reviewed; no critical issues found.",
        "Implementation status: on track with minor revisions.",
        "Next steps include validation and documentation updates.",
        "Contact: security-team@university.example (demo address).",
    ]

    out = seed
    while len(out.encode("utf-8")) < target_len:
        out += random.choice(phrases) + " "
    data = out.encode("utf-8")[:target_len]
    return data


def _derive_pseudo_key(passphrase: str, salt: bytes, iterations: int = 150_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def generate_fake_plaintext(real_path: Path, max_len: int = 256 * 1024) -> bytes:
    try:
        size = real_path.stat().st_size
    except Exception:
        size = 2048

    target = int(min(max(size, 1024), max_len))

    # For text-like files, return plausible UTF-8; otherwise return a structured binary-ish payload.
    ext = real_path.suffix.lower()
    if ext in {".txt", ".md", ".csv", ".log", ".json", ".xml"}:
        return _plausible_english_text(target, real_path.name)

    header = (
        f"FAKE-BLOB|name={real_path.name}|ts={int(time.time())}|note=demo-only\n".encode("utf-8")
    )
    padding_len = max(0, target - len(header))
    # Low-to-medium entropy padding to look like structured data rather than pure random.
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-\n"
    padding = bytes(alphabet[b % len(alphabet)] for b in os.urandom(padding_len))
    return header + padding


def honey_encrypt_bytes(fake_plaintext: bytes) -> HoneyResult:
    # Legacy API retained for backward compatibility.
    salt = os.urandom(16)
    nonce = os.urandom(12)
    aes = AESGCM(_derive_pseudo_key(passphrase="legacy", salt=nonce))
    ciphertext = aes.encrypt(nonce, fake_plaintext, None)
    return HoneyResult(salt=salt, nonce=nonce, ciphertext=ciphertext, template={"v": 1, "ln": len(fake_plaintext)})


def honey_decrypt_bytes(nonce: bytes, ciphertext: bytes, fake_key: bytes) -> bytes:
    aes = AESGCM(fake_key)
    return aes.decrypt(nonce, ciphertext, None)


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
