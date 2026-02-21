# DeceptiveCrypt (Crypto Ransomware System Demo)

A research/demo project that simulates a ransomware-style encryption pipeline **with honey encryption**: decrypting with the wrong key returns **plausible decoy plaintext** instead of an obvious failure.

## What it does

- **Real protection (defender view):** AES-GCM encryption for files in `data/protected_files/`.
- **Honey encryption (attacker view):** `HNY3` schema-driven decoys (Field-Aware DTE). Wrong keys still “decrypt” to believable content.
- **Controller + monitoring:** a state controller can switch between normal AES and honey mode based on suspicious activity (demo logic).
- **Web demo:** a small FastAPI UI to trigger bootstraps and view results.

## Repo layout (high level)

- `encryption/aes_crypto.py` — AES-GCM + PBKDF2 key derivation
- `encryption/honey_crypto.py` — **primary/stable** honey API (wraps enhanced implementation)
- `encryption/honey_crypto_v2.py` — enhanced honey (`HNY3`) + schemas in `encryption/field_schemas.json`
- `encryption/controller.py` — **primary/stable** controller API
- `data_bootstrap_v2.py` — bootstrap pipeline (generates protected/encrypted/fake datasets)
- `web_main.py`, `webapp/` — FastAPI app + static UI

## Quick start

### 1) Create & activate a virtualenv (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
```

### 2) Install dependencies

Minimal set to run the crypto + demos:

```powershell
pip install cryptography watchdog python-dotenv fastapi uvicorn
```

Optional: this repo’s `requirements.txt` may include ML/analytics packages that can fail to build on some Python versions (especially very new versions). If `pip install -r requirements.txt` fails, use the minimal install above.

### 3) Run the enhanced feature tests

```powershell
python test_enhanced_features.py
python test_research_fields.py
```

### 4) Run the CLI/demo scripts

```powershell
python demo_enhanced_features.py
python main.py
```

### 5) Run the web app

```powershell
uvicorn web_main:app --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000`.

## Notes

- Generated artifacts are written under `data/` (encrypted blobs, fake decoys, indexes). This is demo data.
- The honey format is versioned (`HNY1`/`HNY2` legacy, `HNY3` enhanced). The primary API is `encryption/honey_crypto.py`.

## Disclaimer

This repository is for **educational and defensive research** purposes (understanding deception-based protection and ransomware behaviors in a controlled environment). Do not use it for unauthorized activity.
