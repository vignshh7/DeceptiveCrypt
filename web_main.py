from __future__ import annotations

import os

import uvicorn

try:
    from config import load_dotenv_if_present
except Exception:  # pragma: no cover
    from crypto_ransomware_system.config import load_dotenv_if_present


def main() -> None:
    # Convenience entrypoint for the browser demo.
    # Loads crypto_ransomware_system/.env automatically if present.
    load_dotenv_if_present()
    uvicorn.run(
        "webapp.app:app",
        host=os.environ.get("DEMO_HOST", "127.0.0.1"),
        port=int(os.environ.get("DEMO_PORT", "8000")),
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
