e2e-messaging-project
=====================

Minimal scaffold for an end-to-end encrypted messaging demo.

Quick start (Windows PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m src.app.main
```

Run tests:

```powershell
pip install -r requirements.txt
pytest -q
```

Notes:
- The `docs/security-design.pdf` contains the security model and protocol rationale. Reference it for design decisions.
- This scaffold uses the `cryptography` package for primitives.
