"""Entry point for `python -m spoofguard ...` (PEP 338)."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
