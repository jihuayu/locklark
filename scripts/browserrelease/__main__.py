"""Module entry point: python3 -m browserrelease --product ... --output ..."""

from __future__ import annotations

from .cli import main

raise SystemExit(main())
