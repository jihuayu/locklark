"""Fixed, public-safe refusal type shared by the release helpers."""

from __future__ import annotations


class ReleaseError(Exception):
    """A packaging or verification refusal.

    Messages must stay free of absolute paths, user names, host names,
    environment values, and secrets: they are printed to operators and may be
    copied into public notes.
    """


def fail(message: str) -> None:
    raise ReleaseError(message)
