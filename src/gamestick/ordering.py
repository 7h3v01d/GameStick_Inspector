from __future__ import annotations

from typing import Tuple


def stable_text_key(value: str) -> Tuple[str, str]:
    """Total, locale-independent ordering for evidence-bearing text.

    casefold() alone is not a total ordering: values such as ``FC`` and ``fc``
    collide and can inherit nondeterministic set/hash iteration order. The raw
    value is therefore always used as a deterministic secondary key.
    """
    text = str(value)
    return (text.casefold(), text)


def stable_path_score_key(score: int, path: str) -> tuple[int, str, str]:
    """Deterministic descending-score/ascending-path ordering."""
    text = str(path)
    return (-int(score), text.casefold(), text)
