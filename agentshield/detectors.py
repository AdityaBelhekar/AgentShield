"""Optional detectors: heuristics that can only make a decision stricter.

A detector sees text and answers whether it looks like an injection. It never sees the
session or the decision, and the engine applies its answer in exactly two ways:

- on a call the policy would ``allow``, a flagged argument turns it into ``ask``;
- on a completed call, a flagged result adds ``untrusted`` to the session's taint.

``deny`` and ``ask`` are never touched, and taint is only ever added, so a detector that is
wrong, slow or hostile cannot loosen the policy. A detector that raises or runs past its
time limit counts as a flag (fail closed). The limit stops the engine waiting; Python
cannot kill a thread, so each detector runs in its own daemon thread: a hung one is
abandoned, never blocks later calls, and never keeps the process from exiting.

``ChunkedClassifier`` wraps any text classifier that scores a batch of strings. Models
have a short input window and truncate the rest, so an injection buried deep in a long
document is invisible to a single pass; the wrapper scores overlapping chunks and flags
the text if any chunk scores over the threshold.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Sequence
from typing import Protocol

Scorer = Callable[[Sequence[str]], Sequence[float]]
"""Scores a batch of strings; higher means more likely an injection."""


class Detector(Protocol):
    """Anything with a ``name`` and a ``flags(text) -> bool`` method."""

    name: str

    def flags(self, text: str) -> bool: ...


class ChunkedClassifier:
    """Flag text if any overlapping chunk of it scores at or above ``threshold``."""

    def __init__(
        self,
        score: Scorer,
        *,
        threshold: float = 0.5,
        chunk_chars: int = 1500,
        overlap: int = 200,
        name: str = "classifier",
    ) -> None:
        if not 0 <= overlap < chunk_chars:
            raise ValueError("overlap must be at least 0 and smaller than chunk_chars")
        self.score = score
        self.threshold = threshold
        self.chunk_chars = chunk_chars
        self.overlap = overlap
        self.name = name

    def flags(self, text: str) -> bool:
        chunks = chunk(text, self.chunk_chars, self.overlap)
        return bool(chunks) and max(self.score(chunks)) >= self.threshold


def chunk(text: str, size: int, overlap: int) -> list[str]:
    """Split ``text`` into windows of ``size`` characters that overlap by ``overlap``."""
    step = size - overlap
    return [text[start : start + size] for start in range(0, max(len(text) - overlap, 1), step)]


def run_detectors(detectors: Sequence[Detector], text: str, timeout: float) -> str | None:
    """Return the name of the first detector that flags ``text``, or ``None``.

    All detectors run at once and share one deadline of ``timeout`` seconds.
    """
    if not detectors or not text:
        return None
    results: dict[int, bool | None] = {}  # None: the detector raised

    def run(index: int, detector: Detector) -> None:
        try:
            results[index] = bool(detector.flags(text))
        except Exception:  # noqa: BLE001 - a broken detector fails closed
            results[index] = None

    threads = [
        threading.Thread(target=run, args=(i, d), daemon=True, name="agentshield-detector")
        for i, d in enumerate(detectors)
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    for i, (detector, thread) in enumerate(zip(detectors, threads, strict=True)):
        thread.join(max(0.0, deadline - time.monotonic()))
        if thread.is_alive():
            return f"{detector.name} (timed out)"
        if results[i] is None:
            return f"{detector.name} (error)"
        if results[i]:
            return detector.name
    return None


def as_text(value: object) -> str:
    """The text a detector should read for an argument mapping or a tool result."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)
