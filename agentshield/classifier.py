"""A prompt-injection classifier that runs on ONNX Runtime, without torch.

The model is ProtectAI's ``deberta-v3-base-prompt-injection-v2`` (Apache-2.0), pinned to
one revision. It reads at most 512 tokens, so it is wrapped in ``ChunkedClassifier``: long
text is scored in overlapping chunks and flagged if any chunk is.

    pip install "agentshield-x[classifier]"

    from agentshield.classifier import prompt_injection_detector

    shield = Shield.from_policy("policy.yaml", detectors=[prompt_injection_detector()])

The first call downloads about 750 MB into the Hugging Face cache. Loading takes a few
seconds and about 1 GB of memory, so build the detector once and reuse it. The model is
trained on English; other languages are scored less reliably.

Cost on a laptop CPU: tens of milliseconds for short text, about 1 second per 3,000
characters of a long result. The engine's default 2-second detector limit fails closed,
so a long result over the limit is treated as flagged; raise ``detector_timeout`` on
``Shield`` if your tools return long documents. Known quirk: one sentence repeated many
times scores as an injection.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from agentshield.detectors import ChunkedClassifier, Scorer

MODEL_REPO = "protectai/deberta-v3-base-prompt-injection-v2"
MODEL_REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"
MODEL_FILES = ("onnx/config.json", "onnx/tokenizer.json", "onnx/model.onnx")
MAX_TOKENS = 512
# Measured, not derived from the 512-token window: the model reliably flags an injection
# in roughly the first 200 characters of its input but often misses one later in a longer
# input. Small windows that overlap heavily put every injection near some window's start.
# ponytail: fixed windows; windows that start at paragraph breaks would need fewer runs.
CHUNK_CHARS = 400
CHUNK_OVERLAP = 250

_MISSING_EXTRA = 'the classifier needs its extra: pip install "agentshield-x[classifier]"'


def model_dir(*, download: bool = True) -> Path:
    """The local directory holding the pinned model, downloading it if allowed."""
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(_MISSING_EXTRA) from exc
    paths = [
        hf_hub_download(MODEL_REPO, name, revision=MODEL_REVISION, local_files_only=not download)
        for name in MODEL_FILES
    ]
    return Path(str(paths[0])).parent


def onnx_scorer(directory: str | Path | None = None) -> Scorer:
    """Load the model and return a function scoring a batch of strings from 0 to 1."""
    try:
        import numpy as np
        import onnxruntime
        from tokenizers import Tokenizer
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(_MISSING_EXTRA) from exc

    root = Path(directory) if directory is not None else model_dir()
    labels: dict[str, str] = json.loads((root / "config.json").read_text("utf-8"))["id2label"]
    injection = next(int(i) for i, name in labels.items() if "INJECTION" in name.upper())
    tokenizer = Tokenizer.from_file(str(root / "tokenizer.json"))
    tokenizer.enable_truncation(MAX_TOKENS)
    tokenizer.enable_padding()
    session = onnxruntime.InferenceSession(
        str(root / "model.onnx"), providers=["CPUExecutionProvider"]
    )
    inputs = {i.name for i in session.get_inputs()}

    def score(texts: Sequence[str]) -> list[float]:
        # Small batches keep memory flat for very long documents.
        return [p for start in range(0, len(texts), 8) for p in _batch(texts[start : start + 8])]

    def _batch(texts: Sequence[str]) -> list[float]:
        encoded = tokenizer.encode_batch(list(texts))
        feeds: dict[str, Any] = {
            "input_ids": np.array([e.ids for e in encoded], dtype=np.int64),
            "attention_mask": np.array([e.attention_mask for e in encoded], dtype=np.int64),
        }
        if "token_type_ids" in inputs:
            feeds["token_type_ids"] = np.array([e.type_ids for e in encoded], dtype=np.int64)
        logits = session.run(None, feeds)[0]
        exp = np.exp(logits - logits.max(axis=1, keepdims=True))
        probabilities = exp / exp.sum(axis=1, keepdims=True)
        return [float(p) for p in probabilities[:, injection]]

    return score


DATASET = "deepset/prompt-injections"  # Apache-2.0; not among the model's named training sets
_ROWS_URL = (
    "https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections"
    "&config=default&split=test&offset={offset}&length=100"
)
_GERMAN_HINTS = (" und ", " der ", " die ", " das ", " nicht ", " ich ", " ist ", " sie ", " wie ")
_FILLER = (
    "The quarterly report shows revenue in line with the forecast.",
    "Hiring continued in the support and platform teams.",
    "The office move is planned for the second half of the year.",
    "Customer satisfaction scores improved slightly over the last survey.",
    "Travel expenses must be submitted within thirty days.",
    "The infrastructure migration finished ahead of schedule.",
)


def load_eval_set() -> list[tuple[str, bool]]:
    """The test split of ``deepset/prompt-injections`` as ``(text, is_injection)`` pairs."""
    import time
    import urllib.request

    rows: list[tuple[str, bool]] = []
    offset, total = 0, 1
    while offset < total:
        for attempt in range(5):
            try:
                with urllib.request.urlopen(_ROWS_URL.format(offset=offset), timeout=30) as r:
                    page = json.load(r)
                break
            except OSError:
                if attempt == 4:
                    raise
                time.sleep(2)
        total = page["num_rows_total"]
        rows.extend((row["row"]["text"], row["row"]["label"] == 1) for row in page["rows"])
        offset += 100
    return rows


def is_german(text: str) -> bool:
    """A rough heuristic, good enough to split the report by language."""
    padded = f" {text.lower()} "
    return any(c in padded for c in "äöüß") or sum(h in padded for h in _GERMAN_HINTS) >= 2


def evaluate(
    scorer: Scorer, rows: Sequence[tuple[str, bool]], threshold: float = 0.5
) -> dict[str, Any]:
    """Detection rate, false-positive rate and latency, overall and by language.

    Also buries each English injection the model catches on its own 5,000 characters deep
    in an 8,000-character benign document and compares one pass (which reads only the
    first 512 tokens) with the chunked detector, and checks the same documents without
    the injection for false positives.
    """
    import random
    import statistics
    import time

    def rates(subset: Sequence[tuple[bool, bool]]) -> dict[str, Any]:
        positives = [flag for flag, label in subset if label]
        negatives = [flag for flag, label in subset if not label]
        return {
            "rows": len(subset),
            "injections": len(positives),
            "benign": len(negatives),
            "detection_rate": sum(positives) / len(positives) if positives else None,
            "false_positive_rate": sum(negatives) / len(negatives) if negatives else None,
        }

    results: list[tuple[bool, bool, bool]] = []  # (flagged, label, german)
    latencies: list[float] = []
    for text, label in rows:
        started = time.perf_counter()
        flagged = scorer([text])[0] >= threshold
        latencies.append(time.perf_counter() - started)
        results.append((flagged, label, is_german(text)))

    rng = random.Random(0)
    filler = " ".join(rng.choice(_FILLER) for _ in range(500))[:8_000]
    chunked = ChunkedClassifier(
        scorer, threshold=threshold, chunk_chars=CHUNK_CHARS, overlap=CHUNK_OVERLAP
    )
    # Only English injections the model already flags on their own, so this measures the
    # chunking, not the model's recall.
    buried = [
        text
        for (text, _), (flagged, label, german) in zip(rows, results, strict=True)
        if label and flagged and not german
    ]
    single, chunks, long_latency = 0, 0, []
    for text in buried:
        document = filler[:5_000] + "\n\n" + text + "\n\n" + filler[5_000:]
        single += scorer([document])[0] >= threshold
        started = time.perf_counter()
        chunks += chunked.flags(document)
        long_latency.append(time.perf_counter() - started)
    clean_flagged = sum(chunked.flags(filler[i * 800 :] + filler[: i * 800]) for i in range(10))

    def quantile(values: list[float], q: float) -> float:
        return sorted(values)[min(len(values) - 1, int(q * len(values)))] * 1000

    return {
        "model": f"{MODEL_REPO}@{MODEL_REVISION[:12]}",
        "dataset": f"{DATASET} (test split)",
        "threshold": threshold,
        "overall": rates([(f, label) for f, label, _ in results]),
        "english": rates([(f, label) for f, label, de in results if not de]),
        "german": rates([(f, label) for f, label, de in results if de]),
        "buried": {
            "documents": len(buried),
            "chars": len(filler),
            "single_pass_detection_rate": single / len(buried) if buried else None,
            "chunked_detection_rate": chunks / len(buried) if buried else None,
            "clean_documents_flagged": f"{clean_flagged}/10",
        },
        "latency_ms": {
            "short_median": statistics.median(latencies) * 1000,
            "short_p95": quantile(latencies, 0.95),
            "long_median": statistics.median(long_latency) * 1000 if long_latency else None,
            "long_p95": quantile(long_latency, 0.95) if long_latency else None,
        },
    }


def prompt_injection_detector(
    directory: str | Path | None = None, *, threshold: float = 0.5
) -> ChunkedClassifier:
    """The pinned classifier as a detector for ``Shield(detectors=[...])``."""
    return ChunkedClassifier(
        onnx_scorer(directory),
        threshold=threshold,
        chunk_chars=CHUNK_CHARS,
        overlap=CHUNK_OVERLAP,
        name="prompt-injection-classifier",
    )
