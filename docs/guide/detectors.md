# Detectors

Detectors are optional heuristics. They can only make a decision stricter.

A detector is any object with a `name` and `flags(text) -> bool`. The engine applies it in
exactly two places:

- on a call the policy would **allow**, a flagged argument turns it into `ask`;
- on a completed call, a flagged **result** adds `untrusted` taint, so your flows apply.

It never sees the session or the decision, and `deny` and `ask` are never touched. A detector
that raises or exceeds `detector_timeout` (default 2 seconds) counts as a flag.

```python
shield = Shield.from_policy("policy.yaml", detectors=[my_detector], detector_timeout=2.0)
```

## Chunking

Classifiers read a short window and truncate the rest, so an injection deep in a long
document is invisible to one pass. `ChunkedClassifier` wraps any scorer that takes a list of
strings and returns a list of scores, and flags the text if any overlapping window scores at
or above the threshold.

```python
from agentshield.detectors import ChunkedClassifier

detector = ChunkedClassifier(my_scores, threshold=0.5, chunk_chars=400, overlap=250)
```

## The bundled classifier

```bash
pip install "agentshield-x[classifier]"
```

```python
from agentshield.classifier import prompt_injection_detector

shield = Shield.from_policy(
    "policy.yaml", detectors=[prompt_injection_detector()], detector_timeout=5.0
)
```

ProtectAI's `deberta-v3-base-prompt-injection-v2` (Apache-2.0), pinned to one revision, on
ONNX Runtime without torch. The first use downloads about 750 MB into the Hugging Face cache;
loading takes a few seconds and about 1 GB of memory, so build it once.

Window size was measured, not derived from the 512-token limit: the model reliably flags an
injection in roughly the first 200 characters of its input and often misses one later in a
longer input. The default windows are 400 characters, overlapping by 250.

Measured with `agentshield bench --classifier` on a laptop CPU, threshold 0.5:

| Set | Injections detected | False positives |
|---|---|---|
| `deepset/prompt-injections` test, all 116 rows | 36.7% (22/60) | 0.0% (0/56) |
| English rows (76) | 30.8% (12/39) | 0.0% (0/37) |
| German rows (40, heuristic split) | 47.6% (10/21) | 0.0% (0/19) |
| The 12 English injections it detects alone, buried 5,000 characters into an 8,000-character document | one pass 0%, chunked 58.3% (7/12) | 0/10 clean documents |

Latency: short text median 23 ms (p95 61 ms); an 8,000-character result median 2.5 s (p95
3.4 s).

!!! note "How to read this"
    It is a weak, precise second opinion: it rarely flags benign text and misses most of
    this dataset, whose labels also count role-play and off-topic requests as injections.
    The policy is the boundary, not the classifier. Because a timeout counts as a flag, raise
    `detector_timeout` if your tools return long documents. Known quirk: one sentence
    repeated dozens of times scores as an injection.
