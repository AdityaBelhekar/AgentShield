from __future__ import annotations

from typing import Protocol, cast

import numpy as np
from loguru import logger

from agentshield.config import AgentShieldConfig


class _SentenceTransformerLike(Protocol):
    """Minimal protocol for sentence-transformers encode API."""

    def encode(
        self,
        sentences: str | list[str],
        *,
        convert_to_numpy: bool,
        show_progress_bar: bool,
    ) -> np.ndarray:
        """Encode sentence(s) into embedding vectors."""


class EmbeddingService:
    """Loads and manages the sentence-transformers embedding model.

    Shared across all detectors in a single DetectionEngine
    instance. The model is loaded once on first use (lazy init)
    and reused for all embedding computations.

    Loading a sentence-transformer model takes 2-5 seconds.
    Loading it once and reusing saves significant time across
    a session with many events.

    Device selection priority:
      1. ROCm (AMD GPU) via torch.version.hip
      2. CUDA (NVIDIA GPU) via torch.cuda.is_available()
      3. CPU fallback

    Attributes:
        _config: AgentShieldConfig with model name and device.
        _model: Loaded sentence-transformers model or None.
        _device: Resolved device string (cpu/cuda).
    """

    def __init__(self, config: AgentShieldConfig) -> None:
        """Initialize the EmbeddingService.

        The model is not loaded at init time. Loading is deferred
        until the first embed request.

        Args:
            config: AgentShieldConfig with embedding_model and
                embedding_device settings.
        """
        self._config: AgentShieldConfig = config
        self._model: _SentenceTransformerLike | None = None
        self._device: str = "cpu"

        logger.debug(
            "EmbeddingService initialized | model={} device={}",
            self._config.embedding_model,
            self._config.embedding_device,
        )

    def embed(self, text: str) -> np.ndarray | None:
        """Compute a sentence embedding for the given text.

        Loads the model on first call. Returns None when embedding
        cannot be computed so detectors can degrade gracefully.

        Args:
            text: Text to embed.

        Returns:
            Numpy vector of shape (embedding_dim,) or None.
        """
        if not text.strip():
            logger.debug("Empty text passed to embed(), returning None")
            return None

        model = self._get_model()
        if model is None:
            return None

        try:
            embedding = model.encode(
                text,
                convert_to_numpy=True,
                show_progress_bar=False,
            )
            result = np.asarray(embedding, dtype=np.float32)
            logger.debug(
                "Embedding computed | text_len={} shape={}",
                len(text),
                result.shape,
            )
            return result
        except (RuntimeError, ValueError, TypeError) as exc:
            logger.error("Embedding computation failed | error={}", exc)
            return None

    def embed_batch(self, texts: list[str]) -> list[np.ndarray | None]:
        """Compute embeddings for a batch of texts.

        Args:
            texts: List of text strings to embed.

        Returns:
            List of embedding vectors or None values, preserving order.
        """
        if not texts:
            return []

        model = self._get_model()
        if model is None:
            return [None] * len(texts)

        try:
            embeddings = model.encode(
                texts,
                convert_to_numpy=True,
                show_progress_bar=False,
            )
            return [np.asarray(vector, dtype=np.float32) for vector in embeddings]
        except (RuntimeError, ValueError, TypeError) as exc:
            logger.error("Batch embedding failed | count={} error={}", len(texts), exc)
            return [None] * len(texts)

    def is_available(self) -> bool:
        """Check whether the embedding model is available.

        Returns:
            True if the model loaded successfully, else False.
        """
        return self._get_model() is not None

    def _get_model(self) -> _SentenceTransformerLike | None:
        """Lazily load and return the sentence-transformers model.

        Returns:
            Loaded model or None when the dependency or model load fails.
        """
        if self._model is not None:
            return self._model

        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            logger.warning(
                "sentence-transformers not installed; semantic detection disabled"
            )
            return None

        self._device = self._detect_device()
        logger.info(
            "Loading embedding model | model={} device={}",
            self._config.embedding_model,
            self._device,
        )

        try:
            loaded_model = SentenceTransformer(
                self._config.embedding_model,
                device=self._device,
            )
        except (RuntimeError, OSError, ValueError) as exc:
            logger.error(
                "Failed to load embedding model | model={} error={}",
                self._config.embedding_model,
                exc,
            )
            return None

        self._model = cast(_SentenceTransformerLike, loaded_model)
        logger.info(
            "Embedding model loaded successfully | model={} device={}",
            self._config.embedding_model,
            self._device,
        )
        return self._model

    def _detect_device(self) -> str:
        """Detect the best available compute device.

        Uses configured device directly when embedding_device is not
        set to "auto".

        Returns:
            Device string for sentence-transformers: "cpu" or "cuda".
        """
        if self._config.embedding_device != "auto":
            logger.info(
                "Using configured embedding device | device={}",
                self._config.embedding_device,
            )
            return self._config.embedding_device

        try:
            import torch
        except ImportError:
            logger.debug("torch not available; defaulting embeddings to CPU")
            return "cpu"

        if getattr(torch.version, "hip", None) is not None:
            logger.info("AMD ROCm GPU detected; using cuda backend")
            return "cuda"

        if torch.cuda.is_available():
            logger.info(
                "NVIDIA CUDA GPU detected | device={}",
                torch.cuda.get_device_name(0),
            )
            return "cuda"

        logger.info("No GPU detected; using CPU for embeddings")
        return "cpu"
