from __future__ import annotations

import asyncio

from loguru import logger

from agentshield.siem.http_exporter import HttpSIEMExporter
from agentshield.siem.siem_config import SIEMConfig
from agentshield.siem.syslog_exporter import SyslogSIEMExporter


class SIEMManager:
    """Orchestrates enabled SIEM exporters behind a single API."""

    _config: SIEMConfig
    _exporters: list[SyslogSIEMExporter | HttpSIEMExporter]

    def __init__(
        self,
        siem_config: SIEMConfig,
        redis_url: str,
        version: str = "0.1.0",
    ) -> None:
        """Initialize manager and enabled exporter instances.

        Args:
            siem_config: Validated SIEM configuration snapshot.
            redis_url: Redis URL for event pub/sub subscriptions.
            version: AgentShield version string for export metadata.
        """
        self._config = siem_config
        self._exporters = []

        if siem_config.syslog_enabled:
            self._exporters.append(
                SyslogSIEMExporter(siem_config, version=version, redis_url=redis_url)
            )

        if siem_config.http_enabled:
            self._exporters.append(
                HttpSIEMExporter(siem_config, version=version, redis_url=redis_url)
            )

        if not self._exporters:
            logger.warning("SIEMManager: no exporters enabled.")

    async def start(self) -> None:
        """Start all enabled SIEM exporters."""
        if not self._exporters:
            logger.info("SIEMManager started (0 exporters)")
            return

        results = await asyncio.gather(
            *(exporter.start() for exporter in self._exporters),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, Exception):
                logger.warning("SIEMManager start warning | error={}", result)

        logger.info("SIEMManager started ({} exporters)", len(self._exporters))

    async def stop(self) -> None:
        """Stop all SIEM exporters gracefully."""
        if not self._exporters:
            logger.info("SIEMManager stopped.")
            return

        results = await asyncio.gather(
            *(exporter.stop() for exporter in self._exporters),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, Exception):
                logger.warning("SIEMManager stop warning | error={}", result)

        logger.info("SIEMManager stopped.")
