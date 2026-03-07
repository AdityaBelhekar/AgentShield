# Changelog

All notable changes to AgentShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2024

### Added

- **Phase 0 — Project Foundation**
  - Complete project scaffold with all directories and stub files
  - `pyproject.toml` with full dependency definitions and tool configs
  - `AgentShieldConfig` — Pydantic v2 Settings with `AGENTSHIELD_` env prefix
  - Full exception hierarchy (`AgentShieldError` → 11 specialized exceptions)
  - Docker Compose setup (Redis, backend, frontend)
  - Makefile with development workflow targets
  - Production-grade README, CONTRIBUTING guide
  - Phase 0 test suite (imports, config, exceptions, file validity)
