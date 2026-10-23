"""Allow ``python -m agentshield`` to run the CLI."""

from agentshield.cli import main

raise SystemExit(main())
