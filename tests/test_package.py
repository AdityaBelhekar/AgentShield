"""Guards on what the core package costs to install and import."""

import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE_DEPENDENCIES = {"pydantic", "pyyaml"}
HEAVY_MODULES = {"torch", "sentence_transformers", "numpy", "redis", "langchain_core", "openai"}


def test_core_dependencies_stay_light() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    names = {
        re.split(r"[<>=!~\[; ]", dep, maxsplit=1)[0].lower() for dep in project["dependencies"]
    }
    assert names == CORE_DEPENDENCIES


def test_import_is_fast_and_pulls_nothing_heavy() -> None:
    # Dependencies are imported before the clock starts: pydantic's own import time varies
    # several-fold between machines, and this test is about AgentShield's share.
    code = (
        "import sys, time\n"
        "import yaml\n"
        "from pydantic import BaseModel  # plain 'import pydantic' is a lazy shim\n"
        "t = time.perf_counter()\n"
        "import agentshield\n"
        "print(time.perf_counter() - t)\n"
        f"print(','.join(sorted({HEAVY_MODULES!r} & set(sys.modules))))\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    assert float(out[0]) < 0.5
    assert out[1] == ""
