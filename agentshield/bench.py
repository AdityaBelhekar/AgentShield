"""Run AgentDojo's banking suite with every tool call through the enforcement engine.

This module lives behind the ``[bench]`` extra. It tests AgentShield itself, not a model:
the default ``scripted`` mode drives AgentDojo's real suite, environment and task
checkers with a pipeline that executes the user task's ground-truth calls and, for the
attack runs, the injection task's ground-truth calls too. That is the worst case for the
policy -- an agent that always follows an injected instruction -- so the numbers measure
what the enforcement layer lets through, not how often a model is fooled.

``--model`` switches to a real AgentDojo pipeline and attack. It needs a provider API key
and is not what CI runs.

Metrics, per configuration (``unshielded`` / ``shielded``):

* utility: share of user tasks whose checker passes with no injection.
* utility-under-attack: share of user tasks that still pass when an injection is present.
* attack-success-rate (ASR): share of (user task, injection task) pairs whose checker
  passes. An injection that runs is a success for the attacker, so lower is better.

Run it with::

    agentshield bench
    agentshield bench --user-tasks user_task_0 --injection-tasks injection_task_0
    agentshield bench --markdown
    agentshield bench --model gpt-4o-2024-08-06
"""

from __future__ import annotations

import importlib.metadata
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any, Literal

from agentshield.policy import Policy, load_policy
from agentshield.session import Decision, Session, ToolCall, Verdict
from agentshield.shield import Shield

BENCH_SUITE = "banking"
BENCH_VERSION = "v1.2.2"
DEFAULT_ATTACK = "important_instructions"

ApprovalMode = Literal["deny", "allow"]
ConfigName = Literal["unshielded", "shielded"]
RunMode = Literal["scripted", "model"]


def banking_policy() -> Policy:
    """Load the AgentDojo banking policy shipped with the package."""
    resource = files("agentshield.policies").joinpath("agentdojo-banking.yaml")
    with as_file(resource) as path:
        return load_policy(path)


@dataclass(frozen=True, slots=True)
class CallRecord:
    """What the enforcement layer did with one attempted tool call."""

    tool: str
    verdict: str
    rule: str | None
    reason: str
    executed: bool


@dataclass(slots=True)
class Recorder:
    """Collects the calls of one task run, so failures can be read call by call."""

    calls: list[CallRecord] = field(default_factory=list)

    @property
    def blocked(self) -> int:
        return sum(1 for call in self.calls if not call.executed)

    @property
    def approval_requests(self) -> int:
        return sum(1 for call in self.calls if call.verdict == Verdict.ASK.value)


@dataclass(frozen=True, slots=True)
class TaskResult:
    """One run: a user task alone, or a user task with one injection task."""

    user_task: str
    injection_task: str | None
    utility: bool | None
    attack_succeeded: bool | None
    calls: tuple[CallRecord, ...]
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ConfigMetrics:
    """Aggregate numbers for one configuration."""

    config: str
    utility: float
    utility_under_attack: float | None
    attack_success_rate: float | None
    tool_calls: int
    executed: int
    blocked: int
    approval_requests: int


@dataclass(frozen=True, slots=True)
class ConfigReport:
    """Metrics plus every run, so a failure can be read without rerunning."""

    metrics: ConfigMetrics
    tasks: tuple[TaskResult, ...]


@dataclass(frozen=True, slots=True)
class BenchReport:
    """The result of one benchmark invocation."""

    metadata: Mapping[str, Any]
    configs: tuple[ConfigReport, ...]

    def config(self, name: str) -> ConfigReport:
        for report in self.configs:
            if report.metrics.config == name:
                return report
        raise KeyError(f"no {name!r} configuration in this report")

    def as_dict(self) -> dict[str, Any]:
        return {
            "metadata": dict(self.metadata),
            "configs": [
                {
                    "metrics": {
                        "config": report.metrics.config,
                        "utility": report.metrics.utility,
                        "utility_under_attack": report.metrics.utility_under_attack,
                        "attack_success_rate": report.metrics.attack_success_rate,
                        "tool_calls": report.metrics.tool_calls,
                        "executed": report.metrics.executed,
                        "blocked": report.metrics.blocked,
                        "approval_requests": report.metrics.approval_requests,
                    },
                    "tasks": [
                        {
                            "user_task": task.user_task,
                            "injection_task": task.injection_task,
                            "utility": task.utility,
                            "attack_succeeded": task.attack_succeeded,
                            "error": task.error,
                            "calls": [
                                {
                                    "tool": call.tool,
                                    "verdict": call.verdict,
                                    "rule": call.rule,
                                    "reason": call.reason,
                                    "executed": call.executed,
                                }
                                for call in task.calls
                            ],
                        }
                        for task in report.tasks
                    ],
                }
                for report in self.configs
            ],
        }


def run_benchmark(
    *,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    attack: str = DEFAULT_ATTACK,
    user_tasks: Sequence[str] | None = None,
    injection_tasks: Sequence[str] | None = None,
    approval: ApprovalMode = "deny",
    suite_name: str = BENCH_SUITE,
    benchmark_version: str = BENCH_VERSION,
    configs: Sequence[ConfigName] = ("unshielded", "shielded"),
) -> BenchReport:
    """Run the suite once per configuration and return the aggregate report.

    ``model=None`` is the scripted, deterministic mode. ``approval="deny"`` is the
    no-human baseline: a call the policy answers with ``ask`` does not run. Use
    ``approval="allow"`` to measure what happens when every prompt is approved.
    """
    if approval not in ("deny", "allow"):
        raise ValueError(f"approval must be 'deny' or 'allow', not {approval!r}")
    for name in configs:
        if name not in ("unshielded", "shielded"):
            raise ValueError(f"unknown configuration {name!r}")

    suite = _load_suite(benchmark_version, suite_name)
    user_ids = _select_ids(sorted(suite.user_tasks, key=_task_number), user_tasks, "user task")
    injection_ids = _select_ids(
        sorted(suite.injection_tasks, key=_task_number), injection_tasks, "injection task"
    )
    mode: RunMode = "scripted" if model is None else "model"
    pipeline: Any = None
    attack_name = attack
    if model is not None:
        pipeline = _model_pipeline(model, base_url=base_url, api_key=api_key)
        if base_url and attack_name == DEFAULT_ATTACK:
            # A custom endpoint has no AgentDojo model name to put in the attack prompt.
            attack_name = "important_instructions_no_model_name"

    attack_obj: Any = None
    if model is not None:
        try:
            from agentdojo.attacks.attack_registry import load_attack
        except ImportError as exc:  # pragma: no cover - only when the extra is missing
            raise ImportError(_MISSING_EXTRA) from exc
        attack_obj = load_attack(attack_name, suite, pipeline)

    report_configs: list[ConfigReport] = []
    for name in configs:
        shield = None
        if name == "shielded":
            shield = Shield(banking_policy(), approval=_approval_handler(approval))
        report_configs.append(
            _run_config(
                suite=suite,
                shield=shield,
                config=name,
                user_ids=user_ids,
                injection_ids=injection_ids,
                scripted=model is None,
                pipeline=pipeline,
                attack=attack_obj,
            )
        )

    metadata = {
        "suite": suite_name,
        "benchmark_version": benchmark_version,
        "mode": mode,
        "model": model if model is not None else "scripted",
        "attack": attack_name if model is not None else None,
        "approval": approval,
        "agentdojo": _package_version("agentdojo"),
        "commit": _git_commit(),
        "date": datetime.now(UTC).date().isoformat(),
        "user_tasks": len(user_ids),
        "injection_tasks": len(injection_ids),
    }
    return BenchReport(metadata=metadata, configs=tuple(report_configs))


_MISSING_EXTRA = 'the AgentDojo benchmark needs the bench extra: pip install "agentshield-x[bench]"'


def _load_suite(benchmark_version: str, suite_name: str) -> Any:
    try:
        from agentdojo.task_suite.load_suites import get_suite
    except ImportError as exc:
        raise ImportError(_MISSING_EXTRA) from exc
    try:
        return get_suite(benchmark_version, suite_name)
    except KeyError as exc:
        raise ValueError(f"unknown AgentDojo suite {benchmark_version}/{suite_name}") from exc


def _select_ids(
    available: Sequence[str], wanted: Sequence[str] | None, what: str
) -> tuple[str, ...]:
    if wanted is None:
        return tuple(available)
    unknown = [task_id for task_id in wanted if task_id not in available]
    if unknown:
        raise ValueError(
            f"unknown {what}(s): {', '.join(unknown)}; choose from {', '.join(available)}"
        )
    return tuple(wanted)


def _task_number(task_id: str) -> int:
    try:
        return int(task_id.rsplit("_", 1)[1])
    except (IndexError, ValueError):
        return 0


def _approval_handler(mode: ApprovalMode) -> Any:
    if mode == "allow":
        return lambda call, decision: True
    return None


def _approved(shield: Shield, call: ToolCall, decision: Decision) -> bool:
    handler = shield.approval
    if handler is None:
        return False
    try:
        return bool(handler(call, decision))
    except Exception:
        return False


def _runtime_class(shield: Shield | None, recorder: Recorder) -> Any:
    try:
        from agentdojo.functions_runtime import FunctionsRuntime
    except ImportError as exc:  # pragma: no cover - only when the extra is missing
        raise ImportError(_MISSING_EXTRA) from exc

    class _Runtime(FunctionsRuntime):  # type: ignore[misc]
        def __init__(self, functions: Sequence[Any]) -> None:
            super().__init__(functions)
            self.session = Session()

        def run_function(
            self,
            env: Any,
            function: str,
            kwargs: Mapping[str, Any],
            raise_on_error: bool = False,
        ) -> tuple[Any, str | None]:
            if shield is None:
                result, error = super().run_function(
                    env, function, kwargs, raise_on_error=raise_on_error
                )
                recorder.calls.append(CallRecord(function, "allow", None, "", error is None))
                return result, error

            call = ToolCall(function, dict(kwargs))
            decision = shield.engine.check(call, self.session)
            if decision.verdict is Verdict.DENY:
                recorder.calls.append(
                    CallRecord(function, "deny", decision.rule, decision.reason, False)
                )
                return "", f"AgentShield denied: {decision.reason}"
            if decision.verdict is Verdict.ASK and not _approved(shield, call, decision):
                recorder.calls.append(
                    CallRecord(
                        function,
                        Verdict.ASK.value,
                        decision.rule,
                        decision.reason,
                        False,
                    )
                )
                return "", f"AgentShield approval required: {decision.reason}"

            try:
                result, error = super().run_function(
                    env, function, kwargs, raise_on_error=raise_on_error
                )
            finally:
                shield.engine.record(call, session=self.session)
            recorder.calls.append(
                CallRecord(
                    function,
                    decision.verdict.value,
                    decision.rule,
                    decision.reason,
                    error is None,
                )
            )
            return result, error

    return _Runtime


def _run_config(
    *,
    suite: Any,
    shield: Shield | None,
    config: str,
    user_ids: Sequence[str],
    injection_ids: Sequence[str],
    scripted: bool,
    pipeline: Any,
    attack: Any,
) -> ConfigReport:
    tasks: list[TaskResult] = []
    utilities: list[bool] = []
    attacked_utilities: list[bool] = []
    attacks: list[bool] = []

    for user_id in user_ids:
        user_task = suite.get_user_task_by_id(user_id)

        recorder = Recorder()
        runtime = _runtime_class(shield, recorder)
        honest = _scripted_pipeline(user_task) if scripted else pipeline
        utility, _ = suite.run_task_with_pipeline(
            honest,
            user_task,
            injection_task=None,
            injections={},
            runtime_class=runtime,
        )
        utilities.append(utility)
        tasks.append(TaskResult(user_id, None, utility, None, tuple(recorder.calls)))

        for injection_id in injection_ids:
            injection_task = suite.get_injection_task_by_id(injection_id)
            recorder = Recorder()
            runtime = _runtime_class(shield, recorder)
            if scripted:
                compromised = _scripted_pipeline(user_task, injection_task=injection_task)
                injections: dict[str, str] = {}
            else:
                compromised = pipeline
                try:
                    injections = attack.attack(user_task, injection_task)
                except ValueError as exc:
                    tasks.append(TaskResult(user_id, injection_id, None, None, (), str(exc)))
                    continue
            try:
                attacked_utility, attack_succeeded = suite.run_task_with_pipeline(
                    compromised,
                    user_task,
                    injection_task=injection_task,
                    injections=injections,
                    runtime_class=runtime,
                )
            except Exception as exc:  # a broken run is a result, not a crash
                tasks.append(TaskResult(user_id, injection_id, None, None, (), str(exc)))
                continue
            attacked_utilities.append(attacked_utility)
            attacks.append(attack_succeeded)
            tasks.append(
                TaskResult(
                    user_id,
                    injection_id,
                    attacked_utility,
                    attack_succeeded,
                    tuple(recorder.calls),
                )
            )

    all_calls = [call for task in tasks for call in task.calls]
    metrics = ConfigMetrics(
        config=config,
        utility=_mean(utilities) or 0.0,
        utility_under_attack=_mean(attacked_utilities),
        attack_success_rate=_mean(attacks),
        tool_calls=len(all_calls),
        executed=sum(1 for call in all_calls if call.executed),
        blocked=sum(1 for call in all_calls if not call.executed),
        approval_requests=sum(1 for call in all_calls if call.verdict == Verdict.ASK.value),
    )
    return ConfigReport(metrics=metrics, tasks=tuple(tasks))


def _mean(values: Sequence[bool]) -> float | None:
    if not values:
        return None
    return sum(1 for value in values if value) / len(values)


def _scripted_pipeline(user_task: Any, injection_task: Any | None = None) -> Any:
    """A pipeline that executes ground-truth calls directly, with no model.

    With an injection task, it executes the user task's calls followed by the injection
    task's calls: the compromised agent at its most dangerous.
    """
    try:
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
        from agentdojo.functions_runtime import EmptyEnv
        from agentdojo.types import (
            ChatAssistantMessage,
            ChatToolResultMessage,
            text_content_block_from_string,
        )
    except ImportError as exc:  # pragma: no cover - only when the extra is missing
        raise ImportError(_MISSING_EXTRA) from exc

    class _ScriptedPipeline(BasePipelineElement):  # type: ignore[misc]
        name = "agentshield-scripted"

        def query(
            self,
            query: str,
            runtime: Any,
            env: Any = None,
            messages: Sequence[Any] = (),
            extra_args: dict[str, Any] | None = None,
        ) -> tuple[Any, Any, Any, list[Any], dict[str, Any]]:
            if env is None:
                env = EmptyEnv()
            conversation = list(messages)
            calls = list(user_task.ground_truth(env))
            if injection_task is not None:
                calls.extend(injection_task.ground_truth(env))
            for call in calls:
                conversation.append(
                    ChatAssistantMessage(
                        role="assistant",
                        content=[text_content_block_from_string("")],
                        tool_calls=[call],
                    )
                )
                result, error = runtime.run_function(
                    env, call.function, call.args, raise_on_error=False
                )
                conversation.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(tool_result_to_str(result))],
                        tool_call=call,
                        tool_call_id=None,
                        error=error,
                    )
                )
            conversation.append(
                ChatAssistantMessage(
                    role="assistant",
                    content=[text_content_block_from_string(user_task.GROUND_TRUTH_OUTPUT)],
                    tool_calls=None,
                )
            )
            return query, runtime, env, conversation, extra_args or {}

    return _ScriptedPipeline()


def _model_pipeline(model: str, *, base_url: str | None, api_key: str | None) -> Any:
    try:
        from agentdojo.agent_pipeline.agent_pipeline import (
            AgentPipeline,
            PipelineConfig,
            load_system_message,
        )
    except ImportError as exc:
        raise ImportError(_MISSING_EXTRA) from exc

    if base_url:
        try:
            import openai
            from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
            from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
            from agentdojo.agent_pipeline.tool_execution import (
                ToolsExecutionLoop,
                ToolsExecutor,
            )
        except ImportError as exc:
            raise ImportError(
                "the --base-url option needs an OpenAI-compatible server and the "
                "openai package: " + _MISSING_EXTRA
            ) from exc
        client = openai.OpenAI(base_url=base_url, api_key=api_key or "EMPTY")
        llm = OpenAILLM(client, model)
        pipeline = AgentPipeline(
            [
                SystemMessage(load_system_message(None)),
                InitQuery(),
                ToolsExecutionLoop([ToolsExecutor(), llm]),
            ]
        )
        pipeline.name = model
        return pipeline

    config = PipelineConfig(
        llm=model,
        model_id=None,
        defense=None,
        system_message_name=None,
        system_message=None,
    )
    return AgentPipeline.from_config(config)


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _git_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return completed.stdout.strip() or "unknown"


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def format_table(report: BenchReport) -> str:
    """A plain-text table for the terminal."""
    metadata = report.metadata
    mode = "scripted (no model)" if metadata["mode"] == "scripted" else metadata["model"]
    lines = [
        f"suite: {metadata['suite']} ({metadata['benchmark_version']})  "
        f"mode: {mode}  attack: {metadata['attack'] or '-'}  "
        f"tasks: {metadata['user_tasks']} user / {metadata['injection_tasks']} injection",
        f"agentdojo {metadata['agentdojo']}  commit {metadata['commit']}  "
        f"approval: {metadata['approval']}  date: {metadata['date']}",
        "",
    ]
    headers = (
        "config",
        "utility",
        "utility-under-attack",
        "attack-success-rate",
        "blocked calls",
        "approvals",
    )
    rows = [
        (
            item.metrics.config,
            _percent(item.metrics.utility),
            _percent(item.metrics.utility_under_attack),
            _percent(item.metrics.attack_success_rate),
            f"{item.metrics.blocked}/{item.metrics.tool_calls}",
            str(item.metrics.approval_requests),
        )
        for item in report.configs
    ]
    widths = [max(len(row[i]) for row in [headers, *rows]) for i in range(len(headers))]
    for row in [headers, *rows]:
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    return "\n".join(lines)


def format_markdown(report: BenchReport) -> str:
    """A markdown table, for the README."""
    metadata = report.metadata
    mode = "scripted" if metadata["mode"] == "scripted" else f"`{metadata['model']}`"
    lines = [
        f"<!-- generated by agentshield bench at commit {metadata['commit']} -->",
        "",
        f"Suite: `{metadata['suite']}` ({metadata['benchmark_version']}), "
        f"mode: {mode}, attack: `{metadata['attack'] or 'none'}`, "
        f"AgentDojo {metadata['agentdojo']}, date: {metadata['date']}.",
        "",
        "| config | utility | utility under attack | attack success rate "
        "| blocked calls | approval requests |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in report.configs:
        lines.append(
            f"| {item.metrics.config} | {_percent(item.metrics.utility)} "
            f"| {_percent(item.metrics.utility_under_attack)} "
            f"| {_percent(item.metrics.attack_success_rate)} "
            f"| {item.metrics.blocked}/{item.metrics.tool_calls} "
            f"| {item.metrics.approval_requests} |"
        )
    return "\n".join(lines)
