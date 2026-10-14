"""Sessions must not leak between concurrent requests, and must be shared with work
spawned inside them. Regression for C9: one shielded agent pooled every user's state."""

import asyncio
import contextvars
import threading

import pytest

from agentshield import AgentShieldError, Label, Shield, current_session

shield = Shield()


def test_no_session_outside_a_scope() -> None:
    assert current_session() is None


def test_scope_sets_and_restores_the_current_session() -> None:
    with shield.session(user="u1", task="triage") as outer:
        assert current_session() is outer
        assert (outer.user, outer.task) == ("u1", "triage")
        with shield.session(user="u2") as inner:
            assert current_session() is inner
        assert current_session() is outer
    assert current_session() is None


def test_scope_is_reset_when_the_block_raises() -> None:
    with pytest.raises(ValueError), shield.session():
        raise ValueError
    assert current_session() is None


def test_scope_cannot_be_entered_twice() -> None:
    scope = shield.session()
    with scope:
        pass
    with pytest.raises(AgentShieldError), scope:
        pass


def test_sessions_are_distinct() -> None:
    with shield.session() as a, shield.session() as b:
        assert a.id != b.id
        assert a.taint is not b.taint
        assert a.identical_calls is not b.identical_calls


def test_threads_do_not_see_each_others_session() -> None:
    labels = [Label.UNTRUSTED, Label.CONFIDENTIAL, Label.EXTERNAL]
    barrier = threading.Barrier(len(labels))
    seen: dict[str, tuple[str, set[Label], int]] = {}
    errors: list[BaseException] = []

    def worker(user: str, label: Label) -> None:
        try:
            with shield.session(user=user) as s:
                barrier.wait()  # every thread is inside its own session at once
                s.taint.add(label)
                s.tool_calls += 1
                barrier.wait()  # every thread has written before anyone reads
                current = current_session()
                assert current is not None
                seen[user] = (current.user or "", set(current.taint), current.tool_calls)
        except BaseException as exc:  # surfaced below; pytest can't see thread failures
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(f"user{i}", label)) for i, label in enumerate(labels)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert seen == {f"user{i}": (f"user{i}", {label}, 1) for i, label in enumerate(labels)}


def test_asyncio_tasks_do_not_see_each_others_session() -> None:
    async def request(user: str, label: Label) -> tuple[str | None, set[Label]]:
        async with shield.session(user=user) as s:
            await asyncio.sleep(0)
            s.taint.add(label)
            await asyncio.sleep(0)  # let the other task write too
            current = current_session()
            assert current is s
            return current.user, set(current.taint)

    async def main() -> list[tuple[str | None, set[Label]]]:
        return list(
            await asyncio.gather(request("a", Label.UNTRUSTED), request("b", Label.CONFIDENTIAL))
        )

    assert asyncio.run(main()) == [("a", {Label.UNTRUSTED}), ("b", {Label.CONFIDENTIAL})]
    assert current_session() is None


def test_work_spawned_inside_a_session_shares_it() -> None:
    async def child_task() -> None:
        session = current_session()
        assert session is not None
        session.taint.add(Label.UNTRUSTED)

    def child_thread() -> None:
        session = current_session()
        assert session is not None
        session.taint.add(Label.CONFIDENTIAL)

    async def main() -> set[Label]:
        async with shield.session() as s:
            await asyncio.gather(child_task())
            ctx = contextvars.copy_context()
            t = threading.Thread(target=ctx.run, args=(child_thread,))
            t.start()
            t.join()
            return set(s.taint)

    assert asyncio.run(main()) == {Label.UNTRUSTED, Label.CONFIDENTIAL}
