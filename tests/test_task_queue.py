"""Tests for engine/task_queue/queue.py — TaskQueue."""

from __future__ import annotations

import time

from agies.engine.v2.task_queue import AgentType, TaskDesc, TaskQueue


class TestTaskQueue:
    def test_submit_poll_complete_cycle(self) -> None:
        tq = TaskQueue()
        tq.register(AgentType.MAPPING, TaskDesc(max_concurrency=1, max_attempts=3, timeout=10))
        tid = tq.submit(AgentType.MAPPING, "mapping", {"path": "/p"})
        ready = tq.poll()
        assert len(ready) == 1
        assert ready[0].task_id == tid
        tq.complete(tid)
        assert tq.idle()

    def test_concurrency_limit(self) -> None:
        tq = TaskQueue()
        tq.register(AgentType.MAPPING, TaskDesc(max_concurrency=1, max_attempts=3, timeout=10))
        t1 = tq.submit(AgentType.MAPPING, "mapping", {"a": 1})
        t2 = tq.submit(AgentType.MAPPING, "mapping", {"a": 2})
        ready = tq.poll()
        assert len(ready) == 1  # only one at a time
        assert ready[0].task_id == t1
        tq.complete(t1)
        ready2 = tq.poll()
        assert len(ready2) == 1
        assert ready2[0].task_id == t2

    def test_backoff_delay_enforced(self) -> None:
        """A task with submitted_at in the future must not be poll-able."""
        tq = TaskQueue()
        tq.register(AgentType.MAPPING, TaskDesc(max_concurrency=1, max_attempts=3, timeout=10))
        tid = tq.submit(AgentType.MAPPING, "mapping", {"path": "/p"})

        # Poll once to start it
        ready = tq.poll()
        assert len(ready) == 1

        # Fail it — should re-queue with backoff delay
        will_retry = tq.fail(tid)
        assert will_retry is True  # first failure, will retry

        # Immediately poll — should NOT return the task (backoff delay)
        ready = tq.poll()
        assert len(ready) == 0, "Backoff delay not enforced: task should not be poll-able yet"

    def test_fail_exhausts_retries(self) -> None:
        """After max_attempts failures, task is permanently failed.

        Backoff formula: delay = retry_delay_base ** (failure_count - 1).
        With retry_delay_base=2 and max_attempts=3, retries 1 & 3 have delays
        of 1s and 2s respectively.  We use a short base to keep the test fast.
        """
        tq = TaskQueue()
        # retry_delay_base=0.01 → delay = 0.01**0 = 1.0s for first retry.
        # To keep test fast we accept the 1s wait.
        tq.register(
            AgentType.MAPPING,
            TaskDesc(max_concurrency=1, max_attempts=3, timeout=10, retry_delay_base=0.01),
        )
        tid = tq.submit(AgentType.MAPPING, "mapping", {"path": "/p"})

        # Attempt 1: poll, fail, retry queued
        ready = tq.poll()
        assert len(ready) == 1
        assert tq.fail(tid) is True  # will retry (failure_count=1, delay=1.0s)

        # Attempt 2: wait for backoff, poll, fail, retry queued
        time.sleep(1.1)
        ready = tq.poll()
        assert len(ready) == 1
        assert tq.fail(tid) is True  # will retry (failure_count=2, delay=0.01s)

        # Attempt 3: wait, poll, fail — max_attempts exhausted
        time.sleep(0.05)
        ready = tq.poll()
        assert len(ready) == 1
        assert tq.fail(tid) is False  # final failure, no more retries

        assert tq.idle()

    def test_idle_empty(self) -> None:
        tq = TaskQueue()
        assert tq.idle()

    def test_idle_with_pending(self) -> None:
        tq = TaskQueue()
        tq.register(AgentType.MAPPING, TaskDesc(max_concurrency=1, max_attempts=3, timeout=10))
        tq.submit(AgentType.MAPPING, "mapping", {"path": "/p"})
        assert not tq.idle()

    def test_cancel_running_task(self) -> None:
        tq = TaskQueue()
        tq.register(AgentType.MAPPING, TaskDesc(max_concurrency=1, max_attempts=3, timeout=10))
        tid = tq.submit(AgentType.MAPPING, "mapping", {"path": "/p"})
        tq.poll()  # start running
        tq.cancel(tid)
        assert tq.idle()

    def test_pending_and_running_counts(self) -> None:
        tq = TaskQueue()
        tq.register(AgentType.MAPPING, TaskDesc(max_concurrency=2, max_attempts=3, timeout=10))
        tq.submit(AgentType.MAPPING, "m1", {"a": 1})
        tq.submit(AgentType.MAPPING, "m2", {"a": 2})
        tq.submit(AgentType.MAPPING, "m3", {"a": 3})

        assert tq.pending == 3
        assert tq.running == 0

        tq.poll()
        assert tq.running == 2  # max_concurrency=2
        assert tq.pending == 1

    def test_priority_ordering(self) -> None:
        """Higher-priority tasks (lower value) run first."""
        tq = TaskQueue()
        tq.register(AgentType.VULNERABILITY, TaskDesc(max_concurrency=5, max_attempts=3, timeout=10))
        tq.submit(AgentType.VULNERABILITY, "low", {"p": 3}, priority=0.9)
        tq.submit(AgentType.VULNERABILITY, "high", {"p": 1}, priority=0.1)
        tq.submit(AgentType.VULNERABILITY, "medium", {"p": 2}, priority=0.5)

        ready = tq.poll()
        assert len(ready) == 3
        names = [t.agent_name for t in ready]
        assert names == ["high", "medium", "low"], f"Expected priority order, got {names}"
