"""Thread-safe priority task queue with concurrency limits and retry.

Inspired by Xint's ``crs/common/workdb.py`` (WorkDB + BulkTaskWorker).

Usage::

    tq = TaskQueue()
    tq.register(AgentType.VULNERABILITY, TaskDesc(max_concurrency=8, max_attempts=3))

    tid = tq.submit(AgentType.VULNERABILITY, "vulnerability", {"path": "..."})
    ready = tq.poll()          # up to 8 tasks at a time
    tq.complete(tid)           # success
    tq.fail(tid)               # auto-retry with backoff
"""

from __future__ import annotations

import heapq
import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Any

from agies.engine.v2.task_queue.models import AgentType, Task, TaskDesc, TaskStatus

logger = logging.getLogger(__name__)


class TaskQueue:
    """Thread-safe priority heap task queue with per-type concurrency control."""

    def __init__(self) -> None:
        self._queue: list[Task] = []
        self._running: dict[int, Task] = {}
        self._counts: dict[AgentType, int] = defaultdict(int)
        self._desc: dict[AgentType, TaskDesc] = {}
        self._next_id: int = 0
        self._lock = Lock()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, agent_type: AgentType, desc: TaskDesc) -> None:
        """Register an agent type with its resource profile."""
        self._desc[agent_type] = desc

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def submit(
        self,
        agent_type: AgentType,
        agent_name: str,
        params: dict[str, Any],
        priority: float = 0.5,
        timeout: float = 0.0,
    ) -> int:
        """Submit a task and return its ID.

        If *timeout* is 0 (or omitted), the default from the TaskDesc
        for this agent_type is used.
        """
        desc = self._desc.get(agent_type)
        with self._lock:
            tid = self._next_id
            self._next_id += 1
            task = Task(
                priority=max(0.0, min(1.0, priority)),
                submitted_at=time.monotonic(),
                task_id=tid,
                agent_type=agent_type,
                agent_name=agent_name,
                params=params,
                timeout=timeout or (desc.timeout if desc else 300.0),
            )
            heapq.heappush(self._queue, task)
            return tid

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    def poll(self) -> list[Task]:
        """Pop all tasks that can start now respecting concurrency limits.

        Tasks that would exceed their type's ``max_concurrency`` are left
        in the heap for the next poll.

        Backoff delay (``submitted_at`` in the future) is enforced: tasks
        whose ``submitted_at`` has not yet arrived are left in the heap.
        """
        now = time.monotonic()
        ready: list[Task] = []
        with self._lock:
            remaining: list[Task] = []
            while self._queue:
                task = heapq.heappop(self._queue)
                if task.status != TaskStatus.SUBMITTED:
                    continue
                # Backoff delay: don't poll before submitted_at
                if task.submitted_at > now:
                    remaining.append(task)
                    continue
                desc = self._desc.get(task.agent_type)
                limit = desc.max_concurrency if desc else 1
                if self._counts[task.agent_type] >= limit:
                    remaining.append(task)
                    continue
                task.status = TaskStatus.RUNNING
                task.started_at = now
                self._running[task.task_id] = task
                self._counts[task.agent_type] += 1
                ready.append(task)
            for t in remaining:
                heapq.heappush(self._queue, t)
        return ready

    # ------------------------------------------------------------------
    # Completion
    # ------------------------------------------------------------------

    def complete(self, task_id: int) -> None:
        """Mark a task as successfully done."""
        with self._lock:
            task = self._running.pop(task_id, None)
            if task:
                task.status = TaskStatus.DONE
                self._counts[task.agent_type] -= 1
                logger.debug("Task %d completed.", task_id)

    # ------------------------------------------------------------------
    # Failure + retry
    # ------------------------------------------------------------------

    def fail(self, task_id: int) -> bool:
        """Mark a task as failed.  Returns True if it will be retried."""
        with self._lock:
            task = self._running.pop(task_id, None)
            if not task:
                return False
            task.failure_count += 1
            desc = self._desc.get(task.agent_type)
            max_attempts = desc.max_attempts if desc else 3
            if task.failure_count >= max_attempts:
                task.status = TaskStatus.FAILED
                self._counts[task.agent_type] -= 1
                logger.warning(
                    "Task %d (%s) failed after %d attempts.",
                    task_id,
                    task.agent_name,
                    task.failure_count,
                )
                return False

            # Exponential backoff: re-queue after delay
            delay_base = desc.retry_delay_base if desc else 2.0
            delay = delay_base ** (task.failure_count - 1)  # 1st retry: 1s, 2nd: 2s
            task.status = TaskStatus.SUBMITTED
            task.started_at = 0.0
            # Push into the future so poll() won't grab it immediately
            task.submitted_at = time.monotonic() + delay
            heapq.heappush(self._queue, task)
            self._counts[task.agent_type] -= 1
            logger.info(
                "Task %d (%s) failed, retry %d/%d in %.1fs.",
                task_id,
                task.agent_name,
                task.failure_count,
                max_attempts,
                delay,
            )
            return True

    # ------------------------------------------------------------------
    # Cancellation
    # ------------------------------------------------------------------

    def cancel(self, task_id: int) -> None:
        """Cancel a running task."""
        with self._lock:
            task = self._running.pop(task_id, None)
            if task:
                task.status = TaskStatus.CANCELLED
                self._counts[task.agent_type] -= 1

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._queue)

    @property
    def running(self) -> int:
        with self._lock:
            return len(self._running)

    def idle(self) -> bool:
        """Return True when no tasks are queued or running."""
        with self._lock:
            return not self._queue and not self._running
