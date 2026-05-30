"""Task queue data structures — Task, TaskDesc, AgentType, TaskStatus.

Maps to Xint ``crs/common/workdb.py`` — WorkDesc / WorkItem equivalents.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Any


class AgentType(IntEnum):
    """Every agent type that can be dispatched via the TaskQueue."""

    MAPPING = auto()
    SOURCER = auto()
    BULK_ANALYSIS = auto()
    ATTACK_SURFACE = auto()
    DATAFLOW = auto()
    VULNERABILITY = auto()
    VERIFICATION = auto()
    VERIFY = auto()
    REPORT = auto()


class TaskStatus(IntEnum):
    SUBMITTED = auto()
    RUNNING = auto()
    DONE = auto()
    FAILED = auto()
    CANCELLED = auto()


@dataclass(order=True)
class Task:
    """A single schedulable unit of work.

    Sort order (for heapq): priority ASC → submitted_at ASC → task_id ASC.
    This means higher-priority tasks run first, and within the same priority,
    older tasks run first.
    """

    priority: float = 1.0
    """Lower values = higher priority.  Range [0.0, 1.0]."""

    submitted_at: float = 0.0
    """Monotonic timestamp — used as FCFS tiebreaker."""

    task_id: int = 0
    agent_type: AgentType = AgentType.MAPPING
    agent_name: str = ""
    params: dict[str, Any] = field(default_factory=dict, compare=False)
    status: TaskStatus = TaskStatus.SUBMITTED
    failure_count: int = 0
    timeout: float = 300.0
    """Max wall-clock seconds.  0 = no timeout."""
    started_at: float = 0.0


@dataclass
class TaskDesc:
    """Resource profile for one agent type — mirrors Xint's WorkDesc."""

    max_concurrency: int = 1
    """Max simultaneous running instances of this type."""
    max_attempts: int = 3
    """Retries before marking FAILED."""
    timeout: float = 300.0
    """Default timeout in seconds.  0 = no timeout."""
    retry_delay_base: float = 2.0
    """Exponential backoff base: delay = base ** failure_count."""
