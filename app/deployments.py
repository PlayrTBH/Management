"""In-memory tracking for virtual machine deployment activity."""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional, Sequence

from .ssh import CommandResult


LogStream = Literal["stdout", "stderr", "info", "error"]

_MAX_MESSAGES_PER_DEPLOYMENT = 2000


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class DeploymentLogEntry:
    """Represents a single log event for a VM deployment."""

    sequence: int
    timestamp: datetime
    stream: LogStream
    message: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp.isoformat(),
            "stream": self.stream,
            "message": self.message,
        }


@dataclass
class DeploymentRecord:
    """Captures deployment metadata and its associated log messages."""

    id: str
    user_id: int
    agent_id: int
    agent_name: str
    vm_name: str
    profile_id: str
    profile_name: str
    status: str
    created_at: datetime
    updated_at: datetime
    parameters: Dict[str, object] = field(default_factory=dict)
    command: Optional[Sequence[str]] = None
    exit_status: Optional[int] = None
    error: Optional[str] = None
    messages: List[DeploymentLogEntry] = field(default_factory=list)
    _next_sequence: int = 1
    _stream_buffers: Dict[str, str] = field(default_factory=dict)
    _max_messages: int = _MAX_MESSAGES_PER_DEPLOYMENT

    def to_summary_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "vm_name": self.vm_name,
            "profile_id": self.profile_id,
            "profile_name": self.profile_name,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "parameters": dict(self.parameters) if self.parameters else {},
            "command": list(self.command) if self.command else None,
            "exit_status": self.exit_status,
            "error": self.error,
        }

    def to_detail_dict(self, *, after: Optional[int] = None) -> Dict[str, object]:
        summary = self.to_summary_dict()
        if after is None:
            relevant = self.messages
        else:
            relevant = [entry for entry in self.messages if entry.sequence > after]
        summary["messages"] = [entry.to_dict() for entry in relevant]
        summary["next_sequence"] = self._next_sequence
        return summary

    def add_message(self, stream: LogStream, message: str) -> Optional[DeploymentLogEntry]:
        text = (message or "").strip("\r\n")
        if not text:
            return None
        return self._append_message(stream, text)

    def add_stream_chunk(self, stream: LogStream, chunk: str) -> None:
        if not chunk:
            return

        buffer = self._stream_buffers.get(stream, "") + chunk.replace("\r\n", "\n").replace("\r", "\n")
        lines = buffer.split("\n")

        if buffer.endswith("\n"):
            self._stream_buffers[stream] = ""
        else:
            self._stream_buffers[stream] = lines.pop() if lines else ""

        for line in lines:
            cleaned = line.rstrip()
            if cleaned:
                self._append_message(stream, cleaned)

    def flush_buffers(self) -> None:
        for stream, pending in list(self._stream_buffers.items()):
            if pending:
                self._append_message(stream, pending.rstrip())
            self._stream_buffers[stream] = ""

    def _append_message(self, stream: LogStream, message: str) -> DeploymentLogEntry:
        entry = DeploymentLogEntry(
            sequence=self._next_sequence,
            timestamp=_utcnow(),
            stream=stream,
            message=message,
        )
        self._next_sequence += 1
        self.messages.append(entry)
        if len(self.messages) > self._max_messages:
            excess = len(self.messages) - self._max_messages
            if excess > 0:
                self.messages = self.messages[excess:]
        self.updated_at = entry.timestamp
        return entry


class DeploymentLogManager:
    """Stores deployment activity for presentation in the management UI."""

    def __init__(self, *, max_records: int = 50) -> None:
        self._records: Dict[str, DeploymentRecord] = {}
        self._max_records = max_records
        self._lock = threading.RLock()

    def create(
        self,
        *,
        user_id: int,
        agent_id: int,
        agent_name: str,
        vm_name: str,
        profile_id: str,
        profile_name: str,
        parameters: Optional[Dict[str, object]] = None,
    ) -> DeploymentRecord:
        record_id = uuid.uuid4().hex
        now = _utcnow()
        record = DeploymentRecord(
            id=record_id,
            user_id=user_id,
            agent_id=agent_id,
            agent_name=agent_name,
            vm_name=vm_name,
            profile_id=profile_id,
            profile_name=profile_name,
            status="pending",
            created_at=now,
            updated_at=now,
            parameters=dict(parameters or {}),
        )
        with self._lock:
            self._records[record_id] = record
            self._prune_locked()
        return record

    def append_message(self, deployment_id: str, stream: LogStream, message: str) -> None:
        with self._lock:
            record = self._records.get(deployment_id)
            if record is None:
                return
            record.add_message(stream, message)

    def append_stream(self, deployment_id: str, stream: LogStream, chunk: str) -> None:
        with self._lock:
            record = self._records.get(deployment_id)
            if record is None:
                return
            record.add_stream_chunk(stream, chunk)

    def mark_running(self, deployment_id: str) -> None:
        with self._lock:
            record = self._records.get(deployment_id)
            if record is None:
                return
            record.status = "running"
            record.updated_at = _utcnow()

    def mark_success(self, deployment_id: str, result: CommandResult) -> None:
        with self._lock:
            record = self._records.get(deployment_id)
            if record is None:
                return
            record.flush_buffers()
            record.status = "succeeded"
            record.exit_status = result.exit_status
            record.command = list(result.command)
            record.updated_at = _utcnow()
            record.add_message(
                "info",
                f"Deployment completed successfully (exit status {result.exit_status}).",
            )

    def mark_failed(
        self,
        deployment_id: str,
        message: str,
        result: Optional[CommandResult] = None,
    ) -> None:
        with self._lock:
            record = self._records.get(deployment_id)
            if record is None:
                return
            record.flush_buffers()
            record.status = "failed"
            record.error = message
            if result is not None:
                record.exit_status = result.exit_status
                record.command = list(result.command)
            record.updated_at = _utcnow()
            record.add_message("error", message)

    def list_for_user(self, user_id: int) -> List[Dict[str, object]]:
        with self._lock:
            records = [record for record in self._records.values() if record.user_id == user_id]
            records.sort(key=lambda item: item.created_at, reverse=True)
            return [record.to_summary_dict() for record in records]

    def get_for_user(
        self,
        user_id: int,
        deployment_id: str,
        *,
        after: Optional[int] = None,
    ) -> Optional[Dict[str, object]]:
        with self._lock:
            record = self._records.get(deployment_id)
            if record is None or record.user_id != user_id:
                return None
            return record.to_detail_dict(after=after)

    def _prune_locked(self) -> None:
        if len(self._records) <= self._max_records:
            return

        finished = [
            record
            for record in self._records.values()
            if record.status in {"succeeded", "failed"}
        ]
        finished.sort(key=lambda record: record.updated_at)

        while len(self._records) > self._max_records and finished:
            record = finished.pop(0)
            self._records.pop(record.id, None)


__all__ = ["DeploymentLogManager", "DeploymentLogEntry", "DeploymentRecord"]
