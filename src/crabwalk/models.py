"""Core data types shared across crabwalk."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class NormalizedEvent:
    """A single Windows event, flattened into a channel-agnostic shape.

    ``data`` holds the merged EventData/UserData payload; System-section
    metadata lives in the dedicated fields.
    """

    timestamp: datetime
    channel: str
    provider: str
    event_id: int
    record_id: int
    computer: str
    data: dict[str, Any]
    source_file: str
    user_sid: str | None = None

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def to_json(self) -> str:
        payload = {
            "timestamp": self.timestamp.isoformat(),
            "channel": self.channel,
            "provider": self.provider,
            "event_id": self.event_id,
            "record_id": self.record_id,
            "computer": self.computer,
            "user_sid": self.user_sid,
            "data": self.data,
            "source_file": self.source_file,
        }
        return json.dumps(payload, ensure_ascii=False, default=str)
