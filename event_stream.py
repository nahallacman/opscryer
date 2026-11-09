# SPDX-License-Identifier: Apache-2.0
"""Dual-Mode Real-Time Telemetry & Graph Streaming Engine (Piece M7).

Implements:
1. Thread-safe monotonic sequence counter (seq_id) ring buffer.
2. Compact Delta-Snapshot Engine with lifecycle state compaction (GET /api/v1/graph/delta).
3. Pure-stdlib Server-Sent Events (SSE) streaming engine with replay and topic filtering.

Zero external dependencies (pure Python 3.11+ stdlib only).
"""

from __future__ import annotations

from collections import deque
import copy
import json
import logging
import threading
import time
from typing import Any, Generator

logger = logging.getLogger("opscryer.event_stream")

PERMITTED_TOPICS = frozenset({"graph", "jev", "security", "actions", "system"})
DEFAULT_RING_BUFFER_CAPACITY = 1000


class EventRingBuffer:
    """Thread-safe monotonic sequence-indexed circular event buffer."""

    def __init__(self, capacity: int = DEFAULT_RING_BUFFER_CAPACITY) -> None:
        if capacity < 1:
            raise ValueError(f"Ring buffer capacity must be >= 1, got {capacity}")
        self._capacity: int = capacity
        self._lock: threading.Lock = threading.Lock()
        self._not_empty: threading.Condition = threading.Condition(self._lock)
        self._buffer: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._latest_seq: int = 0
        self._total_published: int = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def latest_seq(self) -> int:
        with self._lock:
            return self._latest_seq

    @property
    def oldest_seq(self) -> int:
        with self._lock:
            if not self._buffer:
                return 0
            return self._latest_seq - len(self._buffer) + 1

    def append(self, topic: str, event_type: str, data: dict[str, Any] | None = None) -> int:
        """Publish a new event to the ring buffer with monotonic seq_id."""
        if not isinstance(topic, str) or not topic.strip():
            raise ValueError("topic must be a non-empty string")
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event_type must be a non-empty string")

        topic_clean = topic.strip().lower()
        now = time.time()
        payload = copy.deepcopy(data) if data is not None else {}

        with self._lock:
            self._latest_seq += 1
            seq_id = self._latest_seq
            self._total_published += 1

            event: dict[str, Any] = {
                "seq_id": seq_id,
                "topic": topic_clean,
                "event_type": event_type.strip(),
                "timestamp": now,
                "data": payload,
            }
            self._buffer.append(event)
            self._not_empty.notify_all()
            return seq_id

    def get_events_since(
        self,
        since_seq: int,
        topics: list[str] | set[str] | None = None,
        max_events: int | None = None,
        inclusive: bool = False,
    ) -> tuple[list[dict[str, Any]], bool, int, int]:
        """Retrieve events since sequence ID.

        Returns:
            (events, full_resync_required, oldest_seq, latest_seq)
        """
        if not isinstance(since_seq, int) or since_seq < 0:
            raise ValueError("since_seq must be an integer >= 0")

        topic_filter = {t.lower() for t in topics} if topics else None

        with self._lock:
            latest = self._latest_seq
            count = len(self._buffer)
            oldest = (latest - count + 1) if count > 0 else 0

            # Condition A: Client has no baseline (non-inclusive query)
            if since_seq == 0 and not inclusive:
                return [], True, oldest, latest

            # Condition B: Client is ahead of server (restart / desync)
            if since_seq > latest:
                return [], True, oldest, latest

            # Condition C: Eviction occurred (buffer has wrapped past since_seq)
            # If inclusive=False, client needs events starting at since_seq + 1.
            # If (since_seq + 1) < oldest, the start of client's delta is missing.
            min_needed = since_seq if inclusive else (since_seq + 1)
            if count > 0 and min_needed < oldest and not (since_seq == 0 and inclusive):
                return [], True, oldest, latest

            # Condition D: Client is completely up to date
            if since_seq == latest and not inclusive:
                return [], False, oldest, latest

            # Extract matching events from contiguous buffer
            results: list[dict[str, Any]] = []
            for ev in self._buffer:
                sid = ev["seq_id"]
                if inclusive:
                    if sid < since_seq:
                        continue
                else:
                    if sid <= since_seq:
                        continue

                if topic_filter and ev["topic"] not in topic_filter:
                    continue

                results.append(copy.deepcopy(ev))
                if max_events is not None and len(results) >= max_events:
                    break

            return results, False, oldest, latest

    def clear(self) -> None:
        """Reset ring buffer state (primarily for test fixture cleanup)."""
        with self._lock:
            self._buffer.clear()
            self._latest_seq = 0
            self._total_published = 0
            self._not_empty.notify_all()

    def stats(self) -> dict[str, Any]:
        """Return operational telemetry metrics for observability."""
        with self._lock:
            count = len(self._buffer)
            oldest = (self._latest_seq - count + 1) if count > 0 else 0
            return {
                "capacity": self._capacity,
                "current_size": count,
                "oldest_seq": oldest,
                "latest_seq": self._latest_seq,
                "total_published": self._total_published,
            }


# Module singleton instance
_DEFAULT_BUFFER = EventRingBuffer()


def publish_event(topic: str, event_type: str, data: dict[str, Any] | None = None) -> int:
    """Module-level thread-safe publisher."""
    return _DEFAULT_BUFFER.append(topic, event_type, data)


def get_delta(since_seq: int = 0) -> dict[str, Any]:
    """Calculate compact graph delta snapshot since specified sequence number."""
    if not isinstance(since_seq, int) or since_seq < 0:
        raise ValueError(f"since_seq must be an integer >= 0, got {since_seq}")

    events, full_resync, oldest_seq, latest_seq = _DEFAULT_BUFFER.get_events_since(
        since_seq=since_seq, topics={"graph"}
    )

    if full_resync:
        reason = (
            "Baseline sequence 0 requires initial full catalog sync"
            if since_seq == 0
            else f"Sequence {since_seq} evicted from ring buffer (retained range: {oldest_seq}..{latest_seq})"
            if since_seq < oldest_seq
            else f"Sequence {since_seq} is ahead of server latest sequence {latest_seq}"
        )
        return {
            "schema_version": "1.0-graph-delta-snapshot",
            "since_seq": since_seq,
            "latest_seq": latest_seq,
            "oldest_retained_seq": oldest_seq,
            "full_resync_required": True,
            "reason": reason,
            "resync_url": "/api/v1/graph/catalog",
            "added_nodes": [],
            "updated_nodes": [],
            "removed_nodes": [],
            "events": [],
            "event_count": 0,
        }

    # State compaction reducer
    node_pool: dict[str, dict[str, Any]] = {}
    node_lifecycle: dict[str, str] = {}  # "ADDED" or "UPDATED"
    removed_nodes: set[str] = set()

    for ev in events:
        etype = ev["event_type"]
        edata = ev.get("data", {})

        if etype == "node_added":
            node = edata.get("node")
            if isinstance(node, dict) and "id" in node:
                nid = str(node["id"])
                node_pool[nid] = copy.deepcopy(node)
                node_lifecycle[nid] = "ADDED"
                removed_nodes.discard(nid)

        elif etype == "node_updated":
            node = edata.get("node")
            if isinstance(node, dict) and "id" in node:
                nid = str(node["id"])
                node_pool[nid] = copy.deepcopy(node)
                # If it was already marked ADDED in this window, keep ADDED
                if node_lifecycle.get(nid) != "ADDED":
                    node_lifecycle[nid] = "UPDATED"
                removed_nodes.discard(nid)

        elif etype == "node_removed":
            nid = str(edata.get("node_id") or (edata.get("node", {}).get("id") if isinstance(edata.get("node"), dict) else ""))
            if nid:
                if node_lifecycle.get(nid) == "ADDED":
                    # Created and destroyed within the window: vanish completely
                    node_pool.pop(nid, None)
                    node_lifecycle.pop(nid, None)
                else:
                    node_pool.pop(nid, None)
                    node_lifecycle.pop(nid, None)
                    removed_nodes.add(nid)

    added = [node_pool[nid] for nid, st in node_lifecycle.items() if st == "ADDED"]
    updated = [node_pool[nid] for nid, st in node_lifecycle.items() if st == "UPDATED"]
    removed = sorted(removed_nodes)

    return {
        "schema_version": "1.0-graph-delta-snapshot",
        "since_seq": since_seq,
        "latest_seq": latest_seq,
        "oldest_retained_seq": oldest_seq,
        "full_resync_required": False,
        "added_nodes": added,
        "updated_nodes": updated,
        "removed_nodes": removed,
        "events": events,
        "event_count": len(events),
    }


def format_sse_event(event: dict[str, Any]) -> str:
    """Format an event dictionary as a standard W3C Server-Sent Event."""
    seq_id = event.get("seq_id", "")
    event_type = event.get("event_type", "message")
    payload_str = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
    return f"id: {seq_id}\nevent: {event_type}\ndata: {payload_str}\n\n"


def format_sse_comment(comment: str) -> str:
    """Format an SSE comment (e.g. heartbeat/ping)."""
    return f": {comment}\n\n"


def stream_events_generator(
    since_seq: int | None = None,
    topics: list[str] | set[str] | None = None,
    max_events: int | None = None,
    timeout: float = 0.5,
) -> Generator[str, None, None]:
    """Yield formatted Server-Sent Events with replay, filtering, and bounded delivery."""
    events_yielded = 0

    # 1. Bounded Delivery Mode (tests, CLI, one-shot consumers)
    if max_events is not None:
        start_seq = since_seq if (since_seq is not None and since_seq > 0) else 0
        buffered, resync, oldest, latest = _DEFAULT_BUFFER.get_events_since(
            start_seq, topics=topics, max_events=max_events, inclusive=(start_seq == 0)
        )
        if resync and start_seq > 0:
            resync_ev = {
                "seq_id": latest,
                "topic": "system",
                "event_type": "resync_required",
                "timestamp": time.time(),
                "data": {
                    "reason": "buffer_evicted" if start_seq < oldest else "future_sequence",
                    "oldest_seq": oldest,
                    "latest_seq": latest,
                },
            }
            yield format_sse_event(resync_ev)
            return

        for ev in buffered:
            yield format_sse_event(ev)
            events_yielded += 1
            if events_yielded >= max_events:
                return
        return

    # 2. Unbounded Live Streaming Phase
    current_seq = since_seq
    if current_seq is not None and current_seq > 0:
        buffered, resync, oldest, latest = _DEFAULT_BUFFER.get_events_since(
            current_seq, topics=topics
        )
        if resync:
            resync_ev = {
                "seq_id": latest,
                "topic": "system",
                "event_type": "resync_required",
                "timestamp": time.time(),
                "data": {
                    "reason": "buffer_evicted" if current_seq < oldest else "future_sequence",
                    "oldest_seq": oldest,
                    "latest_seq": latest,
                },
            }
            yield format_sse_event(resync_ev)
            current_seq = latest
        else:
            for ev in buffered:
                yield format_sse_event(ev)
                current_seq = ev["seq_id"]
            if current_seq is None or current_seq < latest:
                current_seq = latest
    else:
        current_seq = _DEFAULT_BUFFER.latest_seq

    while True:
        with _DEFAULT_BUFFER._lock:
            if _DEFAULT_BUFFER._latest_seq == current_seq:
                _DEFAULT_BUFFER._not_empty.wait(timeout=timeout)

        new_events, resync, oldest, new_latest = _DEFAULT_BUFFER.get_events_since(
            current_seq if current_seq is not None else 0,
            topics=topics,
            inclusive=(current_seq == 0),
        )
        if resync and current_seq is not None and current_seq > 0:
            resync_ev = {
                "seq_id": new_latest,
                "topic": "system",
                "event_type": "resync_required",
                "timestamp": time.time(),
                "data": {
                    "reason": "buffer_evicted" if current_seq < oldest else "future_sequence",
                    "oldest_seq": oldest,
                    "latest_seq": new_latest,
                },
            }
            yield format_sse_event(resync_ev)
            current_seq = new_latest
        elif new_events:
            for ev in new_events:
                yield format_sse_event(ev)
                current_seq = ev["seq_id"]
            if current_seq is None or current_seq < new_latest:
                current_seq = new_latest
        else:
            current_seq = new_latest
            yield format_sse_comment("ping")


def reset_event_buffer() -> None:
    """Reset the module default event ring buffer."""
    _DEFAULT_BUFFER.clear()
