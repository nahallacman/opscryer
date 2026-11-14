# SPDX-License-Identifier: Apache-2.0
"""Comprehensive Unit Test Suite for Event Streaming and Ring Buffer Engine (Milestone 7).

Covers:
1. EventRingBuffer capacity bounds, thread-safe monotonic sequence allocation, and eviction detection.
2. Delta-Snapshot Engine state compaction, ghost node elimination, and baseline void resync.
3. Server-Sent Events (SSE) framing, replay from Last-Event-ID / since_seq, topic filtering, and bounded execution.
4. Fail-safe event publishing integration across opscryer_backend, action_cards, http_transport, and jev_client.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import threading
import time
import unittest

_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from event_stream import (
    DEFAULT_RING_BUFFER_CAPACITY,
    PERMITTED_TOPICS,
    EventRingBuffer,
    format_sse_comment,
    format_sse_event,
    get_delta,
    publish_event,
    reset_event_buffer,
    stream_events_generator,
)


class TestEventRingBuffer(unittest.TestCase):
    """Test unit behavior of the EventRingBuffer circular storage engine."""

    def setUp(self) -> None:
        reset_event_buffer()

    def tearDown(self) -> None:
        reset_event_buffer()

    def test_init_and_properties(self) -> None:
        buf = EventRingBuffer(capacity=50)
        self.assertEqual(buf.capacity, 50)
        self.assertEqual(buf.latest_seq, 0)
        self.assertEqual(buf.oldest_seq, 0)
        stats = buf.stats()
        self.assertEqual(stats["capacity"], 50)
        self.assertEqual(stats["current_size"], 0)
        self.assertEqual(stats["latest_seq"], 0)
        self.assertEqual(stats["oldest_seq"], 0)
        self.assertEqual(stats["total_published"], 0)

    def test_invalid_capacity(self) -> None:
        with self.assertRaises(ValueError):
            EventRingBuffer(capacity=0)
        with self.assertRaises(ValueError):
            EventRingBuffer(capacity=-10)

    def test_append_single_event(self) -> None:
        buf = EventRingBuffer(capacity=100)
        seq = buf.append("graph", "node_added", {"id": "node-1", "label": "Node 1"})
        self.assertEqual(seq, 1)
        self.assertEqual(buf.latest_seq, 1)
        self.assertEqual(buf.oldest_seq, 1)

        events, resync, oldest, latest = buf.get_events_since(0, inclusive=True)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["seq_id"], 1)
        self.assertEqual(events[0]["topic"], "graph")
        self.assertEqual(events[0]["event_type"], "node_added")
        self.assertEqual(events[0]["data"]["id"], "node-1")
        self.assertIsInstance(events[0]["timestamp"], float)

    def test_append_validation(self) -> None:
        buf = EventRingBuffer(capacity=10)
        with self.assertRaises(ValueError):
            buf.append("", "node_added")
        with self.assertRaises(ValueError):
            buf.append("graph", "")
        with self.assertRaises(ValueError):
            buf.append(123, "node_added")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            buf.append("graph", None)  # type: ignore[arg-type]

    def test_clear_buffer(self) -> None:
        buf = EventRingBuffer(capacity=10)
        buf.append("graph", "node_added", {"id": "1"})
        buf.append("graph", "node_added", {"id": "2"})
        self.assertEqual(buf.latest_seq, 2)
        buf.clear()
        self.assertEqual(buf.latest_seq, 0)
        self.assertEqual(buf.oldest_seq, 0)
        self.assertEqual(buf.stats()["current_size"], 0)

    def test_concurrent_publishing_monotonicity(self) -> None:
        """Verify that concurrent publishing across multiple threads maintains strictly monotonic seq_ids."""
        buf = EventRingBuffer(capacity=2000)
        num_threads = 10
        events_per_thread = 50
        barrier = threading.Barrier(num_threads)
        published_seqs: list[int] = []
        lock = threading.Lock()

        def worker(thread_idx: int) -> None:
            barrier.wait()
            for i in range(events_per_thread):
                seq = buf.append("graph", "worker_event", {"thread": thread_idx, "idx": i})
                with lock:
                    published_seqs.append(seq)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        total_expected = num_threads * events_per_thread
        self.assertEqual(len(published_seqs), total_expected)
        self.assertEqual(sorted(published_seqs), list(range(1, total_expected + 1)))
        self.assertEqual(buf.latest_seq, total_expected)
        self.assertEqual(buf.oldest_seq, 1)

    def test_eviction_and_boundary_checks(self) -> None:
        """Verify capacity-bounded eviction and exact boundary predicate evaluations."""
        buf = EventRingBuffer(capacity=10)
        for i in range(1, 26):
            buf.append("graph", "evt", {"val": i})

        # Buffer holds 10 events: seq 16 through 25
        self.assertEqual(buf.latest_seq, 25)
        self.assertEqual(buf.oldest_seq, 16)
        self.assertEqual(buf.stats()["current_size"], 10)

        # 1. Baseline void (since_seq == 0) -> full resync required
        events, resync, oldest, latest = buf.get_events_since(0)
        self.assertTrue(resync)
        self.assertEqual(events, [])
        self.assertEqual(oldest, 16)
        self.assertEqual(latest, 25)

        # 2. Evicted sequence (since_seq < oldest - 1, e.g. 10 < 15)
        events, resync, oldest, latest = buf.get_events_since(10)
        self.assertTrue(resync)
        self.assertEqual(events, [])

        # 3. Evicted sequence boundary (since_seq == 14 < 15)
        events, resync, oldest, latest = buf.get_events_since(14)
        self.assertTrue(resync)

        # 4. Exact boundary match (since_seq == 15 == oldest - 1)
        # Client has 15, needs 16..25 (all 10 retained events)
        events, resync, oldest, latest = buf.get_events_since(15)
        self.assertFalse(resync)
        self.assertEqual(len(events), 10)
        self.assertEqual([e["seq_id"] for e in events], list(range(16, 26)))

        # 5. Normal incremental delta (since_seq == 20)
        events, resync, oldest, latest = buf.get_events_since(20)
        self.assertFalse(resync)
        self.assertEqual(len(events), 5)
        self.assertEqual([e["seq_id"] for e in events], [21, 22, 23, 24, 25])

        # 6. Up-to-date client (since_seq == 25)
        events, resync, oldest, latest = buf.get_events_since(25)
        self.assertFalse(resync)
        self.assertEqual(events, [])

        # 7. Future sequence (since_seq > latest, e.g. 30 > 25)
        events, resync, oldest, latest = buf.get_events_since(30)
        self.assertTrue(resync)

    def test_topic_filtering(self) -> None:
        buf = EventRingBuffer(capacity=50)
        buf.append("graph", "node_added", {"id": "1"})
        buf.append("security", "alert", {"sev": "high"})
        buf.append("jev", "ticket", {"title": "issue"})
        buf.append("graph", "node_removed", {"id": "1"})

        events, resync, _, _ = buf.get_events_since(0, topics=["graph"], inclusive=True)
        self.assertEqual(len(events), 2)
        self.assertTrue(all(e["topic"] == "graph" for e in events))

        events, _, _, _ = buf.get_events_since(0, topics=["security", "jev"], inclusive=True)
        self.assertEqual(len(events), 2)
        self.assertEqual({e["topic"] for e in events}, {"security", "jev"})

    def test_max_events_limit(self) -> None:
        buf = EventRingBuffer(capacity=50)
        for i in range(1, 11):
            buf.append("graph", "evt", {"i": i})

        events, _, _, _ = buf.get_events_since(0, max_events=3, inclusive=True)
        self.assertEqual(len(events), 3)
        self.assertEqual([e["seq_id"] for e in events], [1, 2, 3])


class TestGetDelta(unittest.TestCase):
    """Test Delta-Snapshot Engine state compaction and ghost node elimination."""

    def setUp(self) -> None:
        reset_event_buffer()

    def tearDown(self) -> None:
        reset_event_buffer()

    def test_baseline_void_requires_full_resync(self) -> None:
        publish_event("graph", "node_added", {"node": {"id": "n1", "label": "Node 1"}})
        delta = get_delta(0)
        self.assertTrue(delta["full_resync_required"])
        self.assertEqual(delta["resync_url"], "/api/v1/graph/catalog")
        self.assertEqual(delta["added_nodes"], [])
        self.assertEqual(delta["updated_nodes"], [])
        self.assertEqual(delta["removed_nodes"], [])

    def test_future_seq_requires_full_resync(self) -> None:
        publish_event("graph", "node_added", {"node": {"id": "n1"}})
        delta = get_delta(9999)
        self.assertTrue(delta["full_resync_required"])
        self.assertIn("ahead of server", delta["reason"])

    def test_up_to_date_delta(self) -> None:
        seq = publish_event("graph", "node_added", {"node": {"id": "n1", "label": "N1"}})
        delta = get_delta(seq)
        self.assertFalse(delta["full_resync_required"])
        self.assertEqual(delta["added_nodes"], [])
        self.assertEqual(delta["updated_nodes"], [])
        self.assertEqual(delta["removed_nodes"], [])
        self.assertEqual(delta["events"], [])
        self.assertEqual(delta["latest_seq"], seq)

    def test_state_compaction_folding(self) -> None:
        """Verify lifecycle folding:
        1. node-1: added then updated -> ADDED with final payload.
        2. node-2: updated -> UPDATED.
        3. node-3: added then removed -> EPHEMERAL (vanishes).
        4. node-4: updated then removed -> REMOVED.
        5. non-graph events -> excluded from node folding.
        """
        # Baseline point
        s0 = publish_event("graph", "node_added", {"node": {"id": "baseline-node", "label": "Base"}})

        # Mutations in delta window
        publish_event("graph", "node_added", {"node": {"id": "node-1", "label": "Node 1 v1"}})
        publish_event("graph", "node_updated", {"node": {"id": "node-1", "label": "Node 1 v2", "version": 2}})
        publish_event("graph", "node_updated", {"node": {"id": "node-2", "label": "Node 2 v1"}})
        publish_event("graph", "node_added", {"node": {"id": "node-3", "label": "Node 3 Ephemeral"}})
        publish_event("graph", "node_removed", {"node_id": "node-3"})
        publish_event("graph", "node_updated", {"node": {"id": "node-4", "label": "Node 4 Pre-remove"}})
        publish_event("graph", "node_removed", {"node_id": "node-4"})
        publish_event("security", "alert", {"title": "Ignored in graph node partition"})

        delta = get_delta(since_seq=s0)
        self.assertFalse(delta["full_resync_required"])

        # 1. node-1 should be in added_nodes with final version
        added_ids = {n["id"] for n in delta["added_nodes"]}
        self.assertEqual(added_ids, {"node-1"})
        node_1 = next(n for n in delta["added_nodes"] if n["id"] == "node-1")
        self.assertEqual(node_1["label"], "Node 1 v2")
        self.assertEqual(node_1["version"], 2)

        # 2. node-2 should be in updated_nodes
        updated_ids = {n["id"] for n in delta["updated_nodes"]}
        self.assertEqual(updated_ids, {"node-2"})
        node_2 = next(n for n in delta["updated_nodes"] if n["id"] == "node-2")
        self.assertEqual(node_2["label"], "Node 2 v1")

        # 3. node-3 was created and removed in same window: must vanish completely
        self.assertNotIn("node-3", added_ids)
        self.assertNotIn("node-3", updated_ids)
        self.assertNotIn("node-3", delta["removed_nodes"])

        # 4. node-4 was updated and removed: must be in removed_nodes only
        self.assertNotIn("node-4", added_ids)
        self.assertNotIn("node-4", updated_ids)
        self.assertIn("node-4", delta["removed_nodes"])


class TestSSEFormatting(unittest.TestCase):
    """Test W3C Server-Sent Event string formatting."""

    def test_format_sse_event(self) -> None:
        event = {
            "seq_id": 42,
            "topic": "security",
            "event_type": "circuit_breaker_transition",
            "timestamp": 1700000000.0,
            "data": {"name": "ollama", "state": "open"},
        }
        wire = format_sse_event(event)
        lines = wire.split("\n")
        self.assertEqual(lines[0], "id: 42")
        self.assertEqual(lines[1], "event: circuit_breaker_transition")
        self.assertTrue(lines[2].startswith("data: {"))
        parsed_data = json.loads(lines[2][len("data: "):])
        self.assertEqual(parsed_data["seq_id"], 42)
        self.assertEqual(parsed_data["data"]["name"], "ollama")
        self.assertEqual(lines[3], "")
        self.assertEqual(lines[4], "")

    def test_format_sse_comment(self) -> None:
        wire = format_sse_comment("ping")
        self.assertEqual(wire, ": ping\n\n")


class TestStreamEventsGenerator(unittest.TestCase):
    """Test Server-Sent Events generator semantics."""

    def setUp(self) -> None:
        reset_event_buffer()

    def tearDown(self) -> None:
        reset_event_buffer()

    def test_bounded_delivery_empty_buffer(self) -> None:
        """Bounded delivery (?max_events=K) terminates cleanly on empty buffer without blocking."""
        gen = stream_events_generator(max_events=5)
        chunks = list(gen)
        self.assertEqual(chunks, [])

    def test_bounded_delivery_available_events(self) -> None:
        publish_event("graph", "e1", {"idx": 1})
        publish_event("graph", "e2", {"idx": 2})
        publish_event("graph", "e3", {"idx": 3})

        # Request max_events=2 from beginning
        chunks = list(stream_events_generator(since_seq=0, max_events=2))
        self.assertEqual(len(chunks), 2)
        self.assertIn("id: 1", chunks[0])
        self.assertIn("id: 2", chunks[1])

    def test_bounded_delivery_fewer_than_max(self) -> None:
        publish_event("graph", "e1", {"idx": 1})
        publish_event("graph", "e2", {"idx": 2})

        # Request max_events=10 when only 2 exist
        chunks = list(stream_events_generator(since_seq=0, max_events=10))
        self.assertEqual(len(chunks), 2)

    def test_historical_replay_with_since_seq(self) -> None:
        publish_event("graph", "e1")
        publish_event("graph", "e2")
        publish_event("graph", "e3")
        publish_event("graph", "e4")

        # Client has received up to 2; replays 3 and 4
        chunks = list(stream_events_generator(since_seq=2, max_events=10))
        self.assertEqual(len(chunks), 2)
        self.assertIn("id: 3", chunks[0])
        self.assertIn("id: 4", chunks[1])

    def test_topic_filtering(self) -> None:
        publish_event("graph", "g1")
        publish_event("security", "s1")
        publish_event("graph", "g2")
        publish_event("actions", "a1")

        chunks = list(stream_events_generator(since_seq=0, topics={"graph"}, max_events=10))
        self.assertEqual(len(chunks), 2)
        self.assertTrue(all("event: g" in c for c in chunks))

    def test_live_streaming_topic_filtering_throttling(self) -> None:
        """Regression Test: Live SSE stream with topic filtering must throttle cleanly.

        When non-matching topic events are published, the generator must advance its sequence
        and wait on the condition variable rather than entering an unthrottled spin loop yielding
        thousands of pings per second.
        """
        collected_chunks: list[str] = []
        stop_event = threading.Event()
        action_received = threading.Event()

        def stream_consumer() -> None:
            # Live streaming without max_events (unbounded)
            gen = stream_events_generator(topics={"actions"}, timeout=0.1)
            for chunk in gen:
                collected_chunks.append(chunk)
                if "event: action_staged" in chunk:
                    action_received.set()
                if stop_event.is_set():
                    break

        consumer_thread = threading.Thread(target=stream_consumer, daemon=True)
        consumer_thread.start()

        # Allow consumer thread to initialize and enter wait state
        time.sleep(0.02)

        try:
            # 1. Publish interleaved non-matching topic events ("graph", "jev")
            publish_event("graph", "node_added", {"id": "node-alpha"})
            publish_event("graph", "edge_added", {"src": "node-alpha", "dst": "node-beta"})
            publish_event("jev", "ticket_evaluated", {"ticket_id": "jev-999"})

            # Short delay allowing consumer to wake up, filter events, and re-enter wait
            time.sleep(0.04)

            # 2. Publish matching topic event ("actions")
            publish_event("actions", "action_staged", {"card_id": "card-42", "node": "nodegamma03"})

            # Wait for consumer to process the matching action event
            action_seen = action_received.wait(timeout=1.0)
            self.assertTrue(action_seen, "Consumer thread did not receive matching action event in time")

            # 3. Publish trailing non-matching topic event ("security")
            publish_event("security", "circuit_breaker_transition", {"state": "open"})
            time.sleep(0.04)

        finally:
            stop_event.set()
            consumer_thread.join(timeout=1.0)

        self.assertFalse(consumer_thread.is_alive(), "Consumer thread failed to terminate cleanly")

        # Invariant 1: Matching event delivered correctly
        action_chunks = [c for c in collected_chunks if "event: action_staged" in c]
        self.assertEqual(len(action_chunks), 1, "Expected exactly 1 action event")
        self.assertIn("card-42", action_chunks[0])

        # Invariant 2: Non-matching events strictly filtered out (zero leaks)
        for chunk in collected_chunks:
            self.assertNotIn("event: node_added", chunk)
            self.assertNotIn("event: edge_added", chunk)
            self.assertNotIn("event: ticket_evaluated", chunk)
            self.assertNotIn("event: circuit_breaker_transition", chunk)

        # Invariant 3: Clean throttling - ping count strictly bounded (< 5 pings)
        ping_chunks = [c for c in collected_chunks if ": ping" in c]
        self.assertLess(
            len(ping_chunks),
            5,
            f"Excessive ping flood detected ({len(ping_chunks)} pings yielded), indicating unthrottled spin-loop",
        )
        self.assertLess(
            len(collected_chunks),
            6,
            f"Total yielded chunks ({len(collected_chunks)}) exceeded throttle threshold",
        )

    def test_live_streaming_buffer_wraparound_eviction(self) -> None:
        """Regression Test: Live SSE stream must emit resync_required upon buffer wrap-around.

        When a live consumer lags behind ring buffer capacity during streaming, the generator
        must detect eviction, emit a 'resync_required' SSE event, advance sequence to latest,
        and cleanly resume streaming without entering an infinite spin loop or silently dropping events.
        """
        import event_stream

        # Use an isolated small-capacity buffer to trigger deterministic eviction
        test_buf = EventRingBuffer(capacity=10)
        old_buf = event_stream._DEFAULT_BUFFER
        event_stream._DEFAULT_BUFFER = test_buf

        collected_chunks: list[str] = []
        replay_done = threading.Event()
        resync_received = threading.Event()
        stop_event = threading.Event()

        try:
            # Seed 3 initial events
            s1 = test_buf.append("graph", "init_1", {"v": 1})
            s2 = test_buf.append("graph", "init_2", {"v": 2})
            s3 = test_buf.append("graph", "init_3", {"v": 3})

            def stream_consumer() -> None:
                # Live stream starting from s1
                gen = stream_events_generator(since_seq=s1, timeout=0.05)
                for chunk in gen:
                    collected_chunks.append(chunk)
                    if "event: init_3" in chunk:
                        replay_done.set()
                    if "resync_required" in chunk:
                        resync_received.set()
                    if stop_event.is_set():
                        break

            consumer_thread = threading.Thread(target=stream_consumer, daemon=True)
            consumer_thread.start()

            # Wait until initial replay completes and consumer enters live streaming wait loop
            replay_ok = replay_done.wait(timeout=1.0)
            self.assertTrue(replay_ok, "Initial replay did not complete in time")
            time.sleep(0.02)  # Ensure thread transitions into while True wait loop

            # Flood buffer with 25 events (sequences 4..28), exceeding capacity=10
            # Retained range becomes 19..28, evicting sequences 1..18
            for i in range(4, 29):
                test_buf.append("graph", f"flood_{i}", {"idx": i})

            # Wait for consumer to receive resync_required
            resync_ok = resync_received.wait(timeout=1.0)
            self.assertTrue(
                resync_ok,
                f"Lagging live SSE consumer never received resync_required event! Chunks: {len(collected_chunks)}",
            )

            # Publish a post-eviction event to verify stream recovery
            test_buf.append("graph", "post_resync_event", {"status": "recovered"})
            time.sleep(0.04)

        finally:
            stop_event.set()
            consumer_thread.join(timeout=1.0)
            event_stream._DEFAULT_BUFFER = old_buf

        self.assertFalse(consumer_thread.is_alive(), "Consumer thread failed to terminate cleanly")

        # Invariant 1: Exactly one resync_required event emitted
        resync_chunks = [c for c in collected_chunks if "resync_required" in c]
        self.assertEqual(
            len(resync_chunks),
            1,
            f"Expected exactly 1 resync_required event, got {len(resync_chunks)}",
        )

        # Invariant 2: Validate resync event JSON payload schema
        resync_lines = resync_chunks[0].strip().split("\n")
        data_line = next(line for line in resync_lines if line.startswith("data: "))
        resync_data = json.loads(data_line[6:])

        self.assertEqual(resync_data.get("topic"), "system")
        self.assertEqual(resync_data.get("event_type"), "resync_required")
        self.assertEqual(resync_data.get("data", {}).get("reason"), "buffer_evicted")
        self.assertGreaterEqual(resync_data.get("data", {}).get("oldest_seq", 0), 19)
        self.assertGreaterEqual(resync_data.get("data", {}).get("latest_seq", 0), 28)

        # Invariant 3: Stream recovered and delivered post-resync event
        post_resync_chunks = [c for c in collected_chunks if "post_resync_event" in c]
        self.assertEqual(
            len(post_resync_chunks),
            1,
            "Stream failed to recover after resync to deliver post-eviction events",
        )

        # Invariant 4: No infinite spin-loop occurred during eviction
        self.assertLess(
            len(collected_chunks),
            10,
            f"Excessive chunk count during eviction ({len(collected_chunks)}), indicating spin-loop",
        )


class TestModuleIntegration(unittest.TestCase):
    """Test real event publishing integration across opscryer core modules."""

    def setUp(self) -> None:
        reset_event_buffer()

    def tearDown(self) -> None:
        reset_event_buffer()

    def test_opscryer_backend_mutations_and_events(self) -> None:
        from opscryer_backend import KnowledgeGraphBackendEngine

        engine = KnowledgeGraphBackendEngine()
        initial_seq = publish_event("system", "baseline_marker")

        # 1. Add node
        new_node = {
            "id": "node-test-svc",
            "label": "Test Service",
            "domain": "company_org",
            "kind": "service",
            "summary": "Integration test service",
            "primary_url": "https://test.internal",
        }
        engine.add_node(new_node)

        # 2. Update node
        engine.update_node({"id": "node-test-svc", "label": "Updated Test Service"})

        # 3. Add edge
        new_edge = {
            "source": "node-test-svc",
            "target": "root-company",
            "relation": "depends_on",
        }
        engine.add_edge(new_edge)

        # 4. Remove edge
        engine.remove_edge("node-test-svc", "root-company")

        # 5. Remove node
        engine.remove_node("node-test-svc")

        # Query delta since baseline
        delta = engine.delta(since_seq=initial_seq)
        self.assertFalse(delta["full_resync_required"])
        # Node was added and removed in same window -> ghost node eliminated
        self.assertEqual(delta["added_nodes"], [])
        self.assertEqual(delta["updated_nodes"], [])
        self.assertEqual(delta["removed_nodes"], [])
        # Raw events array must retain all 5 mutation events
        event_types = [e["event_type"] for e in delta["events"]]
        self.assertIn("node_added", event_types)
        self.assertIn("node_updated", event_types)
        self.assertIn("edge_added", event_types)
        self.assertIn("edge_removed", event_types)
        self.assertIn("node_removed", event_types)

    def test_action_cards_lifecycle_events(self) -> None:
        from action_cards import ActionCardLedger

        ledger = ActionCardLedger()
        initial_seq = publish_event("system", "marker")

        # Stage card for worker node (single-key mode)
        card = ledger.stage_card(
            "nodegamma03",
            "scale_deployment",
            {"replicas": 3},
        )
        aid = card["action_id"]

        # Approve card
        status, resp = ledger.approve_card(aid, parameters_sha256=card["parameters_sha256"])
        self.assertEqual(status, 200)

        # Stage and reject second card
        card2 = ledger.stage_card("nodegamma03", "restart_node")
        aid2 = card2["action_id"]
        status2, resp2 = ledger.reject_card(aid2, reason="Operator cancelled")
        self.assertEqual(status2, 200)

        # Retrieve published events
        from event_stream import _DEFAULT_BUFFER

        events, _, _, _ = _DEFAULT_BUFFER.get_events_since(initial_seq, topics={"actions"})
        action_event_types = [e["event_type"] for e in events]
        self.assertIn("action_staged", action_event_types)
        self.assertIn("action_approved", action_event_types)
        self.assertIn("action_executed", action_event_types)
        self.assertIn("action_rejected", action_event_types)

    def test_http_transport_circuit_breaker_events(self) -> None:
        from http_transport import CircuitBreaker

        cb = CircuitBreaker("integration-test-cb", failure_threshold=2, recovery_timeout=0.05)
        initial_seq = publish_event("system", "marker")

        # Record failures to trip circuit
        cb.record_failure(RuntimeError("error 1"))
        cb.record_failure(RuntimeError("error 2"))

        from event_stream import _DEFAULT_BUFFER

        events, _, _, _ = _DEFAULT_BUFFER.get_events_since(initial_seq, topics={"security"})
        transition_events = [e for e in events if e["event_type"] == "circuit_breaker_transition"]
        self.assertTrue(len(transition_events) >= 1)
        self.assertEqual(transition_events[-1]["data"]["to_state"], "open")

    def test_jev_client_telemetry_events(self) -> None:
        from jev_client import evaluate_ticket_with_jev_tree

        initial_seq = publish_event("system", "marker")
        result = evaluate_ticket_with_jev_tree("need 3-tier scaffolding setup")
        self.assertEqual(result["route"], "leaf")

        from event_stream import _DEFAULT_BUFFER

        events, _, _, _ = _DEFAULT_BUFFER.get_events_since(initial_seq, topics={"jev"})
        jev_event_types = [e["event_type"] for e in events]
        self.assertIn("ticket_evaluated", jev_event_types)


if __name__ == "__main__":
    unittest.main()
