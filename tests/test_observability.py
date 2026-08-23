from __future__ import annotations

import dataclasses
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from market_aligner.state.observability import (
    ComponentContract,
    ComponentDefinition,
    FlowDefinition,
    FlowStep,
    ObservabilityStore,
    OperationTrace,
    SpanRecord,
    TraceEvent,
    hash_payload,
)


UTC = timezone.utc


def _flow(*, version: str = "1", temperature: float = 0.0) -> FlowDefinition:
    contract = ComponentContract(
        input_schema={"type": "object", "required": ["job"]},
        output_schema={"type": "object", "required": ["score"]},
        side_effects=("model.call",),
    )
    component = ComponentDefinition(
        component_id="opportunity.judge",
        component_type="llm.judge",
        version="sol-2026-07",
        kind="probabilistic",
        contract=contract,
        configuration={"temperature": temperature, "prompt": "opportunity-v3"},
    )
    return FlowDefinition(
        flow_id="career.opportunity",
        version=version,
        components=(component,),
        steps=(FlowStep("judge", "opportunity.judge"),),
        metadata={"owner": "career-automation"},
    )


def _trace(flow: FlowDefinition, *, trace_id: str = "trace-1") -> OperationTrace:
    return OperationTrace(
        trace_id=trace_id,
        flow_hash=flow.content_hash,
        operation="opportunity.assess",
        status="running",
        input_hash=hash_payload({"job_key": "board:1"}),
        model_version="gpt-5.6-sol",
        prompt_version="opportunity-v3",
        profile_version="profile-2026-07-19",
        started_at=datetime(2026, 7, 19, 10, 0, tzinfo=UTC),
        job_key="board:1",
        metadata={"run": 1},
    )


class FlowDefinitionTests(unittest.TestCase):
    def test_round_trip_and_hash_are_deterministic(self) -> None:
        first = _flow()
        rebuilt = FlowDefinition.from_json(first.to_json())
        self.assertEqual(rebuilt.to_dict(), first.to_dict())
        self.assertEqual(rebuilt.content_hash, first.content_hash)

        reordered_config = dataclasses.replace(
            first.components[0],
            configuration={"prompt": "opportunity-v3", "temperature": 0.0},
        )
        equivalent = dataclasses.replace(first, components=(reordered_config,))
        self.assertEqual(equivalent.content_hash, first.content_hash)

    def test_version_or_configuration_change_changes_hash(self) -> None:
        baseline = _flow()
        self.assertNotEqual(_flow(version="2").content_hash, baseline.content_hash)
        self.assertNotEqual(_flow(temperature=0.2).content_hash, baseline.content_hash)

    def test_rejects_invalid_graphs_and_nonportable_json(self) -> None:
        component = _flow().components[0]
        with self.assertRaisesRegex(ValueError, "dependency cycle"):
            FlowDefinition(
                flow_id="cyclic",
                version="1",
                components=(component,),
                steps=(
                    FlowStep("one", component.component_id, ("two",)),
                    FlowStep("two", component.component_id, ("one",)),
                ),
            )
        with self.assertRaisesRegex(ValueError, "non-finite"):
            dataclasses.replace(component, configuration={"temperature": float("nan")})


class ObservabilityStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "career.sqlite3"
        self.store = ObservabilityStore(self.path)
        self.flow = _flow()
        self.store.register_flow(self.flow)
        self.trace = _trace(self.flow)
        self.store.write_trace(self.trace)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_namespaced_tables_coexist_with_existing_database(self) -> None:
        with self.store.connection() as connection:
            connection.execute("CREATE TABLE pipeline_jobs_sentinel(value TEXT)")
            names = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        self.assertIn("pipeline_jobs_sentinel", names)
        self.assertIn("ca_obs_traces", names)
        expected = {
            "ca_obs_flows",
            "ca_obs_traces",
            "ca_obs_spans",
            "ca_obs_events",
            "ca_obs_outbox",
        }
        self.assertTrue(expected.issubset(names))

    def test_trace_span_and_event_writes_are_idempotent(self) -> None:
        self.assertFalse(self.store.register_flow(self.flow))
        self.assertFalse(self.store.write_trace(self.trace))
        finished = dataclasses.replace(
            self.trace,
            status="succeeded",
            output_hash=hash_payload({"score": 0.8}),
            ended_at=datetime(2026, 7, 19, 10, 0, 1, tzinfo=UTC),
            latency_ms=1000,
            cost_usd=0.012,
        )
        self.assertTrue(
            self.store.finish_trace(
                self.trace.trace_id,
                status=finished.status,
                output_hash=finished.output_hash,
                ended_at=finished.ended_at,
                latency_ms=finished.latency_ms,
                cost_usd=finished.cost_usd,
            )
        )
        self.assertFalse(
            self.store.finish_trace(
                self.trace.trace_id,
                status=finished.status,
                output_hash=finished.output_hash,
                ended_at=finished.ended_at,
                latency_ms=finished.latency_ms,
                cost_usd=finished.cost_usd,
            )
        )
        span = SpanRecord(
            span_id="span-1",
            trace_id=self.trace.trace_id,
            component_id="opportunity.judge",
            component_version="sol-2026-07",
            operation="model.invoke",
            status="succeeded",
            input_hash=self.trace.input_hash,
            output_hash=finished.output_hash,
            idempotency_key="span:trace-1:judge",
            model_version="gpt-5.6-sol",
            prompt_version="opportunity-v3",
            profile_version="profile-2026-07-19",
            started_at=self.trace.started_at,
            ended_at=finished.ended_at,
            latency_ms=940,
            cost_usd=0.012,
        )
        self.assertTrue(self.store.write_span(span))
        self.assertFalse(self.store.write_span(span))
        with self.assertRaisesRegex(ValueError, "different content"):
            self.store.write_span(dataclasses.replace(span, cost_usd=99.0))

        event = TraceEvent(
            trace_id=self.trace.trace_id,
            span_id=span.span_id,
            event_type="model.completed",
            payload={"output_hash": finished.output_hash},
            idempotency_key="event:trace-1:model-completed",
            occurred_at=finished.ended_at,
        )
        self.assertTrue(self.store.write_event(event))
        self.assertFalse(self.store.write_event(event))
        with self.assertRaisesRegex(ValueError, "different content"):
            self.store.write_event(dataclasses.replace(event, payload={"changed": True}))

        with self.store.connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM ca_obs_spans").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM ca_obs_events").fetchone()[0], 1)

    def test_outbox_enqueue_is_idempotent_and_conflict_safe(self) -> None:
        arguments = {
            "trace_id": self.trace.trace_id,
            "event_type": "trace.export",
            "payload": {"trace_id": self.trace.trace_id},
            "idempotency_key": "export:trace-1",
        }
        self.assertTrue(self.store.enqueue_outbox(**arguments))
        self.assertFalse(self.store.enqueue_outbox(**arguments))
        with self.assertRaisesRegex(ValueError, "different content"):
            self.store.enqueue_outbox(**{**arguments, "payload": {"different": True}})

    def test_expired_lease_is_recovered_and_stale_receipt_is_rejected(self) -> None:
        t0 = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
        self.store.enqueue_outbox(
            trace_id=self.trace.trace_id,
            event_type="trace.export",
            payload={"trace": 1},
            idempotency_key="lease-recovery",
            available_at=t0,
        )
        first = self.store.claim_outbox("worker-1", lease_seconds=5, now=t0)
        self.assertIsNotNone(first)
        assert first is not None and first.lease_token is not None
        self.assertIsNone(
            self.store.claim_outbox("worker-2", lease_seconds=5, now=t0 + timedelta(seconds=4))
        )

        # Simulate process interruption: reconstruct the store without ack/fail.
        reopened = ObservabilityStore(self.path)
        recovered = reopened.claim_outbox(
            "worker-2", lease_seconds=5, now=t0 + timedelta(seconds=5)
        )
        self.assertIsNotNone(recovered)
        assert recovered is not None and recovered.lease_token is not None
        self.assertEqual(recovered.message_id, first.message_id)
        self.assertEqual(recovered.attempts, 2)
        with self.assertRaisesRegex(RuntimeError, "lease receipt"):
            self.store.ack_outbox(
                first.message_id,
                worker_id="worker-1",
                lease_token=first.lease_token,
                now=t0 + timedelta(seconds=6),
            )
        self.assertTrue(
            reopened.ack_outbox(
                recovered.message_id,
                worker_id="worker-2",
                lease_token=recovered.lease_token,
                now=t0 + timedelta(seconds=6),
            )
        )
        retained = reopened.outbox_message(recovered.message_id)
        self.assertEqual(retained.status, "acked")
        self.assertEqual(retained.payload, {"trace": 1})

    def test_failures_use_exponential_retry_and_retain_dead_message(self) -> None:
        t0 = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
        self.store.enqueue_outbox(
            trace_id=self.trace.trace_id,
            event_type="trace.export",
            payload={"trace": 1},
            idempotency_key="retry-test",
            max_attempts=3,
            available_at=t0,
        )
        first = self.store.claim_outbox("worker", now=t0)
        assert first is not None and first.lease_token is not None
        queued = self.store.fail_outbox(
            first.message_id,
            worker_id="worker",
            lease_token=first.lease_token,
            error="network-1",
            base_delay_seconds=10,
            now=t0,
        )
        self.assertEqual(queued.status, "queued")
        self.assertEqual(queued.available_at, t0 + timedelta(seconds=10))
        self.assertIsNone(self.store.claim_outbox("worker", now=t0 + timedelta(seconds=9)))

        second = self.store.claim_outbox("worker", now=t0 + timedelta(seconds=10))
        assert second is not None and second.lease_token is not None
        queued = self.store.fail_outbox(
            second.message_id,
            worker_id="worker",
            lease_token=second.lease_token,
            error="network-2",
            base_delay_seconds=10,
            now=t0 + timedelta(seconds=10),
        )
        self.assertEqual(queued.available_at, t0 + timedelta(seconds=30))

        third = self.store.claim_outbox("worker", now=t0 + timedelta(seconds=30))
        assert third is not None and third.lease_token is not None
        dead = self.store.fail_outbox(
            third.message_id,
            worker_id="worker",
            lease_token=third.lease_token,
            error="permanent",
            base_delay_seconds=10,
            now=t0 + timedelta(seconds=30),
        )
        self.assertEqual(dead.status, "dead")
        self.assertEqual(dead.attempts, 3)
        self.assertEqual(dead.last_error, "permanent")
        self.assertIsNone(self.store.claim_outbox("worker", now=t0 + timedelta(days=1)))
        self.assertTrue(
            self.store.requeue_dead(dead.message_id, now=t0 + timedelta(days=1))
        )
        revived = self.store.claim_outbox("worker", now=t0 + timedelta(days=1))
        self.assertIsNotNone(revived)
        assert revived is not None
        self.assertEqual(revived.attempts, 4)

    def test_final_attempt_interruption_is_retained_not_stranded(self) -> None:
        t0 = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
        self.store.enqueue_outbox(
            trace_id=self.trace.trace_id,
            event_type="trace.export",
            payload={"trace": 1},
            idempotency_key="final-lease-interruption",
            max_attempts=1,
            available_at=t0,
        )
        claimed = self.store.claim_outbox("worker", lease_seconds=5, now=t0)
        assert claimed is not None

        # The only delivery worker disappears. A later poll must retain the payload
        # as dead rather than leaving an unclaimable final lease behind forever.
        self.assertIsNone(
            self.store.claim_outbox("recovery", now=t0 + timedelta(seconds=5))
        )
        retained = self.store.outbox_message(claimed.message_id)
        self.assertEqual(retained.status, "dead")
        self.assertEqual(retained.payload, {"trace": 1})
        self.assertIn("lease expired", retained.last_error or "")

    def test_acknowledged_message_cannot_be_failed_back_to_queue(self) -> None:
        t0 = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
        self.store.enqueue_outbox(
            trace_id=self.trace.trace_id,
            event_type="trace.export",
            payload={"trace": 1},
            idempotency_key="acked-is-terminal",
            available_at=t0,
        )
        claimed = self.store.claim_outbox("worker", now=t0)
        assert claimed is not None and claimed.lease_token is not None
        self.store.ack_outbox(
            claimed.message_id,
            worker_id="worker",
            lease_token=claimed.lease_token,
            now=t0,
        )
        with self.assertRaisesRegex(RuntimeError, "lease receipt"):
            self.store.fail_outbox(
                claimed.message_id,
                worker_id="worker",
                lease_token=claimed.lease_token,
                error="late failure",
                now=t0,
            )
        self.assertEqual(self.store.outbox_message(claimed.message_id).status, "acked")


if __name__ == "__main__":
    unittest.main()
