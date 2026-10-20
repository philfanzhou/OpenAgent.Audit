"""Agent-side instrumentation (proposal §11.2).

``AgentInstrument`` covers the two write-side duties that happen on the
request path:

1. **媒体先替换再上报** — base64 payloads are envelope-encrypted, uploaded to
   object storage, and replaced with ``s3://`` references *before* anything
   enters the trace (media bytes never reach the Langfuse pipeline).
2. **标识符透传** — conversation id -> ``session_id``, internal user id ->
   ``user_id``, agent id -> ``tags``, so every trace aggregates correctly.

Prompt/completion masking deliberately does *not* happen here: the export
hook (:mod:`openagent_audit.tracing.hook`) masks in the background export
thread, fail-closed. ``AgentInstrument`` works against any ``TraceSink``
(Langfuse SDK sink in production, local recorder in tests).
"""

from __future__ import annotations

from typing import Protocol, Sequence

from openagent_audit.media.service import MediaReference, MediaService


class SpanHandle(Protocol):
    def set_attribute(self, key: str, value: object) -> None: ...
    def end(self) -> None: ...


class TraceSink(Protocol):
    """Minimal surface both the Langfuse sink and the test sink implement."""

    def start_trace(
        self, name: str, *, session_id: str, user_id: str, agent_tag: str, trace_id: str
    ) -> "TraceHandle": ...


class TraceHandle(Protocol):
    def add_span(self, name: str, *, input: object = None, output: object = None) -> SpanHandle: ...
    def add_generation(
        self, name: str, *, model: str, input: object = None, output: object = None,
        usage: dict | None = None, latency_ms: int | None = None,
    ) -> SpanHandle: ...
    def end(self) -> None: ...


class LocalTraceSink:
    """Writes :class:`TraceRecord` objects into a ``LocalTraceStore``."""

    def __init__(self, store) -> None:
        self._store = store

    def start_trace(self, name, *, session_id, user_id, agent_tag, trace_id):
        from datetime import datetime, timezone

        from openagent_audit.tracing.trace_store import ObservationRecord, TraceRecord

        store = self._store
        observations: list[ObservationRecord] = []

        class _Span:
            def __init__(self, record: ObservationRecord) -> None:
                self._record = record

            def set_attribute(self, key: str, value: object) -> None:
                pass

            def end(self) -> None:
                pass

        class _Trace:
            def __init__(self) -> None:
                self._ts = datetime.now(timezone.utc)

            def add_span(self, name, *, input=None, output=None):
                rec = ObservationRecord(id=f"span-{len(observations)}", type="span", name=name,
                                        input=input, output=output)
                observations.append(rec)
                return _Span(rec)

            def add_generation(self, name, *, model, input=None, output=None, usage=None, latency_ms=None):
                rec = ObservationRecord(id=f"gen-{len(observations)}", type="generation", name=name,
                                        input=input, output=output, model=model,
                                        usage=usage or {}, latency_ms=latency_ms)
                observations.append(rec)
                return _Span(rec)

            def end(self) -> None:
                store.upsert_trace(
                    TraceRecord(
                        trace_id=trace_id, session_id=session_id, user_id=user_id,
                        agent_tag=agent_tag, name=name, timestamp=self._ts,
                        observations=tuple(observations),
                    )
                )

        return _Trace()


class LangfuseTraceSink:
    """Adapter over the Langfuse v5 SDK (``langfuse`` extra).

    Identifiers ride the documented OTEL attribute mapping
    (``langfuse.session.id``, ``langfuse.user.id``, ``langfuse.tag.<name>``),
    equivalent to ``propagate_attributes`` for manual spans.
    """

    LANGFUSE_SESSION = "langfuse.session.id"
    LANGFUSE_USER = "langfuse.user.id"
    LANGFUSE_TAG = "langfuse.tag."

    def __init__(self, client) -> None:  # langfuse.Langfuse
        self._client = client

    def start_trace(self, name, *, session_id, user_id, agent_tag, trace_id):
        client = self._client
        root = client.start_observation(name=name, trace_id=trace_id)
        root.set_attribute(self.LANGFUSE_SESSION, session_id)
        root.set_attribute(self.LANGFUSE_USER, user_id)
        for tag in agent_tag.split(","):
            if tag.strip():
                root.set_attribute(f"{self.LANGFUSE_TAG}{tag.strip()}", "")

        class _Child:
            def __init__(self, obs) -> None:
                self._obs = obs

            def set_attribute(self, key: str, value: object) -> None:
                self._obs.set_attribute(key, value)

            def update(self, **kwargs) -> None:
                self._obs.update(**kwargs)

            def end(self) -> None:
                self._obs.end()

        class _Trace:
            def _child(self, name, input, output, *, as_type):
                kwargs = {"name": name, "as_type": as_type}
                if input is not None:
                    kwargs["input"] = input
                if output is not None:
                    kwargs["output"] = output
                return _Child(root.start_observation(**kwargs))

            def add_span(self, name, *, input=None, output=None):
                return self._child(name, input, output, as_type="span")

            def add_generation(self, name, *, model, input=None, output=None, usage=None, latency_ms=None):
                child = self._child(name, input, output, as_type="generation")
                if model or usage or latency_ms:
                    child.update(model=model, usage=usage, latency=latency_ms)
                return child

            def end(self) -> None:
                root.end()

        return _Trace()


class AgentInstrument:
    def __init__(self, sink: TraceSink, media: MediaService | None = None) -> None:
        self._sink = sink
        self._media = media

    def prepare_messages(self, messages: Sequence[dict]) -> tuple[list[dict], list[MediaReference]]:
        """Encrypt + upload inline media and swap in references."""
        if self._media is None:
            return list(messages), []
        return self._media.replace_references(list(messages))

    def report_request(
        self,
        *,
        trace_id: str,
        conversation_id: str,
        internal_user_id: str,
        agent_id: str,
        name: str,
        messages: Sequence[dict],
        llm_calls: Sequence[dict] | None = None,
    ) -> tuple[str, list[MediaReference]]:
        """Record one user request as a trace tree.

        Returns the serialized (media-reference) messages actually recorded,
        plus the media references generated. Text content is recorded as-is:
        masking happens in the export thread before anything leaves the
        process (fail-closed), per the proposal.
        """
        prepared, refs = self.prepare_messages(messages)
        trace = self._sink.start_trace(
            name,
            session_id=conversation_id,
            user_id=internal_user_id,
            agent_tag=f"agent:{agent_id}",
            trace_id=trace_id,
        )
        trace.add_span("接收请求", input=prepared)
        for call in llm_calls or []:
            trace.add_generation(
                call.get("name", "LLM 调用"),
                model=call.get("model", ""),
                input=call.get("input"),
                output=call.get("output"),
                usage=call.get("usage"),
                latency_ms=call.get("latency_ms"),
            )
        trace.add_span("返回响应", output=prepared[-1] if prepared else None)
        trace.end()
        return prepared, refs
