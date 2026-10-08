"""End-to-end IDS processing engine.

Chains the assignment stages for every captured packet:

    Capture -> Parse (network/transport/application) -> Decoder ->
    Preprocessor -> Flow/Connection Tracker

The engine owns the per-run statistics (packets processed/dropped, flows
created/closed) and guarantees that one malformed packet never aborts a run.
"""

from typing import Any, Callable, Dict, Optional

from capture.capturer import CapturedPacket
from config import IDSConfig
from decoder.decoder import Decoder
from flow.models import Flow
from flow.tracker import FlowTracker
from parsers.models import NormalizedEvent
from pipeline.pipeline import ParsingPipeline
from preprocessor.preprocessor import Preprocessor


class IDSEngine:
    """Runs parse, decode, preprocess and flow tracking for each packet."""

    def __init__(
        self,
        config: IDSConfig,
        on_flow_closed: Optional[Callable[[Flow], None]] = None,
    ) -> None:
        self.config = config
        self.packets_processed = 0
        self.packets_dropped = 0
        self._parsers = ParsingPipeline(include_unknown=config.pipeline.include_unknown)
        self._decoder = Decoder(config.decoder)
        self._preprocessor = Preprocessor(config.preprocessor)
        self._tracker = FlowTracker(config.flow, on_flow_closed=on_flow_closed)

    def process_packet(self, captured: CapturedPacket) -> NormalizedEvent:
        """Process one captured packet through the full chain."""
        event, payload = self._parsers.parse(captured)
        self._decoder.decode(event, payload)
        self._preprocessor.process(event)

        self.packets_processed += 1
        preprocess = event.preprocess
        if preprocess is not None and preprocess.processing_action == "dropped":
            # Dropped events are not attributed to a flow.
            self.packets_dropped += 1
            event.flow = None
        else:
            self._tracker.observe(event)
        return event

    def finalize(self) -> int:
        """Flush the flow tracker at end of run; returns flows closed here."""
        return self._tracker.finalize()

    def stats(self) -> Dict[str, Any]:
        """Return pipeline and tracker counters for the run summary."""
        stats: Dict[str, Any] = {
            "packets_processed": self.packets_processed,
            "packets_dropped": self.packets_dropped,
        }
        stats.update(self._tracker.stats())
        return stats
