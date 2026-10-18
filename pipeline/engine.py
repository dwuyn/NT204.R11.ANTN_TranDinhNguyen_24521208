"""End-to-end IDS processing engine.

Chains the assignment stages for every captured packet:

    Capture -> Parse (network/transport/application) -> Decoder ->
    Preprocessor -> Flow/Connection Tracker -> Rule Evaluation

The engine owns the per-run statistics (packets processed/dropped, flows
created/closed, rule evaluation counters) and guarantees that one malformed
packet never aborts a run. Rule evaluation is only active when a non-empty
rule repository is provided, so the pipeline behaviour without rule files is
unchanged.
"""

from typing import Any, Callable, Dict, Optional

from capture.capturer import CapturedPacket
from config import IDSConfig
from core.detection import DetectionEvent
from core.evaluator import RuleEvaluationEngine
from core.indexer import RuleRepository
from decoder.decoder import Decoder
from flow.models import Flow
from flow.tracker import FlowTracker
from parsers.models import NormalizedEvent
from pipeline.pipeline import ParsingPipeline
from preprocessor.preprocessor import Preprocessor


class IDSEngine:
    """Runs parse, decode, preprocess, flow tracking and rule evaluation."""

    def __init__(
        self,
        config: IDSConfig,
        on_flow_closed: Optional[Callable[[Flow], None]] = None,
        rule_repository: Optional[RuleRepository] = None,
        on_detection: Optional[Callable[[DetectionEvent], None]] = None,
    ) -> None:
        self.config = config
        self.packets_processed = 0
        self.packets_dropped = 0
        self._parsers = ParsingPipeline(include_unknown=config.pipeline.include_unknown)
        self._decoder = Decoder(config.decoder)
        self._preprocessor = Preprocessor(config.preprocessor)
        self._tracker = FlowTracker(config.flow, on_flow_closed=on_flow_closed)
        self._rule_engine: Optional[RuleEvaluationEngine] = None
        if rule_repository is not None and len(rule_repository) > 0:
            self._rule_engine = RuleEvaluationEngine(
                rule_repository,
                stop_on_first_match=config.rules.stop_on_first_match,
            )
        self._on_detection = on_detection

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

        if self._rule_engine is not None:
            for detection in self._rule_engine.evaluate(event, payload):
                if self._on_detection is not None:
                    self._on_detection(detection)
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
        if self._rule_engine is not None:
            stats.update(self._rule_engine.stats())
        return stats

