"""Unit tests cho Rule Evaluation Engine (core.evaluator)."""

import unittest

from core.evaluator import RuleEvaluationEngine
from core.indexer import RuleRepository
from core.parser import RuleParser
from parsers.models import FlowRef, NetworkLayer, NormalizedEvent, TransportLayer

PAYLOAD = b"GET /x HTTP/1.1\r\nHost: ids.local\r\n\r\n"

RULES = [
    ('alert tcp any any -> any 80 (msg:"generic get"; content:"GET"; nocase; sid:100001; rev:1;)', 100001),
    ('alert tcp any any -> any 80 (msg:"path x"; content:"/x"; sid:100002; rev:1;)', 100002),
    ('alert tcp any any -> any 443 (msg:"tls"; content:"|16 03|"; sid:100003; rev:1;)', 100003),
]


def build_repository(rule_texts) -> RuleRepository:
    repository = RuleRepository()
    for index, text in enumerate(rule_texts):
        outcome = RuleParser.parse(text, "eval.rules", index + 1)
        assert outcome.ok, outcome.reason
        repository.add(outcome.rule)
    return repository


def make_event(src_port=52000, dst_port=80) -> NormalizedEvent:
    return NormalizedEvent(
        packet_id=1,
        timestamp=1700000000.0,
        raw_len=len(PAYLOAD) + 54,
        network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="TCP"),
        transport=TransportLayer(layer="TCP", src_port=src_port, dst_port=dst_port, payload_len=len(PAYLOAD)),
        flow=FlowRef(flow_id="TCP-10.0.0.10:52000-10.0.0.20:80", direction="forward", state="ESTABLISHED", is_new_flow=False),
    )


class TestRuleEvaluationEngine(unittest.TestCase):
    def test_multi_match_returns_all_detections(self):
        engine = RuleEvaluationEngine(build_repository([text for text, _ in RULES]))
        detections = engine.evaluate(make_event(), PAYLOAD)

        sids = [detection.sid for detection in detections]
        self.assertEqual(sids, [100001, 100002])  # sid 100003 sai port -> không phải candidate
        self.assertEqual(engine.stats()["events_evaluated"], 1)
        self.assertEqual(engine.stats()["candidate_rules"], 2)
        self.assertEqual(engine.stats()["matches"], 2)

    def test_stop_on_first_match(self):
        engine = RuleEvaluationEngine(build_repository([text for text, _ in RULES]), stop_on_first_match=True)
        detections = engine.evaluate(make_event(), PAYLOAD)

        self.assertEqual([detection.sid for detection in detections], [100001])
        self.assertEqual(engine.stats()["matches"], 1)

    def test_no_match(self):
        engine = RuleEvaluationEngine(build_repository([text for text, _ in RULES]))
        detections = engine.evaluate(make_event(dst_port=8080), PAYLOAD)

        self.assertEqual(detections, [])
        self.assertEqual(engine.stats()["events_evaluated"], 1)
        self.assertEqual(engine.stats()["candidate_rules"], 0)
        self.assertEqual(engine.stats()["matches"], 0)

    def test_event_without_transport_is_skipped(self):
        engine = RuleEvaluationEngine(build_repository([text for text, _ in RULES]))
        event = make_event()
        event.transport = None

        self.assertEqual(engine.evaluate(event, b""), [])
        self.assertEqual(engine.stats()["events_evaluated"], 0)

    def test_detection_carries_match_details(self):
        engine = RuleEvaluationEngine(build_repository([text for text, _ in RULES]))
        detection = engine.evaluate(make_event(), PAYLOAD)[0]

        self.assertEqual(detection.msg, "generic get")
        content = detection.matched["contents"][0]
        self.assertEqual(content["content"], "GET")
        self.assertEqual(PAYLOAD[content["offset"]:content["offset"] + content["length"]], b"GET")

    def test_stats_reports_rules_loaded(self):
        engine = RuleEvaluationEngine(build_repository([text for text, _ in RULES]))
        self.assertEqual(engine.stats()["rules_loaded"], 3)


if __name__ == "__main__":
    unittest.main()
