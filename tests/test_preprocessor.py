"""Unit tests for the preprocessor stage (validation + normalization)."""

import time
import unittest

from config import PreprocessorConfig
from parsers.models import (
    ApplicationLayer,
    DecodeInfo,
    NetworkLayer,
    NormalizedEvent,
    TransportLayer,
)
from preprocessor.preprocessor import Preprocessor


def _event(
    network=None,
    transport=None,
    application=None,
    timestamp=1700000000.0,
) -> NormalizedEvent:
    return NormalizedEvent(
        packet_id=1,
        timestamp=timestamp,
        raw_len=100,
        network=network,
        transport=transport,
        application=application,
    )


def _http_request(uri="/", headers=None, method="GET") -> ApplicationLayer:
    return ApplicationLayer(
        protocol="HTTP",
        type="request",
        details={"method": method, "uri": uri, "version": "HTTP/1.1", "headers": dict(headers or {}), "body": ""},
    )


class TestPreprocessorValidation(unittest.TestCase):
    def setUp(self):
        self.preprocessor = Preprocessor(PreprocessorConfig())

    def test_valid_event(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=52000, dst_port=80),
            application=ApplicationLayer(protocol="HTTP", type="request", details={}),
        )
        info = self.preprocessor.process(event)

        self.assertEqual(info.preprocess_status, "valid")
        self.assertIsNone(info.reason)
        self.assertEqual(info.processing_action, "forward")
        self.assertIs(event.preprocess, info)

    def test_missing_network_layer_is_invalid(self):
        event = _event(application=ApplicationLayer(protocol="ARP", type="request", details={}))
        info = self.preprocessor.process(event)

        self.assertEqual(info.preprocess_status, "invalid")
        self.assertEqual(info.reason, "missing_network_layer")
        self.assertEqual(info.processing_action, "forward")  # drop_invalid defaults to False
        self.assertIsNone(event.flow)

    def test_missing_transport_layer_is_partial(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="PROTO_0"),
            application=None,
        )
        info = self.preprocessor.process(event)

        self.assertEqual(info.preprocess_status, "partial")
        self.assertEqual(info.reason, "missing_transport_layer")

    def test_missing_application_layer_is_partial(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=80, dst_port=80),
            application=None,
        )
        info = self.preprocessor.process(event)

        self.assertEqual(info.preprocess_status, "partial")
        self.assertEqual(info.reason, "no_application_layer")

    def test_unsupported_protocol_is_partial(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.30", dst_ip="10.0.0.31", proto="UDP"),
            transport=TransportLayer(layer="UDP", src_port=40000, dst_port=40001),
            application=ApplicationLayer(protocol="UNKNOWN", type="default", details={}),
        )
        info = self.preprocessor.process(event)

        self.assertEqual(info.preprocess_status, "partial")
        self.assertEqual(info.reason, "unsupported_protocol")

    def test_invalid_port_is_invalid(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=99999, dst_port=80),
            application=ApplicationLayer(protocol="HTTP", type="request", details={}),
        )
        info = self.preprocessor.process(event)

        self.assertEqual(info.preprocess_status, "invalid")
        self.assertEqual(info.reason, "invalid_port")

    def test_invalid_timestamp_is_invalid(self):
        event = _event(network=NetworkLayer(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="TCP"), timestamp=-1)
        info = self.preprocessor.process(event)

        self.assertEqual(info.preprocess_status, "invalid")
        self.assertEqual(info.reason, "invalid_timestamp")

    def test_invalid_ip_address_is_invalid(self):
        event = _event(network=NetworkLayer(src_ip="not-an-ip", dst_ip="10.0.0.2", proto="TCP"))
        info = self.preprocessor.process(event)

        self.assertEqual(info.preprocess_status, "invalid")
        self.assertEqual(info.reason, "invalid_ip_address")

    def test_future_timestamp_is_partial(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=1, dst_port=2),
            application=ApplicationLayer(protocol="HTTP", type="request", details={}),
            timestamp=time.time() + 200000,
        )
        info = self.preprocessor.process(event)

        self.assertEqual(info.preprocess_status, "partial")
        self.assertEqual(info.reason, "timestamp_in_future")

    def test_second_problem_is_reported_as_warning(self):
        event = _event()  # no network, no transport, no application
        info = self.preprocessor.process(event)

        self.assertEqual(info.reason, "missing_network_layer")
        self.assertIn("missing_transport_layer", info.warnings)
        self.assertIn("no_application_layer", info.warnings)

    def test_drop_invalid_config_drops_event(self):
        preprocessor = Preprocessor(PreprocessorConfig(drop_invalid=True))
        event = _event()
        info = preprocessor.process(event)

        self.assertEqual(info.processing_action, "dropped")

    def test_drop_invalid_does_not_drop_partial_events(self):
        preprocessor = Preprocessor(PreprocessorConfig(drop_invalid=True))
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=80, dst_port=80),
            application=None,
        )
        info = preprocessor.process(event)

        self.assertEqual(info.preprocess_status, "partial")
        self.assertEqual(info.processing_action, "forward")

    def test_process_never_raises_on_hostile_events(self):
        hostile = [
            _event(network=NetworkLayer(src_ip="", dst_ip="", proto="")),
            _event(
                network=NetworkLayer(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="TCP"),
                transport=TransportLayer(layer="TCP", src_port="80", dst_port=None),
            ),
            _event(
                network=NetworkLayer(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="TCP"),
                transport=TransportLayer(layer="TCP", src_port=0, dst_port=0),
                application=ApplicationLayer(protocol="HTTP", type="response", details={"headers": "bad"}),
            ),
        ]
        for event in hostile:
            info = self.preprocessor.process(event)
            self.assertIn(info.preprocess_status, {"valid", "partial", "invalid"})


class TestPreprocessorNormalization(unittest.TestCase):
    def setUp(self):
        self.preprocessor = Preprocessor(PreprocessorConfig())

    def test_protocol_names_and_headers_are_normalized(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="tcp"),
            transport=TransportLayer(layer="tcp", src_port=52000, dst_port=80),
            application=_http_request(
                uri="/x",
                headers={"hOSt": "IDS.SECURITY.LAB:8080", "content-TYPE": "text/plain"},
            ),
        )
        info = self.preprocessor.process(event)

        self.assertEqual(event.network.proto, "TCP")
        self.assertEqual(event.transport.layer, "TCP")
        self.assertIn("protocol_name", info.normalizations)
        self.assertIn("http_header_names", info.normalizations)
        self.assertIn("host_header", info.normalizations)
        self.assertEqual(event.application.details["headers"]["Content-Type"], "text/plain")
        self.assertEqual(event.application.details["headers"]["Host"], "ids.security.lab:8080")

    def test_ip_addresses_are_canonicalized(self):
        event = _event(
            network=NetworkLayer(
                src_ip="2001:0DB8:0000:0000:0000:0000:0000:0001", dst_ip="10.0.0.2", proto="TCP"
            ),
            transport=TransportLayer(layer="TCP", src_port=1, dst_port=2),
            application=ApplicationLayer(protocol="HTTP", type="request", details={}),
        )
        info = self.preprocessor.process(event)

        self.assertEqual(event.network.src_ip, "2001:db8::1")
        self.assertEqual(event.network.dst_ip, "10.0.0.2")
        self.assertIn("ip_address", info.normalizations)

    def test_already_canonical_ip_is_not_reported(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=1, dst_port=2),
            application=ApplicationLayer(protocol="HTTP", type="request", details={}),
        )
        info = self.preprocessor.process(event)

        self.assertNotIn("ip_address", info.normalizations)

    def test_dns_domain_names_are_lowercased(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.10", dst_ip="8.8.8.8", proto="UDP"),
            transport=TransportLayer(layer="UDP", src_port=53000, dst_port=53),
            application=ApplicationLayer(
                protocol="DNS",
                type="query",
                details={"queries": [{"name": "PORTAL.UIT.EDU.VN", "type": "A"}], "answers": []},
            ),
        )
        info = self.preprocessor.process(event)

        self.assertEqual(event.application.details["queries"][0]["name"], "portal.uit.edu.vn")
        self.assertIn("domain_lowercase", info.normalizations)

    def test_domain_normalization_can_be_disabled(self):
        preprocessor = Preprocessor(PreprocessorConfig(normalize_domains=False))
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.10", dst_ip="8.8.8.8", proto="UDP"),
            transport=TransportLayer(layer="UDP", src_port=53000, dst_port=53),
            application=ApplicationLayer(
                protocol="DNS", type="query", details={"queries": [{"name": "A.B.C", "type": "A"}]}
            ),
        )
        info = preprocessor.process(event)

        self.assertEqual(event.application.details["queries"][0]["name"], "A.B.C")
        self.assertNotIn("domain_lowercase", info.normalizations)

    def test_uri_is_normalized_from_decoded_form(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=52000, dst_port=80),
            application=_http_request(uri="//admin//./stats/%2e%2e/secret?q=%2f"),
        )
        event.decode = DecodeInfo(
            decode_status="decoded",
            decoders=["percent_url"],
            fields={"uri_decoded": "//admin//./stats/../secret?q=/"},
        )
        info = self.preprocessor.process(event)

        self.assertEqual(event.application.details["uri_normalized"], "/admin/secret?q=/")
        self.assertIn("uri_path", info.normalizations)

    def test_uri_without_changes_is_not_reported(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=52000, dst_port=80),
            application=_http_request(uri="/api/v1/stats"),
        )
        info = self.preprocessor.process(event)

        self.assertEqual(event.application.details["uri_normalized"], "/api/v1/stats")
        self.assertNotIn("uri_path", info.normalizations)

    def test_uri_normalization_can_be_disabled(self):
        preprocessor = Preprocessor(PreprocessorConfig(normalize_uri=False))
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=52000, dst_port=80),
            application=_http_request(uri="//a//b/../c"),
        )
        info = preprocessor.process(event)

        self.assertNotIn("uri_normalized", event.application.details)
        self.assertNotIn("uri_path", info.normalizations)

    def test_duplicate_header_after_canonicalization_warns(self):
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=52000, dst_port=80),
            application=_http_request(uri="/x", headers={"Content-Type": "text/plain", "content-TYPE": "text/html"}),
        )
        info = self.preprocessor.process(event)

        self.assertIn("duplicate_header_name", info.warnings)
        self.assertEqual(event.application.details["headers"]["Content-Type"], "text/plain")

    def test_normalization_can_be_disabled_entirely(self):
        preprocessor = Preprocessor(PreprocessorConfig(normalize_headers=False, normalize_domains=False, normalize_uri=False))
        event = _event(
            network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="tcp"),
            transport=TransportLayer(layer="tcp", src_port=52000, dst_port=80),
            application=_http_request(uri="//a//b", headers={"content-TYPE": "text/plain"}),
        )
        info = preprocessor.process(event)

        # Protocol normalization has no config switch (always on).
        self.assertIn("protocol_name", info.normalizations)
        self.assertNotIn("http_header_names", info.normalizations)
        self.assertNotIn("uri_path", info.normalizations)
        self.assertEqual(event.application.details["headers"], {"content-TYPE": "text/plain"})

    def test_uri_path_edge_cases(self):
        cases = {
            "/a/b/../../../c": "/c",
            "/a/./b": "/a/b",
            "/a/b/": "/a/b/",
            "/a/b/.": "/a/b/",
            "/a/b/..": "/a/",
            "http://EXAMPLE.com/A/B": "http://example.com/A/B",
            "/%2e%2e/escape": "/%2E%2E/escape",
        }
        for raw, expected in cases.items():
            event = _event(
                network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="TCP"),
                transport=TransportLayer(layer="TCP", src_port=52000, dst_port=80),
                application=_http_request(uri=raw),
            )
            self.preprocessor.process(event)
            self.assertEqual(event.application.details["uri_normalized"], expected, msg=raw)


if __name__ == "__main__":
    unittest.main()
