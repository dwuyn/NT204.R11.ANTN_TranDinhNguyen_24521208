"""Unit tests for the IDS configuration module."""

import argparse
import json
import os
import tempfile
import unittest

from config import (
    DEFAULT_MAX_ACTIVE_FLOWS,
    DEFAULT_MAX_DECODE_SIZE,
    DEFAULT_TCP_IDLE_TIMEOUT,
    DEFAULT_UDP_IDLE_TIMEOUT,
    DecoderConfig,
    FlowConfig,
    IDSConfig,
    PipelineConfig,
    PreprocessorConfig,
    apply_cli_overrides,
    load_config,
)


def _write_config(tmpdir: str, payload) -> str:
    path = os.path.join(tmpdir, "config.json")
    with open(path, "w", encoding="utf-8") as handle:
        if isinstance(payload, str):
            handle.write(payload)
        else:
            json.dump(payload, handle)
    return path


def _namespace(**overrides) -> argparse.Namespace:
    """Namespace mimicking main.py's parsed CLI arguments."""
    base = {
        "config": None,
        "flows_output": None,
        "tcp_timeout": None,
        "udp_timeout": None,
        "max_active_flows": None,
        "max_decode_size": None,
        "drop_invalid": False,
        "exclude_unknown": False,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


class TestLoadConfig(unittest.TestCase):
    def test_defaults_without_file(self):
        config = load_config()
        self.assertEqual(config.decoder.max_decode_size, DEFAULT_MAX_DECODE_SIZE)
        self.assertTrue(config.decoder.decode_html_entities)
        self.assertTrue(config.decoder.decode_form_urlencoded)
        self.assertTrue(config.decoder.decode_mime)
        self.assertFalse(config.preprocessor.drop_invalid)
        self.assertTrue(config.preprocessor.normalize_headers)
        self.assertTrue(config.preprocessor.normalize_domains)
        self.assertTrue(config.preprocessor.normalize_uri)
        self.assertEqual(config.flow.tcp_idle_timeout, DEFAULT_TCP_IDLE_TIMEOUT)
        self.assertEqual(config.flow.udp_idle_timeout, DEFAULT_UDP_IDLE_TIMEOUT)
        self.assertEqual(config.flow.max_active_flows, DEFAULT_MAX_ACTIVE_FLOWS)
        self.assertTrue(config.flow.flush_on_eof)
        self.assertTrue(config.pipeline.include_unknown)

    def test_file_overrides_partial_section(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_config(tmpdir, {
                "flow": {"tcp_idle_timeout": 5, "max_active_flows": 3},
                "preprocessor": {"drop_invalid": True},
            })
            config = load_config(path)

        self.assertEqual(config.flow.tcp_idle_timeout, 5.0)
        self.assertEqual(config.flow.max_active_flows, 3)
        self.assertTrue(config.preprocessor.drop_invalid)
        # Untouched keys keep their defaults.
        self.assertEqual(config.flow.udp_idle_timeout, DEFAULT_UDP_IDLE_TIMEOUT)
        self.assertTrue(config.preprocessor.normalize_headers)

    def test_unknown_section_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_config(tmpdir, {"decoder": {}, "detector": {}})
            with self.assertRaises(ValueError) as ctx:
                load_config(path)
        self.assertIn("detector", str(ctx.exception))

    def test_unknown_key_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_config(tmpdir, {"flow": {"tcp_idle_timeout": 1.0, "idle_timeout": 2.0}})
            with self.assertRaises(ValueError) as ctx:
                load_config(path)
        self.assertIn("flow.idle_timeout", str(ctx.exception))

    def test_wrong_type_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_config(tmpdir, {"decoder": {"max_decode_size": "big"}})
            with self.assertRaises(ValueError) as ctx:
                load_config(path)
        self.assertIn("decoder.max_decode_size", str(ctx.exception))

    def test_out_of_range_value_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_config(tmpdir, {"flow": {"tcp_idle_timeout": -1}})
            with self.assertRaises(ValueError):
                load_config(path)

    def test_invalid_json_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_config(tmpdir, "{not json")
            with self.assertRaises(ValueError):
                load_config(path)

    def test_missing_file_raises(self):
        with self.assertRaises(ValueError):
            load_config("/nonexistent/path/config.json")


class TestApplyCliOverrides(unittest.TestCase):
    def test_cli_wins_over_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_config(tmpdir, {"flow": {"tcp_idle_timeout": 99.0}})
            config = load_config(path)

        overridden = apply_cli_overrides(config, _namespace(tcp_timeout=1.5))
        self.assertEqual(overridden.flow.tcp_idle_timeout, 1.5)
        # Original configuration is not mutated.
        self.assertEqual(config.flow.tcp_idle_timeout, 99.0)

    def test_unset_flags_keep_config(self):
        config = apply_cli_overrides(load_config(), _namespace())
        self.assertEqual(config.flow.tcp_idle_timeout, DEFAULT_TCP_IDLE_TIMEOUT)
        self.assertEqual(config.flow.udp_idle_timeout, DEFAULT_UDP_IDLE_TIMEOUT)
        self.assertEqual(config.flow.max_active_flows, DEFAULT_MAX_ACTIVE_FLOWS)
        self.assertEqual(config.decoder.max_decode_size, DEFAULT_MAX_DECODE_SIZE)
        self.assertTrue(config.pipeline.include_unknown)
        self.assertFalse(config.preprocessor.drop_invalid)

    def test_zero_max_decode_size_is_kept(self):
        config = apply_cli_overrides(load_config(), _namespace(max_decode_size=0))
        self.assertEqual(config.decoder.max_decode_size, 0)

    def test_boolean_flags_switch_settings(self):
        config = apply_cli_overrides(
            load_config(), _namespace(drop_invalid=True, exclude_unknown=True)
        )
        self.assertTrue(config.preprocessor.drop_invalid)
        self.assertFalse(config.pipeline.include_unknown)

    def test_invalid_numeric_override_raises(self):
        with self.assertRaises(ValueError):
            apply_cli_overrides(load_config(), _namespace(tcp_timeout=-2.0))
        with self.assertRaises(ValueError):
            apply_cli_overrides(load_config(), _namespace(max_active_flows=0))

    def test_nested_dataclasses_stay_independent(self):
        base = IDSConfig()
        other = IDSConfig()
        other.decoder.max_decode_size = 7
        self.assertEqual(base.decoder.max_decode_size, DEFAULT_MAX_DECODE_SIZE)

    def test_dataclass_defaults_are_independent_instances(self):
        first = IDSConfig()
        second = IDSConfig()
        self.assertIsNot(first.decoder, second.decoder)
        self.assertIsNot(first.flow, second.flow)
        self.assertEqual(DecoderConfig().decode_mime, True)
        self.assertEqual(PreprocessorConfig().drop_invalid, False)
        self.assertEqual(FlowConfig().max_active_flows, DEFAULT_MAX_ACTIVE_FLOWS)
        self.assertEqual(PipelineConfig().include_unknown, True)


if __name__ == "__main__":
    unittest.main()
