"""Configuration management for the IDS pipeline.

Centralizes decoder, preprocessor, flow tracker and pipeline settings so that
timeouts, size limits and packet-handling policies can be tuned through a JSON
file and/or command line flags without touching code.

Precedence: built-in defaults < ``--config`` JSON file < CLI overrides.
"""

from dataclasses import dataclass, field, replace
import json
from typing import Any, Dict, Optional, Union

DEFAULT_MAX_DECODE_SIZE = 1048576
DEFAULT_TCP_IDLE_TIMEOUT = 120.0
DEFAULT_UDP_IDLE_TIMEOUT = 30.0
DEFAULT_MAX_ACTIVE_FLOWS = 10000


@dataclass
class DecoderConfig:
    """Settings for the decoder stage (percent/HTML/MIME/character decoding)."""
    max_decode_size: int = DEFAULT_MAX_DECODE_SIZE
    decode_html_entities: bool = True
    decode_form_urlencoded: bool = True
    decode_mime: bool = True


@dataclass
class PreprocessorConfig:
    """Settings for the preprocessor stage (validation + normalization policy)."""
    drop_invalid: bool = False
    normalize_headers: bool = True
    normalize_domains: bool = True
    normalize_uri: bool = True


@dataclass
class FlowConfig:
    """Settings for the flow/connection tracker."""
    tcp_idle_timeout: float = DEFAULT_TCP_IDLE_TIMEOUT
    udp_idle_timeout: float = DEFAULT_UDP_IDLE_TIMEOUT
    max_active_flows: int = DEFAULT_MAX_ACTIVE_FLOWS
    flush_on_eof: bool = True


@dataclass
class PipelineConfig:
    """Settings for the parsing pipeline."""
    include_unknown: bool = True


@dataclass
class IDSConfig:
    """Full IDS configuration (defaults are safe for a stock run)."""
    decoder: DecoderConfig = field(default_factory=DecoderConfig)
    preprocessor: PreprocessorConfig = field(default_factory=PreprocessorConfig)
    flow: FlowConfig = field(default_factory=FlowConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)


# JSON section -> {key: expected type}. A value of (int, float) accepts either
# numeric type (but never bool, which is a subclass of int in Python).
_SECTION_TYPES: Dict[str, Dict[str, Any]] = {
    "decoder": {
        "max_decode_size": int,
        "decode_html_entities": bool,
        "decode_form_urlencoded": bool,
        "decode_mime": bool,
    },
    "preprocessor": {
        "drop_invalid": bool,
        "normalize_headers": bool,
        "normalize_domains": bool,
        "normalize_uri": bool,
    },
    "flow": {
        "tcp_idle_timeout": (int, float),
        "udp_idle_timeout": (int, float),
        "max_active_flows": int,
        "flush_on_eof": bool,
    },
    "pipeline": {
        "include_unknown": bool,
    },
}

_SECTION_CLASSES = {
    "decoder": DecoderConfig,
    "preprocessor": PreprocessorConfig,
    "flow": FlowConfig,
    "pipeline": PipelineConfig,
}


def _validate_type(key: str, value: Any, expected: Any) -> None:
    """Raise ValueError when ``value`` does not match ``expected``."""
    if expected is bool:
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be a boolean, got {type(value).__name__}")
        return
    if expected is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{key} must be an integer, got {type(value).__name__}")
        return
    # Numeric pair (int, float).
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be a number, got {type(value).__name__}")


def _validate_range(key: str, value: Union[int, float]) -> None:
    """Raise ValueError when a numeric setting is outside its sane range."""
    if key == "decoder.max_decode_size" and value < 0:
        raise ValueError(f"{key} must be >= 0, got {value}")
    if key in ("flow.tcp_idle_timeout", "flow.udp_idle_timeout") and value <= 0:
        raise ValueError(f"{key} must be > 0, got {value}")
    if key == "flow.max_active_flows" and value < 1:
        raise ValueError(f"{key} must be >= 1, got {value}")


def _build_section(section: str, values: Any, source: str) -> Any:
    """Validate one JSON section and build its dataclass instance."""
    if not isinstance(values, dict):
        raise ValueError(f"{source}: section '{section}' must be a JSON object")
    expected_types = _SECTION_TYPES[section]
    for key in sorted(values):
        if key not in expected_types:
            raise ValueError(f"{source}: unknown config key '{section}.{key}'")
    for key, value in values.items():
        full_key = f"{section}.{key}"
        _validate_type(full_key, value, expected_types[key])
        if expected_types[key] is not bool:
            _validate_range(full_key, value)
    return _SECTION_CLASSES[section](**values)


def load_config(path: Optional[str] = None) -> IDSConfig:
    """Build an :class:`IDSConfig` from defaults plus an optional JSON file.

    Missing sections/keys keep their default value. Raises ValueError when the
    file is unreadable, is not valid JSON, or contains unknown keys or wrongly
    typed values, so that a bad configuration fails fast instead of silently
    changing detection behaviour.
    """
    config = IDSConfig()
    if path is None:
        return config

    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        raise ValueError(f"config file not found: {path}") from None
    except OSError as exc:
        raise ValueError(f"cannot read config file {path}: {exc}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in config file {path}: {exc}") from None

    if not isinstance(raw, dict):
        raise ValueError(f"config file {path} must contain a JSON object")

    unknown = sorted(set(raw) - set(_SECTION_TYPES))
    if unknown:
        raise ValueError(f"config file {path}: unknown section(s): {', '.join(unknown)}")

    for section, values in raw.items():
        setattr(config, section, _build_section(section, values, f"config file {path}"))
    return config


def apply_cli_overrides(config: IDSConfig, args: Any) -> IDSConfig:
    """Return a copy of ``config`` with command line overrides applied.

    Only flags explicitly provided on the command line win over the file
    defaults; boolean flags only ever switch a setting on. ``args`` is an
    ``argparse.Namespace`` (missing attributes are treated as "not provided").
    """
    decoder = replace(config.decoder)
    preprocessor = replace(config.preprocessor)
    flow = replace(config.flow)
    pipeline = replace(config.pipeline)

    value = getattr(args, "max_decode_size", None)
    if value is not None:
        _validate_type("decoder.max_decode_size", value, int)
        _validate_range("decoder.max_decode_size", value)
        decoder.max_decode_size = value

    value = getattr(args, "tcp_timeout", None)
    if value is not None:
        _validate_range("flow.tcp_idle_timeout", value)
        flow.tcp_idle_timeout = float(value)

    value = getattr(args, "udp_timeout", None)
    if value is not None:
        _validate_range("flow.udp_idle_timeout", value)
        flow.udp_idle_timeout = float(value)

    value = getattr(args, "max_active_flows", None)
    if value is not None:
        _validate_range("flow.max_active_flows", value)
        flow.max_active_flows = value

    if getattr(args, "drop_invalid", False):
        preprocessor.drop_invalid = True
    if getattr(args, "exclude_unknown", False):
        pipeline.include_unknown = False

    return IDSConfig(decoder=decoder, preprocessor=preprocessor, flow=flow, pipeline=pipeline)
