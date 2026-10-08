"""Decoder package: payload decoding for IDS events.

Turns raw transport payload bytes into normalized, decoded text fields
(percent/URL encoding, form-urlencoded bodies, HTML entities, MIME transfer
encodings, character decoding) without ever raising on malformed input.
"""

from decoder.decoder import Decoder

__all__ = ["Decoder"]
