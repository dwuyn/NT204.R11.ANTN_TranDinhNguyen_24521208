"""Preprocessor package: validation and normalization of parsed IDS events.

Assigns ``preprocess_status`` (valid/partial/invalid), ``processing_action``
(forward/dropped) and a ``reason`` to every event, and normalizes protocol
names, IP addresses, HTTP header names, domains and URI paths so that later
stages (flow tracker, feature extractor) see consistent values.
"""

from preprocessor.preprocessor import Preprocessor

__all__ = ["Preprocessor"]
