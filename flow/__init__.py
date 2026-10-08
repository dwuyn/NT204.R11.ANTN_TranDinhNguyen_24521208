"""Flow tracker package: bidirectional connection tracking for IDS events.

Groups packets into bidirectional 5-tuple flows, tracks TCP state transitions
and UDP idle timeouts, and produces per-flow statistics records.
"""

from flow.models import Flow, FlowCounters
from flow.tracker import FlowTracker

__all__ = ["Flow", "FlowCounters", "FlowTracker"]
