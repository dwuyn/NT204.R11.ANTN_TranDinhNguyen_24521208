"""JSON Lines logger for IDS events."""

import os
from typing import Optional, TextIO
from parsers.models import NormalizedEvent


class JsonLinesLogger:
    """Logs normalized IDS events to a JSON Lines file and/or terminal."""

    def __init__(
        self,
        filepath: Optional[str] = None,
        console_summary: bool = False,
    ) -> None:
        self.filepath = filepath
        self.console_summary = console_summary
        self._file: Optional[TextIO] = None

        if self.filepath:
            os.makedirs(os.path.dirname(os.path.abspath(self.filepath)), exist_ok=True)
            self._file = open(self.filepath, "w", encoding="utf-8")

    def log(self, event: NormalizedEvent) -> None:
        """Write a single event to the JSON Lines file and optionally print summary."""
        if self._file:
            self._file.write(event.to_json() + "\n")
            self._file.flush()

        if self.console_summary:
            print(self.format_summary(event))

    @staticmethod
    def format_summary(event: NormalizedEvent) -> str:
        """Create a compact 1-line readable summary for console logging."""
        net_str = "NoIP"
        if event.network:
            net_str = f"{event.network.src_ip} -> {event.network.dst_ip} ({event.network.proto})"

        trans_str = ""
        if event.transport:
            flags_str = f" [{','.join(event.transport.flags)}]" if event.transport.flags else ""
            trans_str = f":{event.transport.src_port} -> :{event.transport.dst_port}{flags_str}"

        app_str = ""
        if event.application and event.application.protocol != "UNKNOWN":
            app_str = f" | {event.application.protocol}"
            if event.application.type:
                app_str += f" ({event.application.type})"

        return f"[{event.packet_id:04d}] {net_str}{trans_str}{app_str} [len={event.raw_len}]"

    def close(self) -> None:
        """Close the underlying file handle if open."""
        if self._file and not self._file.closed:
            self._file.close()
            self._file = None

    def __enter__(self) -> "JsonLinesLogger":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
