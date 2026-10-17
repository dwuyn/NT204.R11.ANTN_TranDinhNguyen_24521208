"""Rule Matching Engine (module 4.4 của đề bài).

Trả lời một rule có thỏa mãn ``NormalizedEvent + Flow Context`` hay không:

    - Header:  protocol, src/dst IP (any/IPv4/CIDR), src/dst port (any/single/
      range), chiều ``->`` (một chiều như viết) và ``<>`` (một trong hai chiều).
    - Flow/State: dùng FlowRef của Flow Tracker để kiểm tra to_server/
      to_client và established/not_established.
    - Packet/TCP: cờ TCP (``flags``) và kích thước payload (``dsize``).
    - Content: tìm trong raw transport payload (application data trên đường
      truyền) với ``nocase`` (không phân biệt hoa thường ASCII) và các giới
      hạn vị trí ``offset/depth`` (tuyệt đối) hoặc ``distance/within``
      (tương đối sau match trước đó).

Kết quả: ``MATCH`` (MatchResult kèm vị trí từng content khớp) hoặc
``NO_MATCH`` (None). Matching Engine không in cảnh báo — việc sinh Detection
Event thuộc ``core.detection``.
"""

import string
from typing import List, Optional

from core.models import ContentMatch, ContentOption, MatchResult, Rule
from flow.models import (
    DIRECTION_BACKWARD,
    DIRECTION_FORWARD,
    STATE_CLOSING,
    STATE_ESTABLISHED,
)
from parsers.models import FlowRef, NormalizedEvent

# Bảng hạ chữ thường ASCII-only (giống Snort); byte >= 0x80 giữ nguyên.
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)

# Các state được coi là "established" theo Flow Tracker của bài tập.
_ESTABLISHED_STATES = (STATE_ESTABLISHED, STATE_CLOSING)


class RuleMatcher:
    """So khớp một rule đã validate với một event."""

    @classmethod
    def match(
        cls,
        rule: Rule,
        event: NormalizedEvent,
        payload: bytes = b"",
    ) -> Optional[MatchResult]:
        """Trả MatchResult nếu rule khớp event, ngược lại None."""
        network = event.network
        transport = event.transport
        if network is None or transport is None:
            return None

        protocol = str(transport.layer).strip().upper()
        if protocol != rule.header.protocol.upper():
            return None

        if not cls._header_matches(
            rule,
            src_ip=network.src_ip,
            src_port=transport.src_port,
            dst_ip=network.dst_ip,
            dst_port=transport.dst_port,
        ):
            return None

        if not cls._flow_matches(rule, event.flow):
            return None

        if rule.flags is not None and not rule.flags.matches(transport.flags):
            return None

        if rule.dsize is not None and not rule.dsize.matches(transport.payload_len or 0):
            return None

        buffer = payload.decode("latin-1") if payload else ""
        contents = cls._match_contents(rule.contents, buffer)
        if contents is None:
            return None

        fields: List[str] = []
        if rule.flow:
            fields.append("flow:" + ",".join(rule.flow))
        if rule.flags is not None:
            fields.append("flags:" + rule.flags.flags)
        if rule.dsize is not None:
            fields.append("dsize:" + rule.dsize.text)

        return MatchResult(rule=rule, contents=contents, fields=fields)

    # ------------------------------------------------------------------
    # Từng nhóm kiểm tra
    # ------------------------------------------------------------------

    @staticmethod
    def _header_matches(rule: Rule, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bool:
        header = rule.header
        direct = (
            header.src_ip.contains(src_ip)
            and header.dst_ip.contains(dst_ip)
            and header.src_port.contains(src_port)
            and header.dst_port.contains(dst_port)
        )
        if direct:
            return True
        if header.direction == "<>":
            return (
                header.src_ip.contains(dst_ip)
                and header.dst_ip.contains(src_ip)
                and header.src_port.contains(dst_port)
                and header.dst_port.contains(src_port)
            )
        return False

    @staticmethod
    def _flow_matches(rule: Rule, flow_ref: Optional[FlowRef]) -> bool:
        """Kiểm tra flow:to_server/to_client/established/not_established."""
        if not rule.flow:
            return True
        if flow_ref is None:
            # Không có flow context thì không thể xác định trạng thái/chiều.
            return False

        direction = flow_ref.direction
        established = flow_ref.state in _ESTABLISHED_STATES

        for token in rule.flow:
            if token == "to_server" and direction != DIRECTION_FORWARD:
                return False
            if token == "to_client" and direction != DIRECTION_BACKWARD:
                return False
            if token == "established" and not established:
                return False
            if token == "not_established" and established:
                return False
        return True

    @staticmethod
    def _match_contents(contents: List[ContentOption], buffer: str) -> Optional[List[ContentMatch]]:
        """So khớp chuỗi content theo thứ tự; None nếu có content không khớp.

        ``offset/depth`` là cửa sổ tuyệt đối trên payload; ``distance/within``
        là cửa sổ tương đối tính từ vị trí kết thúc của content khớp trước đó
        (đúng ngữ nghĩa Snort: modifier tương đối thay thế modifier tuyệt đối).
        """
        matches: List[ContentMatch] = []
        lowered_buffer = buffer.translate(_ASCII_LOWER)
        previous_end = 0

        for option in contents:
            haystack = buffer
            pattern = option.content
            if option.nocase:
                haystack = lowered_buffer
                pattern = pattern.translate(_ASCII_LOWER)

            if option.distance is not None or option.within is not None:
                start = previous_end + (option.distance or 0)
                if option.within is not None:
                    end = start + option.within
                else:
                    end = len(buffer)
            else:
                start = option.offset or 0
                end = start + option.depth if option.depth is not None else len(buffer)

            start = max(start, 0)
            end = min(end, len(buffer))
            if start > end:
                return None

            position = haystack.find(pattern, start, end)
            if position == -1:
                return None

            previous_end = position + len(pattern)
            matches.append(
                ContentMatch(
                    content=option.content,
                    offset=position,
                    length=len(pattern),
                    nocase=option.nocase,
                )
            )
        return matches
