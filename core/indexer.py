"""Rule Repository / Indexer (module 4.3 của đề bài).

Lưu các rule đã validate và tạo chỉ mục theo protocol + port để chọn nhanh
tập candidate rules cho một event, tránh duyệt toàn bộ rule:

    - rule có cả hai vế port ``any``  -> bucket "any port" của protocol;
    - rule có port đơn               -> bucket ``(protocol, vai trò, port)``;
    - rule có dải/khoảng mở port     -> danh sách range nhỏ của protocol
      (chỉ duyệt danh sách này khi event có port nằm trong dải).

Sau bước chọn theo chỉ mục, candidate được lọc thêm bằng phép kiểm tra
orientation đầy đủ (IP + port, có xét chiều ``<>``) để tập kết quả chính xác.
"""

from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.models import DIRECTION_BIDI, Rule


class RuleRepository:
    """Kho rule + chỉ mục candidate theo protocol/port."""

    def __init__(self) -> None:
        self._rules: List[Rule] = []
        self._by_sid: Dict[int, Rule] = {}
        self._exact: Dict[Tuple[str, str, int], List[Rule]] = {}
        self._ranges: Dict[str, List[Rule]] = {}
        self._any_port: Dict[str, List[Rule]] = {}

    # ------------------------------------------------------------------
    # Nạp rule
    # ------------------------------------------------------------------

    def add(self, rule: Rule) -> None:
        """Thêm một rule valid vào kho và cập nhật chỉ mục."""
        self._rules.append(rule)
        self._by_sid[rule.sid] = rule

        header = rule.header
        proto = header.protocol

        if header.src_port.any and header.dst_port.any:
            self._append_unique(self._any_port.setdefault(proto, []), rule)

        has_range = False
        for role, spec in (("src", header.src_port), ("dst", header.dst_port)):
            if spec.any:
                continue
            if spec.lo is not None and spec.lo == spec.hi:
                keys = [(proto, role, spec.lo)]
                if header.direction == DIRECTION_BIDI:
                    # Rule hai chiều cũng khớp khi port xuất hiện ở vế đối diện.
                    opposite = "dst" if role == "src" else "src"
                    keys.append((proto, opposite, spec.lo))
                for key in keys:
                    self._append_unique(self._exact.setdefault(key, []), rule)
            else:
                has_range = True

        if has_range:
            self._append_unique(self._ranges.setdefault(proto, []), rule)

    def add_many(self, rules: Iterable[Rule]) -> None:
        for rule in rules:
            self.add(rule)

    @staticmethod
    def _append_unique(bucket: List[Rule], rule: Rule) -> None:
        if not any(existing is rule for existing in bucket):
            bucket.append(rule)

    # ------------------------------------------------------------------
    # Truy vấn
    # ------------------------------------------------------------------

    def candidates(
        self,
        protocol: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> List[Rule]:
        """Trả về candidate rules (đã sắp theo sid) cho một event."""
        proto = str(protocol).strip().lower()

        collected: List[Rule] = []
        seen: set = set()

        def pull(rules: Iterable[Rule]) -> None:
            for rule in rules:
                if id(rule) not in seen:
                    seen.add(id(rule))
                    collected.append(rule)

        pull(self._any_port.get(proto, ()))
        pull(self._exact.get((proto, "src", src_port), ()))
        pull(self._exact.get((proto, "dst", dst_port), ()))
        for rule in self._ranges.get(proto, ()):
            if _orientation_ok(rule, src_ip, src_port, dst_ip, dst_port):
                pull([rule])

        candidates = [
            rule
            for rule in collected
            if _orientation_ok(rule, src_ip, src_port, dst_ip, dst_port)
        ]
        candidates.sort(key=lambda rule: rule.sid)
        return candidates

    def get(self, sid: int) -> Optional[Rule]:
        return self._by_sid.get(int(sid))

    @property
    def rules(self) -> List[Rule]:
        return list(self._rules)

    def stats(self) -> Dict[str, Any]:
        protocols: Dict[str, int] = {}
        for rule in self._rules:
            protocols[rule.header.protocol] = protocols.get(rule.header.protocol, 0) + 1
        return {
            "rules": len(self._rules),
            "protocols": protocols,
            "exact_port_buckets": len(self._exact),
            "range_buckets": {proto: len(rules) for proto, rules in self._ranges.items()},
            "any_port_buckets": {proto: len(rules) for proto, rules in self._any_port.items()},
        }

    def __len__(self) -> int:
        return len(self._rules)


def _orientation_ok(
    rule: Rule, src_ip: str, src_port: int, dst_ip: str, dst_port: int
) -> bool:
    """Kiểm tra nhanh rule header khớp hướng packet (IP + port, xét chiều)."""
    header = rule.header
    direct = (
        header.src_ip.contains(src_ip)
        and header.dst_ip.contains(dst_ip)
        and header.src_port.contains(src_port)
        and header.dst_port.contains(dst_port)
    )
    if direct:
        return True
    if header.direction == DIRECTION_BIDI:
        return (
            header.src_ip.contains(dst_ip)
            and header.dst_ip.contains(src_ip)
            and header.src_port.contains(dst_port)
            and header.dst_port.contains(src_port)
        )
    return False
