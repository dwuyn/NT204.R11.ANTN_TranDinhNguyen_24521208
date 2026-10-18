"""Rule Evaluation Engine (module 4.5 của đề bài).

Nhận Normalized Event + Flow Context, truy vấn Rule Repository/Indexer để lấy
candidate rules rồi gọi Rule Matching Engine cho từng candidate.

Mặc định **không dừng ở match đầu tiên**: một event có thể khớp nhiều rule và
mọi kết quả match đều sinh Detection Event. Cấu hình ``stop_on_first_match``
có thể bật để dừng sớm (khi đó hành vi này là chủ đích của người cấu hình).

Theo dõi tối thiểu để kiểm tra hiệu năng: số event đã đánh giá, tổng số
candidate rule đã gọi matcher và số lần match.
"""

from typing import Any, Dict, List

from core.detection import DetectionEvent, DetectionEventGenerator
from core.indexer import RuleRepository
from core.matcher import RuleMatcher
from parsers.models import NormalizedEvent


class RuleEvaluationEngine:
    """Đánh giá mọi candidate rule cho từng event và sinh Detection Event."""

    def __init__(
        self,
        repository: RuleRepository,
        stop_on_first_match: bool = False,
    ) -> None:
        self.repository = repository
        self.stop_on_first_match = stop_on_first_match
        self.events_evaluated = 0
        self.candidate_rules = 0
        self.matches = 0

    def evaluate(self, event: NormalizedEvent, payload: bytes = b"") -> List[DetectionEvent]:
        """Trả về danh sách Detection Event cho một event (đã qua flow tracker).

        Event không có tầng network/transport (ví dụ packet ARP) không thể
        đánh giá được nên bị bỏ qua và không tính vào thống kê.
        """
        network = event.network
        transport = event.transport
        if network is None or transport is None:
            return []

        self.events_evaluated += 1
        candidates = self.repository.candidates(
            protocol=str(transport.layer),
            src_ip=network.src_ip,
            src_port=transport.src_port,
            dst_ip=network.dst_ip,
            dst_port=transport.dst_port,
        )
        self.candidate_rules += len(candidates)

        detections: List[DetectionEvent] = []
        for rule in candidates:
            result = RuleMatcher.match(rule, event, payload)
            if result is None:
                continue
            self.matches += 1
            detections.append(DetectionEventGenerator.generate(rule, result, event))
            if self.stop_on_first_match:
                break
        return detections

    def stats(self) -> Dict[str, Any]:
        """Bộ đếm phục vụ kiểm tra hiệu năng / summary cuối run."""
        return {
            "rules_loaded": len(self.repository),
            "events_evaluated": self.events_evaluated,
            "candidate_rules": self.candidate_rules,
            "matches": self.matches,
        }
