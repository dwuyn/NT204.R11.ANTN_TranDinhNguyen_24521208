"""Rule Loader (module 4.1 của đề bài).

Đọc một hoặc nhiều file ``.rules``, bỏ qua dòng trống/comment, chuyển từng
dòng rule cho Rule Parser & Validator, và cho phép enable/disable rule (theo
``sid``) hoặc disable cả file rule bằng cấu hình.

Lỗi của một rule hoặc một file **không** làm dừng việc nạp: mọi vấn đề được
ghi lại dưới dạng warning kèm ``file:line`` để báo cáo trong quá trình nạp.
"""

from dataclasses import dataclass, field
import os
import re
from typing import Any, Dict, Iterable, List, Optional

from core.models import (
    STATUS_INVALID,
    STATUS_UNSUPPORTED,
    STATUS_VALID,
    Rule,
)
from core.parser import RuleParser

# Snort cho phép `include <file|$VAR>`; ngoài phạm vi bài tập nên được bỏ qua
# kèm warning thay vì đẩy sang parser và báo lỗi cú pháp.
_INCLUDE_RE = re.compile(r"^include\b", re.IGNORECASE)


@dataclass
class LoadResult:
    """Kết quả nạp rule: rule hợp lệ + invalid/unsupported + warning."""
    valid: List[Rule] = field(default_factory=list)
    invalid: List[Any] = field(default_factory=list)
    unsupported: List[Any] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    disabled_rules: List[int] = field(default_factory=list)
    disabled_files: List[str] = field(default_factory=list)

    def stats(self) -> Dict[str, int]:
        return {
            "files_loaded": len(self.files),
            "valid": len(self.valid),
            "invalid": len(self.invalid),
            "unsupported": len(self.unsupported),
            "disabled_rules": len(self.disabled_rules),
            "disabled_files": len(self.disabled_files),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files": list(self.files),
            "stats": self.stats(),
            "valid": [rule.to_dict() for rule in self.valid],
            "invalid": [outcome.to_dict() for outcome in self.invalid],
            "unsupported": [outcome.to_dict() for outcome in self.unsupported],
            "disabled_rules": list(self.disabled_rules),
            "disabled_files": list(self.disabled_files),
            "warnings": list(self.warnings),
        }


class RuleLoader:
    """Nạp rule từ các file ``.rules`` theo chính sách enable/disable."""

    def __init__(
        self,
        disabled_sids: Optional[Iterable[int]] = None,
        disabled_files: Optional[Iterable[str]] = None,
    ) -> None:
        self._disabled_sids = {int(sid) for sid in (disabled_sids or [])}
        self._disabled_files = {str(name) for name in (disabled_files or [])}

    def load_files(self, paths: Iterable[str]) -> LoadResult:
        """Nạp toàn bộ ``paths``; không raise khi file lỗi/rule lỗi."""
        result = LoadResult()
        for path in paths:
            self._load_one(str(path), result)
        return result

    # ------------------------------------------------------------------

    def _load_one(self, path: str, result: LoadResult) -> None:
        if path in self._disabled_files or os.path.basename(path) in self._disabled_files:
            result.disabled_files.append(path)
            result.warnings.append(f"rule file disabled by config: {path}")
            return

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
        except OSError as exc:
            result.warnings.append(f"cannot read rule file: {path}: {exc}")
            return

        result.files.append(path)
        seen_sids = {rule.sid for rule in result.valid}

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if _INCLUDE_RE.match(stripped):
                result.warnings.append(
                    f"unsupported include directive at {path}:{line_no}: {stripped}"
                )
                continue

            outcome = RuleParser.parse(stripped, rule_file=path, line_no=line_no)

            if outcome.status == STATUS_UNSUPPORTED:
                result.unsupported.append(outcome)
                result.warnings.append(
                    f"unsupported rule at {path}:{line_no}: {outcome.reason}"
                )
                continue

            if outcome.status == STATUS_INVALID:
                result.invalid.append(outcome)
                result.warnings.append(
                    f"invalid rule at {path}:{line_no}: {outcome.reason}"
                )
                continue

            if outcome.status != STATUS_VALID:
                continue

            rule = outcome.rule
            if rule.sid in self._disabled_sids:
                result.disabled_rules.append(rule.sid)
                result.warnings.append(
                    f"rule disabled by config: sid={rule.sid} ({path}:{line_no})"
                )
                continue
            if rule.sid in seen_sids:
                result.warnings.append(
                    f"duplicate sid ignored: sid={rule.sid} ({path}:{line_no})"
                )
                continue
            seen_sids.add(rule.sid)
            result.valid.append(rule)
