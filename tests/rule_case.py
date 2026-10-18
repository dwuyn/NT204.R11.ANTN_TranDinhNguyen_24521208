"""Dump rule loading + indexer results for a rules-only BT3 test case.

Used by ``tests/run_case.py`` for cases with ``kind = "rules"``: loads the rule
file with ``RuleLoader``, builds a ``RuleRepository``, evaluates optional
candidate probes, and writes one JSON document to ``result.json`` so the case
runner can assert against it.

Usage:
    python tests/rule_case.py <rules_path> <result_path> [probes_json] [loader_json]

probes_json:  JSON list of candidate queries, each with keys
              protocol/src_ip/src_port/dst_ip/dst_port.
loader_json:  JSON object with optional disabled_sids / disabled_files.
"""

import json
import sys

from core.indexer import RuleRepository
from core.loader import RuleLoader


def main() -> int:
    rules_path, result_path = sys.argv[1], sys.argv[2]
    probes = json.loads(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else []
    loader_options = json.loads(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else {}

    loader = RuleLoader(
        disabled_sids=loader_options.get("disabled_sids"),
        disabled_files=loader_options.get("disabled_files"),
    )
    load_result = loader.load_files([rules_path])

    repository = RuleRepository()
    for rule in load_result.valid:
        repository.add(rule)

    data = load_result.to_dict()
    data["candidates"] = []
    for probe in probes:
        sids = [
            rule.sid
            for rule in repository.candidates(
                protocol=probe["protocol"],
                src_ip=probe["src_ip"],
                src_port=probe["src_port"],
                dst_ip=probe["dst_ip"],
                dst_port=probe["dst_port"],
            )
        ]
        data["candidates"].append({
            "query": probe,
            "sids": sids,
            "sids_str": ",".join(str(sid) for sid in sids),
        })

    with open(result_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)

    print(
        f"[+] {rules_path}: valid={len(load_result.valid)} "
        f"invalid={len(load_result.invalid)} unsupported={len(load_result.unsupported)} "
        f"probes={len(probes)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
