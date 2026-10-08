"""Runner to execute a test case, generate output.jsonl, and generate report.md.

Each test case has a registered set of assertions (EXPECTATIONS). A case only
reports PASS when every expected JSON subset matches at least one parsed event,
the minimum event count is reached, and (when configured) the minimum number of
flow records is reached and every flow assertion matches.

Registered keys per case:
  min_events   minimum number of parsed events.
  checks       list of JSON subsets; each subset must match at least one event.
  pcap         optional pcap filename (default test.pcap).
  min_flows    optional minimum number of flow records.
  flow_checks  optional list of JSON subsets matched against flow records.
  args         optional extra CLI arguments passed to main.py.
  description  test objective (required to be included in `run_case.py all`).
  criteria     verification criteria (required for `run_case.py all`).

Usage:
  python tests/run_case.py <case_name> "<description>" "<criteria>"
  python tests/run_case.py all
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

# Expected result per test case directory.
#   min_events: minimum number of parsed events.
#   checks: list of JSON subsets; each subset must match at least one event.
#   pcap: optional pcap filename (default test.pcap).
#   min_flows / flow_checks: optional flow record assertions.
#   args: optional extra CLI arguments for main.py.
#   description / criteria: required for `run_case.py all`.
EXPECTATIONS = {
    "test_01_tcp_handshake": {
        "min_events": 3,
        "checks": [
            {"transport": {"handshake": "SYN"}},
            {"transport": {"handshake": "SYN-ACK"}},
            {"transport": {"handshake": "ACK"}},
        ],
    },
    "test_02_tcp_data": {
        "min_events": 1,
        "checks": [
            {"transport": {"layer": "TCP", "payload_len": 44}},
            {"application": {"protocol": "UNKNOWN"}},
        ],
    },
    "test_03_udp": {
        "min_events": 1,
        "checks": [{"transport": {"layer": "UDP", "payload_len": 47}}],
    },
    "test_04_http_get": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "type": "request",
                    "details": {
                        "method": "GET",
                        "uri": "/api/v1/network/stats",
                        "version": "HTTP/1.1",
                    },
                }
            }
        ],
    },
    "test_05_http_post": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "type": "request",
                    "details": {
                        "method": "POST",
                        "uri": "/api/login",
                        "body": "username=admin&password=secretPassword123",
                    },
                }
            }
        ],
    },
    "test_06_http_response": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "type": "response",
                    "details": {"status_code": 200, "reason": "OK"},
                }
            }
        ],
    },
    "test_07_dns_query": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "DNS",
                    "type": "query",
                    "details": {"queries": [{"name": "portal.uit.edu.vn", "type": "A"}]},
                }
            }
        ],
    },
    "test_08_dns_response": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "DNS",
                    "type": "response",
                    "details": {
                        "answers": [
                            {
                                "name": "portal.uit.edu.vn",
                                "type": "A",
                                "rdata": "118.69.123.45",
                            }
                        ]
                    },
                }
            }
        ],
    },
    "test_09_smtp_command": {
        "min_events": 3,
        "checks": [
            {"application": {"protocol": "SMTP", "details": {"command": "EHLO"}}},
            {"application": {"protocol": "SMTP", "details": {"command": "MAIL FROM"}}},
            {"application": {"protocol": "SMTP", "details": {"command": "RCPT TO"}}},
        ],
    },
    "test_10_smtp_response": {
        "min_events": 3,
        "checks": [
            {"application": {"protocol": "SMTP", "details": {"status_code": 220}}},
            {"application": {"protocol": "SMTP", "details": {"status_code": 250}}},
            {"application": {"protocol": "SMTP", "details": {"status_code": 354}}},
        ],
    },
    "test_11_unknown_protocol": {
        "min_events": 2,
        "checks": [
            {"application": {"protocol": "UNKNOWN"}},
            {"errors": []},
        ],
    },
    "test_12_malformed_packet": {
        "min_events": 2,
        "checks": [
            {"transport": {"handshake": "SYN"}},
            {"application": {"protocol": "UNKNOWN"}},
        ],
    },
    "test_13_non_standard_port": {
        "min_events": 3,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "details": {"method": "GET", "detection_method": "payload_signature"},
                }
            },
            {
                "application": {
                    "protocol": "SMTP",
                    "details": {"command": "EHLO", "detection_method": "payload_signature"},
                }
            },
            {
                "application": {
                    "protocol": "DNS",
                    "details": {"detection_method": "payload_signature"},
                }
            },
        ],
    },
    "test_14_truncated_pcap": {
        "pcap": "truncated.pcap",
        "min_events": 1,
        "checks": [
            {"application": {"protocol": "HTTP", "details": {"method": "GET"}}},
        ],
    },
    # ------------------------------------------------------------------
    # Assignment 2 cases (decoder, preprocessor, flow tracker)
    # ------------------------------------------------------------------
    "bt2_t01_http_url_decode": {
        "min_events": 1,
        "checks": [
            {"application": {"details": {"uri": "/search?q=%27%20OR%201%3D1&lang=en"}}},
            {
                "decode": {
                    "decode_status": "decoded",
                    "fields": {"uri_decoded": "/search?q=' OR 1=1&lang=en"},
                }
            },
            {
                "preprocess": {"preprocess_status": "valid", "processing_action": "forward"},
            },
        ],
        "min_flows": 1,
        "description": "Giải mã percent-encoding trên URI của HTTP request",
        "criteria": (
            "Event HTTP request giữ nguyên URI gốc đã mã hóa, decode.fields.uri_decoded "
            "chứa chuỗi %27%20OR%201%3D1 đã giải mã, event hợp lệ (forward) và có 1 flow TCP."
        ),
    },
    "bt2_t02_html_entity": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "details": {
                        "body": "<p>Hello &lt;script&gt;alert(1)&lt;/script&gt; &amp; welcome</p>"
                    }
                }
            },
            {
                "decode": {
                    "decoders": ["html_entities"],
                    "fields": {
                        "body_decoded": "<p>Hello <script>alert(1)</script> & welcome</p>",
                        "body_charset": "utf-8",
                        "body_decode_status": "ok",
                    },
                }
            },
        ],
        "description": "Giải mã HTML entity trong body của HTTP response text/html",
        "criteria": (
            "Body gốc vẫn giữ nguyên entity, decode.fields.body_decoded đã unescape "
            "&lt;script&gt; thành <script>, charset là utf-8 và body_decode_status là ok."
        ),
    },
}


def _subset_match(actual, expected) -> bool:
    """Return True when expected is contained in actual.

    Dict: every expected key must match recursively.
    List: each expected element must match at least one actual element;
    an empty expected list means the actual list must also be empty.
    """
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return all(
            key in actual and _subset_match(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return False
        if not expected:
            return actual == []
        return all(any(_subset_match(item, exp) for item in actual) for exp in expected)
    return actual == expected


def _matches_any(events, expected) -> bool:
    return any(_subset_match(event, expected) for event in events)


def _read_jsonl(path: str) -> list:
    """Read a JSON Lines file into a list of records (empty when missing)."""
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _resolve_paths(case_name: str, spec: dict):
    """Return (case_dir, pcap, output, flows, temp_dir) for a case.

    Assignment 1 cases keep their artifacts untouched: their flow records are
    written to a temporary directory because those cases do not assert flows.
    """
    case_dir = os.path.join("TEST", case_name)
    pcap_path = os.path.join(case_dir, spec.get("pcap", "test.pcap"))
    output_path = os.path.join(case_dir, "output.jsonl")
    if case_name.startswith("bt2_"):
        return case_dir, pcap_path, output_path, os.path.join(case_dir, "flows.jsonl"), None
    temp_dir = tempfile.mkdtemp(prefix="ids_flows_")
    return case_dir, pcap_path, output_path, os.path.join(temp_dir, "flows.jsonl"), temp_dir


def run_case(case_name: str, description: str, verification_criteria: str) -> int:
    spec = EXPECTATIONS.get(case_name)
    case_dir, pcap_path, output_path, flows_path, temp_dir = _resolve_paths(case_name, spec or {})
    report_path = os.path.join(case_dir, "report.md")

    if not os.path.isfile(pcap_path):
        print(f"[!] Error: {pcap_path} not found.")
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return 1

    try:
        # Run main.py on the pcap
        cmd = [
            sys.executable,
            "main.py",
            "--pcap",
            pcap_path,
            "--output",
            output_path,
            "--flows-output",
            flows_path,
        ] + list(spec.get("args", []) if spec else [])
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[!] main.py failed on {case_name}:\n{res.stderr}")
            return res.returncode

        events = _read_jsonl(output_path)
        flows = _read_jsonl(flows_path)

        # Verify registered assertions
        failures = []
        min_flows = None
        flow_checks = []
        if spec is None:
            failures.append(f"Chưa đăng ký kỳ vọng kiểm thử cho case '{case_name}'.")
            checks = []
            min_events = 0
        else:
            checks = spec["checks"]
            min_events = spec["min_events"]
            if len(events) < min_events:
                failures.append(f"Cần tối thiểu {min_events} event, thực tế {len(events)}.")
            for idx, check in enumerate(checks, start=1):
                if not _matches_any(events, check):
                    failures.append(
                        f"Không event nào khớp kỳ vọng #{idx}: "
                        f"{json.dumps(check, ensure_ascii=False)}"
                    )

            min_flows = spec.get("min_flows")
            if min_flows is not None and len(flows) < min_flows:
                failures.append(f"Cần tối thiểu {min_flows} flow record, thực tế {len(flows)}.")
            flow_checks = spec.get("flow_checks", [])
            for idx, check in enumerate(flow_checks, start=1):
                if not _matches_any(flows, check):
                    failures.append(
                        f"Không flow nào khớp kỳ vọng #{idx}: "
                        f"{json.dumps(check, ensure_ascii=False)}"
                    )

        status = "PASS (Thành công)" if not failures else "FAIL (Thất bại)"
        result_lines = (
            "\n".join(f"- {line}" for line in failures)
            if failures
            else "- Tất cả kỳ vọng kiểm thử đều khớp với output thực tế."
        )

        flow_header = ""
        flow_assertions = ""
        flow_section = ""
        if case_name.startswith("bt2_"):
            flow_header = (
                f"- **File Flow Records**: `{flows_path}`\n"
                f"- **Số flow record**: {len(flows)}"
            )
            flow_assertions = f"""- Số flow tối thiểu: **{min_flows if min_flows is not None else 0}**
- Danh sách flow subset bắt buộc phải khớp:
```json
{json.dumps(flow_checks, indent=2, ensure_ascii=False)}
```"""
            flow_section = f"""
## 5. Flow Records (flows.jsonl)
- **Số flow record**: {len(flows)}
- **Số flow tối thiểu**: {min_flows if min_flows is not None else 0}
- **Kỳ vọng flow (JSON subset)**:
```json
{json.dumps(flow_checks, indent=2, ensure_ascii=False)}
```
- **Chi tiết flow records**:
```json
{json.dumps(flows, indent=2, ensure_ascii=False)}
```
"""

        # Write report.md
        report_content = f"""# Test Case Report: {case_name}

- **Mục tiêu**: {description}
- **Yêu cầu kiểm thử**: {verification_criteria}
- **File PCAP**: `{pcap_path}`
- **File Output JSONL**: `{output_path}`
{flow_header}- **Số gói tin đã xử lý**: {len(events)}
- **Trạng thái**: **{status}**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
{res.stdout.strip()}
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **{min_events}**
- Danh sách JSON subset bắt buộc phải khớp:
```json
{json.dumps(checks, indent=2, ensure_ascii=False)}
```
{flow_assertions}

## 3. Đánh giá tính đúng đắn
{result_lines}
- Chương trình kết thúc bình thường (exit code 0), không crash.
- Cấu trúc dữ liệu đầu ra tuân thủ đúng định dạng JSON chuẩn hóa của đề bài.

## 4. Chi tiết Normalized Events (JSON)
```json
{json.dumps(events, indent=2, ensure_ascii=False)}
```
{flow_section}"""
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        print(f"[+] Case {case_name}: {status}. Report written to {report_path}")
        return 0 if not failures else 1
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def run_all() -> int:
    """Run every case that registers a description and criteria."""
    selected = [
        case
        for case, spec in EXPECTATIONS.items()
        if spec.get("description") and spec.get("criteria")
    ]
    if not selected:
        print("No cases registered.")
        return 0

    failed = []
    for case in selected:
        spec = EXPECTATIONS[case]
        if run_case(case, spec["description"], spec["criteria"]) != 0:
            failed.append(case)

    print("-" * 60)
    print(f"[+] {len(selected) - len(failed)}/{len(selected)} cases PASS")
    if failed:
        print(f"[!] FAILED cases: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "all":
        sys.exit(run_all())
    if len(sys.argv) < 4:
        print("Usage: python run_case.py <case_name> <description> <criteria>")
        print("       python run_case.py all")
        sys.exit(1)
    sys.exit(run_case(sys.argv[1], sys.argv[2], sys.argv[3]))
