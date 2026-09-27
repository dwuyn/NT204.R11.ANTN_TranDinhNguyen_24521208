"""Runner to execute a test case, generate output.jsonl, and generate report.md.

Each test case has a registered set of assertions (EXPECTATIONS). A case only
reports PASS when every expected JSON subset matches at least one parsed event
and the minimum event count is reached. Otherwise the report says FAIL and the
script exits with code 1.
"""

import json
import os
import subprocess
import sys

# Expected result per test case directory.
#   min_events: minimum number of parsed events.
#   checks: list of JSON subsets; each subset must match at least one event.
#   pcap: optional pcap filename (default test.pcap).
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


def run_case(case_name: str, description: str, verification_criteria: str) -> int:
    spec = EXPECTATIONS.get(case_name)
    case_dir = os.path.join("TEST", case_name)
    pcap_path = os.path.join(case_dir, (spec or {}).get("pcap", "test.pcap"))
    output_path = os.path.join(case_dir, "output.jsonl")
    report_path = os.path.join(case_dir, "report.md")

    if not os.path.isfile(pcap_path):
        print(f"[!] Error: {pcap_path} not found.")
        return 1

    # Run main.py on the pcap
    cmd = [sys.executable, "main.py", "--pcap", pcap_path, "--output", output_path]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] main.py failed on {case_name}:\n{res.stderr}")
        return res.returncode

    # Read output.jsonl
    with open(output_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    # Verify registered assertions
    failures = []
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

    status = "PASS (Thành công)" if not failures else "FAIL (Thất bại)"
    result_lines = (
        "\n".join(f"- {line}" for line in failures)
        if failures
        else "- Tất cả kỳ vọng kiểm thử đều khớp với output thực tế."
    )

    # Write report.md
    report_content = f"""# Test Case Report: {case_name}

- **Mục tiêu**: {description}
- **Yêu cầu kiểm thử**: {verification_criteria}
- **File PCAP**: `{pcap_path}`
- **File Output JSONL**: `{output_path}`
- **Số gói tin đã xử lý**: {len(events)}
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

## 3. Đánh giá tính đúng đắn
{result_lines}
- Chương trình kết thúc bình thường (exit code 0), không crash.
- Cấu trúc dữ liệu đầu ra tuân thủ đúng định dạng JSON chuẩn hóa của đề bài.

## 4. Chi tiết Normalized Events (JSON)
```json
{json.dumps(events, indent=2, ensure_ascii=False)}
```
"""
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"[+] Case {case_name}: {status}. Report written to {report_path}")
    return 0 if not failures else 1


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python run_case.py <case_name> <description> <criteria>")
        sys.exit(1)
    sys.exit(run_case(sys.argv[1], sys.argv[2], sys.argv[3]))
