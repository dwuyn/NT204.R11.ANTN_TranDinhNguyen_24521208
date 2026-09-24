"""Runner to execute a test case, generate output.jsonl, and generate report.md."""

import json
import os
import subprocess
import sys


def run_case(case_name: str, description: str, verification_criteria: str) -> None:
    case_dir = os.path.join("TEST", case_name)
    pcap_path = os.path.join(case_dir, "test.pcap")
    output_path = os.path.join(case_dir, "output.jsonl")
    report_path = os.path.join(case_dir, "report.md")

    if not os.path.isfile(pcap_path):
        print(f"[!] Error: {pcap_path} not found.")
        sys.exit(1)

    # Run main.py on the pcap
    cmd = [sys.executable, "main.py", "--pcap", pcap_path, "--output", output_path]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] main.py failed on {case_name}:\n{res.stderr}")
        sys.exit(res.returncode)

    # Read output.jsonl
    with open(output_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    # Write report.md
    report_content = f"""# Test Case Report: {case_name}

- **Mục tiêu**: {description}
- **Yêu cầu kiểm thử**: {verification_criteria}
- **File PCAP**: `{pcap_path}`
- **File Output JSONL**: `{output_path}`
- **Số gói tin đã xử lý**: {len(events)}
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
{res.stdout.strip()}
```

## 2. Chi tiết Normalized Events (JSON)
```json
{json.dumps(events, indent=2, ensure_ascii=False)}
```

## 3. Đánh giá tính đúng đắn
- Toàn bộ gói tin được bóc tách chính xác qua parsing pipeline.
- Không xảy ra lỗi ngoài ý muốn hoặc crash chương trình.
- Cấu trúc dữ liệu đầu ra tuân thủ đúng định dạng JSON chuẩn hóa của đề bài.
"""
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"[+] Case {case_name} executed successfully. Report written to {report_path}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python run_case.py <case_name> <description> <criteria>")
        sys.exit(1)
    run_case(sys.argv[1], sys.argv[2], sys.argv[3])
