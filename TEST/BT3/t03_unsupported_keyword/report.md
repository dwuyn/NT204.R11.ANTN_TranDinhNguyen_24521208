# Test Case Report: bt3_t03_unsupported_keyword

- **Mục tiêu**: Cấu trúc ngoài phạm vi bị đánh unsupported kèm lý do, không crash
- **Yêu cầu kiểm thử**: Bốn rule dùng pcre, action drop, protocol icmp và địa chỉ phủ định đều được phân loại unsupported với reason cụ thể từng dòng; loader vẫn kết thúc bình thường với 0 rule hợp lệ.
- **File Rules**: `TEST/BT3/t03_unsupported_keyword/test.rules`
- **File Kết quả**: `TEST/BT3/t03_unsupported_keyword/result.json`
- **Thống kê nạp rule**: files=1 valid=0 invalid=0 unsupported=4
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
[+] TEST/BT3/t03_unsupported_keyword/test.rules: valid=0 invalid=0 unsupported=4 probes=0
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "stats": {
      "files_loaded": 1,
      "valid": 0,
      "invalid": 0,
      "unsupported": 4
    }
  },
  {
    "unsupported": [
      {
        "status": "unsupported",
        "line_no": 1,
        "reason": "unsupported keyword: pcre"
      }
    ]
  },
  {
    "unsupported": [
      {
        "status": "unsupported",
        "line_no": 2,
        "reason": "unsupported action: drop"
      }
    ]
  },
  {
    "unsupported": [
      {
        "status": "unsupported",
        "line_no": 3,
        "reason": "unsupported protocol: icmp"
      }
    ]
  },
  {
    "unsupported": [
      {
        "status": "unsupported",
        "line_no": 4,
        "reason": "unsupported negated address: !192.168.1.1"
      }
    ]
  }
]
```

## 3. Đánh giá tính đúng đắn
- Tất cả kỳ vọng kiểm thử đều khớp với kết quả thực tế.
- Chương trình kết thúc bình thường (exit code 0), không crash.
- Kết quả nạp rule tuân thủ đúng mô hình valid / invalid / unsupported của đề bài.

## 4. Kết quả nạp rule (result.json)
```json
{
  "files": [
    "TEST/BT3/t03_unsupported_keyword/test.rules"
  ],
  "stats": {
    "files_loaded": 1,
    "valid": 0,
    "invalid": 0,
    "unsupported": 4,
    "disabled_rules": 0,
    "disabled_files": 0
  },
  "valid": [],
  "invalid": [],
  "unsupported": [
    {
      "status": "unsupported",
      "reason": "unsupported keyword: pcre",
      "rule_file": "TEST/BT3/t03_unsupported_keyword/test.rules",
      "line_no": 1,
      "raw": "alert tcp any any -> any 80 (msg:\"pcre\"; pcre:\"/etc/passwd/\"; sid:1100013;)",
      "sid": null
    },
    {
      "status": "unsupported",
      "reason": "unsupported action: drop",
      "rule_file": "TEST/BT3/t03_unsupported_keyword/test.rules",
      "line_no": 2,
      "raw": "drop tcp any any -> any 80 (msg:\"drop action\"; sid:1100014;)",
      "sid": null
    },
    {
      "status": "unsupported",
      "reason": "unsupported protocol: icmp",
      "rule_file": "TEST/BT3/t03_unsupported_keyword/test.rules",
      "line_no": 3,
      "raw": "alert icmp any any -> any any (msg:\"icmp echo\"; sid:1100015;)",
      "sid": null
    },
    {
      "status": "unsupported",
      "reason": "unsupported negated address: !192.168.1.1",
      "rule_file": "TEST/BT3/t03_unsupported_keyword/test.rules",
      "line_no": 4,
      "raw": "alert tcp !192.168.1.1 any -> any 80 (msg:\"negated src\"; sid:1100016;)",
      "sid": null
    }
  ],
  "disabled_rules": [],
  "disabled_files": [],
  "warnings": [
    "unsupported rule at TEST/BT3/t03_unsupported_keyword/test.rules:1: unsupported keyword: pcre",
    "unsupported rule at TEST/BT3/t03_unsupported_keyword/test.rules:2: unsupported action: drop",
    "unsupported rule at TEST/BT3/t03_unsupported_keyword/test.rules:3: unsupported protocol: icmp",
    "unsupported rule at TEST/BT3/t03_unsupported_keyword/test.rules:4: unsupported negated address: !192.168.1.1"
  ],
  "candidates": []
}
```
