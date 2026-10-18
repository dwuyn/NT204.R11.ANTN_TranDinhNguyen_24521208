# Test Case Report: bt3_t02_invalid_rule

- **Mục tiêu**: Rule sai cú pháp bị đánh invalid kèm lý do, loader không dừng
- **Yêu cầu kiểm thử**: Ba rule thiếu sid, sai toán tử chiều (=>) và cổng không hợp lệ (abc) đều bị đánh invalid với reason tương ứng theo từng dòng, không rule nào bị crash và cả ba warning đều được ghi lại.
- **File Rules**: `TEST/BT3/t02_invalid_rule/test.rules`
- **File Kết quả**: `TEST/BT3/t02_invalid_rule/result.json`
- **Thống kê nạp rule**: files=1 valid=0 invalid=3 unsupported=0
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
[+] TEST/BT3/t02_invalid_rule/test.rules: valid=0 invalid=3 unsupported=0 probes=0
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "stats": {
      "files_loaded": 1,
      "valid": 0,
      "invalid": 3,
      "unsupported": 0
    }
  },
  {
    "invalid": [
      {
        "status": "invalid",
        "line_no": 1,
        "reason": "missing required option: sid"
      }
    ]
  },
  {
    "invalid": [
      {
        "status": "invalid",
        "line_no": 2,
        "reason": "invalid rule syntax"
      }
    ]
  },
  {
    "invalid": [
      {
        "status": "invalid",
        "line_no": 3,
        "reason": "invalid port: abc"
      }
    ]
  },
  {
    "warnings": [
      "invalid rule at TEST/BT3/t02_invalid_rule/test.rules:1: missing required option: sid",
      "invalid rule at TEST/BT3/t02_invalid_rule/test.rules:2: invalid rule syntax",
      "invalid rule at TEST/BT3/t02_invalid_rule/test.rules:3: invalid port: abc"
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
    "TEST/BT3/t02_invalid_rule/test.rules"
  ],
  "stats": {
    "files_loaded": 1,
    "valid": 0,
    "invalid": 3,
    "unsupported": 0,
    "disabled_rules": 0,
    "disabled_files": 0
  },
  "valid": [],
  "invalid": [
    {
      "status": "invalid",
      "reason": "missing required option: sid",
      "rule_file": "TEST/BT3/t02_invalid_rule/test.rules",
      "line_no": 1,
      "raw": "alert tcp any any -> any 80 (msg:\"missing sid\";)",
      "sid": null
    },
    {
      "status": "invalid",
      "reason": "invalid rule syntax",
      "rule_file": "TEST/BT3/t02_invalid_rule/test.rules",
      "line_no": 2,
      "raw": "alert tcp any any => any 80 (msg:\"bad direction\"; sid:1100011;)",
      "sid": null
    },
    {
      "status": "invalid",
      "reason": "invalid port: abc",
      "rule_file": "TEST/BT3/t02_invalid_rule/test.rules",
      "line_no": 3,
      "raw": "alert tcp any any -> any abc (msg:\"bad port\"; sid:1100012;)",
      "sid": null
    }
  ],
  "unsupported": [],
  "disabled_rules": [],
  "disabled_files": [],
  "warnings": [
    "invalid rule at TEST/BT3/t02_invalid_rule/test.rules:1: missing required option: sid",
    "invalid rule at TEST/BT3/t02_invalid_rule/test.rules:2: invalid rule syntax",
    "invalid rule at TEST/BT3/t02_invalid_rule/test.rules:3: invalid port: abc"
  ],
  "candidates": []
}
```
