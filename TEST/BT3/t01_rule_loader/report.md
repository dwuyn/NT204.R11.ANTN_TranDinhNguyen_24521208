# Test Case Report: bt3_t01_rule_loader

- **Mục tiêu**: Nạp rule từ file: dòng hợp lệ, dòng invalid và dòng unsupported
- **Yêu cầu kiểm thử**: Rule loader nạp file test.rules, bỏ qua comment/dòng trống, nhận đúng 3 rule hợp lệ với sid/rev/content (nocase) chính xác, ghi nhận 1 rule invalid (thiếu msg) tại dòng 6 và 1 rule unsupported (pcre) tại dòng 7 kèm warning tương ứng.
- **File Rules**: `TEST/BT3/t01_rule_loader/test.rules`
- **File Kết quả**: `TEST/BT3/t01_rule_loader/result.json`
- **Thống kê nạp rule**: files=1 valid=3 invalid=1 unsupported=1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
[+] TEST/BT3/t01_rule_loader/test.rules: valid=3 invalid=1 unsupported=1 probes=0
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "stats": {
      "files_loaded": 1,
      "valid": 3,
      "invalid": 1,
      "unsupported": 1,
      "disabled_rules": 0,
      "disabled_files": 0
    }
  },
  {
    "valid": [
      {
        "sid": 1100001,
        "rev": 2,
        "msg": "HTTP GET"
      },
      {
        "sid": 1100002,
        "rev": 1,
        "msg": "TLS hello"
      },
      {
        "sid": 1100003,
        "rev": 1,
        "msg": "DNS query"
      }
    ]
  },
  {
    "valid": [
      {
        "sid": 1100001,
        "contents": [
          {
            "content": "GET",
            "nocase": true
          },
          {
            "content": "/index"
          }
        ]
      }
    ]
  },
  {
    "invalid": [
      {
        "status": "invalid",
        "line_no": 6,
        "reason": "missing required option: msg"
      }
    ]
  },
  {
    "unsupported": [
      {
        "status": "unsupported",
        "line_no": 7,
        "reason": "unsupported keyword: pcre"
      }
    ]
  },
  {
    "warnings": [
      "invalid rule at TEST/BT3/t01_rule_loader/test.rules:6: missing required option: msg",
      "unsupported rule at TEST/BT3/t01_rule_loader/test.rules:7: unsupported keyword: pcre"
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
    "TEST/BT3/t01_rule_loader/test.rules"
  ],
  "stats": {
    "files_loaded": 1,
    "valid": 3,
    "invalid": 1,
    "unsupported": 1,
    "disabled_rules": 0,
    "disabled_files": 0
  },
  "valid": [
    {
      "header": {
        "action": "alert",
        "protocol": "tcp",
        "src_ip": {
          "any": true,
          "network": null,
          "text": "any"
        },
        "src_port": {
          "lo": null,
          "hi": null,
          "text": "any"
        },
        "direction": "->",
        "dst_ip": {
          "any": false,
          "network": "10.0.0.20/32",
          "text": "10.0.0.20"
        },
        "dst_port": {
          "lo": 80,
          "hi": 80,
          "text": "80"
        }
      },
      "msg": "HTTP GET",
      "sid": 1100001,
      "rev": 2,
      "classtype": null,
      "priority": null,
      "contents": [
        {
          "content": "GET",
          "nocase": true,
          "offset": null,
          "depth": null,
          "distance": null,
          "within": null,
          "text": "content:\"GET\""
        },
        {
          "content": "/index",
          "nocase": false,
          "offset": null,
          "depth": null,
          "distance": null,
          "within": null,
          "text": "content:\"/index\""
        }
      ],
      "flow": [],
      "flags": null,
      "dsize": null,
      "rule_file": "TEST/BT3/t01_rule_loader/test.rules",
      "line_no": 3
    },
    {
      "header": {
        "action": "alert",
        "protocol": "tcp",
        "src_ip": {
          "any": true,
          "network": null,
          "text": "any"
        },
        "src_port": {
          "lo": null,
          "hi": null,
          "text": "any"
        },
        "direction": "->",
        "dst_ip": {
          "any": true,
          "network": null,
          "text": "any"
        },
        "dst_port": {
          "lo": 443,
          "hi": 443,
          "text": "443"
        }
      },
      "msg": "TLS hello",
      "sid": 1100002,
      "rev": 1,
      "classtype": null,
      "priority": null,
      "contents": [
        {
          "content": "\u0016\u0003",
          "nocase": false,
          "offset": null,
          "depth": null,
          "distance": null,
          "within": null,
          "text": "content:\"|16 03|\""
        }
      ],
      "flow": [],
      "flags": null,
      "dsize": null,
      "rule_file": "TEST/BT3/t01_rule_loader/test.rules",
      "line_no": 4
    },
    {
      "header": {
        "action": "alert",
        "protocol": "udp",
        "src_ip": {
          "any": true,
          "network": null,
          "text": "any"
        },
        "src_port": {
          "lo": null,
          "hi": null,
          "text": "any"
        },
        "direction": "->",
        "dst_ip": {
          "any": true,
          "network": null,
          "text": "any"
        },
        "dst_port": {
          "lo": 53,
          "hi": 53,
          "text": "53"
        }
      },
      "msg": "DNS query",
      "sid": 1100003,
      "rev": 1,
      "classtype": null,
      "priority": null,
      "contents": [
        {
          "content": "\u0001\u0000",
          "nocase": false,
          "offset": 2,
          "depth": 2,
          "distance": null,
          "within": null,
          "text": "content:\"|01 00|\""
        }
      ],
      "flow": [],
      "flags": null,
      "dsize": null,
      "rule_file": "TEST/BT3/t01_rule_loader/test.rules",
      "line_no": 5
    }
  ],
  "invalid": [
    {
      "status": "invalid",
      "reason": "missing required option: msg",
      "rule_file": "TEST/BT3/t01_rule_loader/test.rules",
      "line_no": 6,
      "raw": "alert tcp any any -> any 22 (content:\"SSH\"; sid:1100004;)",
      "sid": null
    }
  ],
  "unsupported": [
    {
      "status": "unsupported",
      "reason": "unsupported keyword: pcre",
      "rule_file": "TEST/BT3/t01_rule_loader/test.rules",
      "line_no": 7,
      "raw": "alert tcp any any -> any 80 (msg:\"pcre test\"; pcre:\"/foo/\"; sid:1100005;)",
      "sid": null
    }
  ],
  "disabled_rules": [],
  "disabled_files": [],
  "warnings": [
    "invalid rule at TEST/BT3/t01_rule_loader/test.rules:6: missing required option: msg",
    "unsupported rule at TEST/BT3/t01_rule_loader/test.rules:7: unsupported keyword: pcre"
  ],
  "candidates": []
}
```
