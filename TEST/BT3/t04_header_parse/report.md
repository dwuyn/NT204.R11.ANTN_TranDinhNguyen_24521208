# Test Case Report: bt3_t04_header_parse

- **Mục tiêu**: Parse rule header: CIDR, dải cổng, cận mở và toán tử hai chiều
- **Yêu cầu kiểm thử**: Header CIDR 192.168.1.0/24 với dải cổng 1024:2048, header UDP hai chiều <> tới 8.8.8.8:53 và header với cận dưới mở :1024 đều được parse thành IPSpec/PortSpec chính xác (any/network/lo/hi/text).
- **File Rules**: `TEST/BT3/t04_header_parse/test.rules`
- **File Kết quả**: `TEST/BT3/t04_header_parse/result.json`
- **Thống kê nạp rule**: files=1 valid=3 invalid=0 unsupported=0
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
[+] TEST/BT3/t04_header_parse/test.rules: valid=3 invalid=0 unsupported=0 probes=0
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "stats": {
      "files_loaded": 1,
      "valid": 3
    }
  },
  {
    "valid": [
      {
        "sid": 1100021,
        "header": {
          "action": "alert",
          "protocol": "tcp",
          "direction": "->",
          "src_ip": {
            "any": false,
            "network": "192.168.1.0/24",
            "text": "192.168.1.0/24"
          },
          "src_port": {
            "lo": 1024,
            "hi": 2048,
            "text": "1024:2048"
          },
          "dst_ip": {
            "any": false,
            "network": "10.0.0.5/32",
            "text": "10.0.0.5"
          },
          "dst_port": {
            "lo": 80,
            "hi": 80,
            "text": "80"
          }
        }
      }
    ]
  },
  {
    "valid": [
      {
        "sid": 1100022,
        "header": {
          "protocol": "udp",
          "direction": "<>",
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
          "dst_ip": {
            "any": false,
            "network": "8.8.8.8/32"
          },
          "dst_port": {
            "lo": 53,
            "hi": 53,
            "text": "53"
          }
        }
      }
    ]
  },
  {
    "valid": [
      {
        "sid": 1100023,
        "header": {
          "src_ip": {
            "any": false,
            "network": "172.16.0.0/12"
          },
          "src_port": {
            "lo": null,
            "hi": 1024,
            "text": ":1024"
          },
          "dst_ip": {
            "any": true
          },
          "dst_port": {
            "lo": 8080,
            "hi": 8080
          }
        }
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
    "TEST/BT3/t04_header_parse/test.rules"
  ],
  "stats": {
    "files_loaded": 1,
    "valid": 3,
    "invalid": 0,
    "unsupported": 0,
    "disabled_rules": 0,
    "disabled_files": 0
  },
  "valid": [
    {
      "header": {
        "action": "alert",
        "protocol": "tcp",
        "src_ip": {
          "any": false,
          "network": "192.168.1.0/24",
          "text": "192.168.1.0/24"
        },
        "src_port": {
          "lo": 1024,
          "hi": 2048,
          "text": "1024:2048"
        },
        "direction": "->",
        "dst_ip": {
          "any": false,
          "network": "10.0.0.5/32",
          "text": "10.0.0.5"
        },
        "dst_port": {
          "lo": 80,
          "hi": 80,
          "text": "80"
        }
      },
      "msg": "cidr range",
      "sid": 1100021,
      "rev": 1,
      "classtype": null,
      "priority": null,
      "contents": [],
      "flow": [],
      "flags": null,
      "dsize": null,
      "rule_file": "TEST/BT3/t04_header_parse/test.rules",
      "line_no": 1
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
        "direction": "<>",
        "dst_ip": {
          "any": false,
          "network": "8.8.8.8/32",
          "text": "8.8.8.8"
        },
        "dst_port": {
          "lo": 53,
          "hi": 53,
          "text": "53"
        }
      },
      "msg": "bidirectional dns",
      "sid": 1100022,
      "rev": 1,
      "classtype": null,
      "priority": null,
      "contents": [],
      "flow": [],
      "flags": null,
      "dsize": null,
      "rule_file": "TEST/BT3/t04_header_parse/test.rules",
      "line_no": 2
    },
    {
      "header": {
        "action": "alert",
        "protocol": "tcp",
        "src_ip": {
          "any": false,
          "network": "172.16.0.0/12",
          "text": "172.16.0.0/12"
        },
        "src_port": {
          "lo": null,
          "hi": 1024,
          "text": ":1024"
        },
        "direction": "->",
        "dst_ip": {
          "any": true,
          "network": null,
          "text": "any"
        },
        "dst_port": {
          "lo": 8080,
          "hi": 8080,
          "text": "8080"
        }
      },
      "msg": "open lower bound",
      "sid": 1100023,
      "rev": 1,
      "classtype": null,
      "priority": null,
      "contents": [],
      "flow": [],
      "flags": null,
      "dsize": null,
      "rule_file": "TEST/BT3/t04_header_parse/test.rules",
      "line_no": 3
    }
  ],
  "invalid": [],
  "unsupported": [],
  "disabled_rules": [],
  "disabled_files": [],
  "warnings": [],
  "candidates": []
}
```
