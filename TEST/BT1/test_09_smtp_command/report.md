# Test Case Report: test_09_smtp_command

- **Mục tiêu**: SMTP Commands
- **Yêu cầu kiểm thử**: Parse HELO/EHLO, MAIL FROM và RCPT TO kèm tham số
- **File PCAP**: `TEST/BT1/test_09_smtp_command/test.pcap`
- **File Output JSONL**: `TEST/BT1/test_09_smtp_command/output.jsonl`
- **Số gói tin đã xử lý**: 3
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT1/test_09_smtp_command/test.pcap)
[*] Writing normalized events to: TEST/BT1/test_09_smtp_command/output.jsonl
[*] Writing flow records to: /tmp/ids_flows_ym9lbmn1/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 192.168.1.100 -> 10.0.0.25 (TCP):45000 -> :25 [ACK,PSH] | SMTP (command) [len=63]
[0002] 192.168.1.100 -> 10.0.0.25 (TCP):45000 -> :25 [ACK,PSH] | SMTP (command) [len=72]
[0003] 192.168.1.100 -> 10.0.0.25 (TCP):45000 -> :25 [ACK,PSH] | SMTP (command) [len=73]
[FLOW] TCP-192.168.1.100:45000-10.0.0.25:25 state=ESTABLISHED pkts=3 bytes=208 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 3 packets in 0.00s (1496.4 pkts/s)
[+] Output saved to: TEST/BT1/test_09_smtp_command/output.jsonl
[+] Flow records saved to: /tmp/ids_flows_ym9lbmn1/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **3**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "application": {
      "protocol": "SMTP",
      "details": {
        "command": "EHLO"
      }
    }
  },
  {
    "application": {
      "protocol": "SMTP",
      "details": {
        "command": "MAIL FROM"
      }
    }
  },
  {
    "application": {
      "protocol": "SMTP",
      "details": {
        "command": "RCPT TO"
      }
    }
  }
]
```



## 3. Đánh giá tính đúng đắn
- Tất cả kỳ vọng kiểm thử đều khớp với output thực tế.
- Chương trình kết thúc bình thường (exit code 0), không crash.
- Cấu trúc dữ liệu đầu ra tuân thủ đúng định dạng JSON chuẩn hóa của đề bài.

## 4. Chi tiết Normalized Events (JSON)
```json
[
  {
    "packet_id": 1,
    "timestamp": 1790269306.149252,
    "timestamp_iso": "2026-09-24T17:01:46.149252+00:00",
    "raw_len": 63,
    "network": {
      "layer": "IPv4",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.25",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 63,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 45000,
      "dst_port": 25,
      "payload_len": 23,
      "seq": 0,
      "ack": 0,
      "flags": [
        "ACK",
        "PSH"
      ],
      "window": 8192,
      "data_offset": 5
    },
    "application": {
      "protocol": "SMTP",
      "type": "command",
      "details": {
        "command": "EHLO",
        "argument": "client.ids.local",
        "raw_line": "EHLO client.ids.local",
        "detection_method": "payload_signature"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {},
      "warnings": []
    },
    "preprocess": {
      "preprocess_status": "valid",
      "processing_action": "forward",
      "reason": null,
      "normalizations": [],
      "warnings": []
    },
    "flow": {
      "flow_id": "TCP-192.168.1.100:45000-10.0.0.25:25",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1790269306.149603,
    "timestamp_iso": "2026-09-24T17:01:46.149603+00:00",
    "raw_len": 72,
    "network": {
      "layer": "IPv4",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.25",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 72,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 45000,
      "dst_port": 25,
      "payload_len": 32,
      "seq": 0,
      "ack": 0,
      "flags": [
        "ACK",
        "PSH"
      ],
      "window": 8192,
      "data_offset": 5
    },
    "application": {
      "protocol": "SMTP",
      "type": "command",
      "details": {
        "command": "MAIL FROM",
        "argument": "<student@uit.edu.vn>",
        "raw_line": "MAIL FROM:<student@uit.edu.vn>",
        "detection_method": "payload_signature"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {},
      "warnings": []
    },
    "preprocess": {
      "preprocess_status": "valid",
      "processing_action": "forward",
      "reason": null,
      "normalizations": [],
      "warnings": []
    },
    "flow": {
      "flow_id": "TCP-192.168.1.100:45000-10.0.0.25:25",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": false
    },
    "errors": []
  },
  {
    "packet_id": 3,
    "timestamp": 1790269306.149961,
    "timestamp_iso": "2026-09-24T17:01:46.149961+00:00",
    "raw_len": 73,
    "network": {
      "layer": "IPv4",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.25",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 73,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 45000,
      "dst_port": 25,
      "payload_len": 33,
      "seq": 0,
      "ack": 0,
      "flags": [
        "ACK",
        "PSH"
      ],
      "window": 8192,
      "data_offset": 5
    },
    "application": {
      "protocol": "SMTP",
      "type": "command",
      "details": {
        "command": "RCPT TO",
        "argument": "<instructor@uit.edu.vn>",
        "raw_line": "RCPT TO:<instructor@uit.edu.vn>",
        "detection_method": "payload_signature"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {},
      "warnings": []
    },
    "preprocess": {
      "preprocess_status": "valid",
      "processing_action": "forward",
      "reason": null,
      "normalizations": [],
      "warnings": []
    },
    "flow": {
      "flow_id": "TCP-192.168.1.100:45000-10.0.0.25:25",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": false
    },
    "errors": []
  }
]
```
