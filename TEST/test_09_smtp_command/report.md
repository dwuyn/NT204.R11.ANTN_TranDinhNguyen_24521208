# Test Case Report: test_09_smtp_command

- **Mục tiêu**: SMTP Commands
- **Yêu cầu kiểm thử**: Parse HELO/EHLO, MAIL FROM và RCPT TO kèm tham số
- **File PCAP**: `TEST/test_09_smtp_command/test.pcap`
- **File Output JSONL**: `TEST/test_09_smtp_command/output.jsonl`
- **Số gói tin đã xử lý**: 3
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_09_smtp_command/test.pcap)
[*] Writing normalized events to: TEST/test_09_smtp_command/output.jsonl
------------------------------------------------------------
[0001] 192.168.1.100 -> 10.0.0.25 (TCP):45000 -> :25 [ACK,PSH] | SMTP (command) [len=63]
[0002] 192.168.1.100 -> 10.0.0.25 (TCP):45000 -> :25 [ACK,PSH] | SMTP (command) [len=72]
[0003] 192.168.1.100 -> 10.0.0.25 (TCP):45000 -> :25 [ACK,PSH] | SMTP (command) [len=73]
------------------------------------------------------------
[+] Finished: Processed 3 packets in 0.00s (1983.4 pkts/s)
[+] Output saved to: TEST/test_09_smtp_command/output.jsonl
============================================================
```

## 2. Chi tiết Normalized Events (JSON)
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
    "errors": []
  }
]
```

## 3. Đánh giá tính đúng đắn
- Toàn bộ gói tin được bóc tách chính xác qua parsing pipeline.
- Không xảy ra lỗi ngoài ý muốn hoặc crash chương trình.
- Cấu trúc dữ liệu đầu ra tuân thủ đúng định dạng JSON chuẩn hóa của đề bài.
