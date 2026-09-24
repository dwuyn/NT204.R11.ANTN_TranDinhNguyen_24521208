# Test Case Report: test_10_smtp_response

- **Mục tiêu**: SMTP Responses
- **Yêu cầu kiểm thử**: Parse SMTP status codes (220, 250, 354)
- **File PCAP**: `TEST/test_10_smtp_response/test.pcap`
- **File Output JSONL**: `TEST/test_10_smtp_response/output.jsonl`
- **Số gói tin đã xử lý**: 3
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_10_smtp_response/test.pcap)
[*] Writing normalized events to: TEST/test_10_smtp_response/output.jsonl
------------------------------------------------------------
[0001] 10.0.0.25 -> 192.168.1.100 (TCP):25 -> :45000 [ACK,PSH] | SMTP (response) [len=73]
[0002] 10.0.0.25 -> 192.168.1.100 (TCP):25 -> :45000 [ACK,PSH] | SMTP (response) [len=70]
[0003] 10.0.0.25 -> 192.168.1.100 (TCP):25 -> :45000 [ACK,PSH] | SMTP (response) [len=77]
------------------------------------------------------------
[+] Finished: Processed 3 packets in 0.00s (1878.6 pkts/s)
[+] Output saved to: TEST/test_10_smtp_response/output.jsonl
============================================================
```

## 2. Chi tiết Normalized Events (JSON)
```json
[
  {
    "packet_id": 1,
    "timestamp": 1790269306.150329,
    "timestamp_iso": "2026-09-24T17:01:46.150329+00:00",
    "raw_len": 73,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.25",
      "dst_ip": "192.168.1.100",
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
      "src_port": 25,
      "dst_port": 45000,
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
      "type": "response",
      "details": {
        "status_code": 220,
        "message": "mail.uit.edu.vn ESMTP Ready",
        "raw_lines": [
          "220 mail.uit.edu.vn ESMTP Ready"
        ],
        "detection_method": "payload_signature"
      }
    },
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1790269306.150687,
    "timestamp_iso": "2026-09-24T17:01:46.150687+00:00",
    "raw_len": 70,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.25",
      "dst_ip": "192.168.1.100",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 70,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 25,
      "dst_port": 45000,
      "payload_len": 30,
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
      "type": "response",
      "details": {
        "status_code": 250,
        "message": "2.1.0 Ok sender accepted",
        "raw_lines": [
          "250 2.1.0 Ok sender accepted"
        ],
        "detection_method": "payload_signature"
      }
    },
    "errors": []
  },
  {
    "packet_id": 3,
    "timestamp": 1790269306.151025,
    "timestamp_iso": "2026-09-24T17:01:46.151025+00:00",
    "raw_len": 77,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.25",
      "dst_ip": "192.168.1.100",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 77,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 25,
      "dst_port": 45000,
      "payload_len": 37,
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
      "type": "response",
      "details": {
        "status_code": 354,
        "message": "End data with <CR><LF>.<CR><LF>",
        "raw_lines": [
          "354 End data with <CR><LF>.<CR><LF>"
        ],
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
