# Test Case Report: test_13_non_standard_port

- **Mục tiêu**: Non-standard Port Detection
- **Yêu cầu kiểm thử**: Nhận diện HTTP/SMTP/DNS trên port phi tiêu chuẩn bằng payload
- **File PCAP**: `TEST/test_13_non_standard_port/test.pcap`
- **File Output JSONL**: `TEST/test_13_non_standard_port/output.jsonl`
- **Số gói tin đã xử lý**: 3
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_13_non_standard_port/test.pcap)
[*] Writing normalized events to: TEST/test_13_non_standard_port/output.jsonl
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):51000 -> :9000 [ACK,PSH] | HTTP (request) [len=94]
[0002] 10.0.0.10 -> 10.0.0.20 (TCP):51000 -> :8025 [ACK,PSH] | SMTP (command) [len=71]
[0003] 10.0.0.10 -> 8.8.8.8 (UDP):51000 -> :53535 | DNS (query) [len=69]
------------------------------------------------------------
[+] Finished: Processed 3 packets in 0.00s (1216.3 pkts/s)
[+] Output saved to: TEST/test_13_non_standard_port/output.jsonl
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **3**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "application": {
      "protocol": "HTTP",
      "details": {
        "method": "GET",
        "detection_method": "payload_signature"
      }
    }
  },
  {
    "application": {
      "protocol": "SMTP",
      "details": {
        "command": "EHLO",
        "detection_method": "payload_signature"
      }
    }
  },
  {
    "application": {
      "protocol": "DNS",
      "details": {
        "detection_method": "payload_signature"
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
    "timestamp": 1790530847.655324,
    "timestamp_iso": "2026-09-27T17:40:47.655324+00:00",
    "raw_len": 94,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 94,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 51000,
      "dst_port": 9000,
      "payload_len": 54,
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
      "protocol": "HTTP",
      "type": "request",
      "details": {
        "method": "GET",
        "uri": "/nonstandard",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "nonstandard.local"
        },
        "body": "",
        "detection_method": "payload_signature"
      }
    },
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1790530847.65561,
    "timestamp_iso": "2026-09-27T17:40:47.655610+00:00",
    "raw_len": 71,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 71,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 51000,
      "dst_port": 8025,
      "payload_len": 31,
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
        "argument": "client.nonstandard.local",
        "raw_line": "EHLO client.nonstandard.local",
        "detection_method": "payload_signature"
      }
    },
    "errors": []
  },
  {
    "packet_id": 3,
    "timestamp": 1790530847.656396,
    "timestamp_iso": "2026-09-27T17:40:47.656396+00:00",
    "raw_len": 69,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "8.8.8.8",
      "proto": "UDP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 69,
      "flags": []
    },
    "transport": {
      "layer": "UDP",
      "src_port": 51000,
      "dst_port": 53535,
      "payload_len": 41,
      "checksum": 13573
    },
    "application": {
      "protocol": "DNS",
      "type": "query",
      "details": {
        "transaction_id": 8738,
        "qr": 0,
        "opcode": "QUERY",
        "rcode": "NOERROR",
        "queries": [
          {
            "name": "nonstandard.example.com",
            "type": "A"
          }
        ],
        "answers": [],
        "detection_method": "payload_signature"
      }
    },
    "errors": []
  }
]
```
