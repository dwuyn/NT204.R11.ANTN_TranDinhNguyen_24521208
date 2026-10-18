# Test Case Report: test_13_non_standard_port

- **Mục tiêu**: Non-standard Port Detection
- **Yêu cầu kiểm thử**: Nhận diện HTTP/SMTP/DNS trên port phi tiêu chuẩn bằng payload
- **File PCAP**: `TEST/BT1/test_13_non_standard_port/test.pcap`
- **File Output JSONL**: `TEST/BT1/test_13_non_standard_port/output.jsonl`
- **Số gói tin đã xử lý**: 3
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT1/test_13_non_standard_port/test.pcap)
[*] Writing normalized events to: TEST/BT1/test_13_non_standard_port/output.jsonl
[*] Writing flow records to: /tmp/ids_flows_au2ox3xn/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):51000 -> :9000 [ACK,PSH] | HTTP (request) [len=94]
[0002] 10.0.0.10 -> 10.0.0.20 (TCP):51000 -> :8025 [ACK,PSH] | SMTP (command) [len=71]
[0003] 10.0.0.10 -> 8.8.8.8 (UDP):51000 -> :53535 | DNS (query) [len=69]
[FLOW] TCP-10.0.0.10:51000-10.0.0.20:9000 state=ESTABLISHED pkts=1 bytes=94 reason=end_of_capture
[FLOW] TCP-10.0.0.10:51000-10.0.0.20:8025 state=ESTABLISHED pkts=1 bytes=71 reason=end_of_capture
[FLOW] UDP-10.0.0.10:51000-8.8.8.8:53535 state=ESTABLISHED pkts=1 bytes=69 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 3 packets in 0.00s (1072.0 pkts/s)
[+] Output saved to: TEST/BT1/test_13_non_standard_port/output.jsonl
[+] Flow records saved to: /tmp/ids_flows_au2ox3xn/flows.jsonl
[+] Flows: created=3 closed=3 active_flushed=3
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=3
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
        "detection_method": "payload_signature",
        "uri_normalized": "/nonstandard"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/nonstandard"
      },
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
      "flow_id": "TCP-10.0.0.10:51000-10.0.0.20:9000",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
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
      "flow_id": "TCP-10.0.0.10:51000-10.0.0.20:8025",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
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
      "flow_id": "UDP-10.0.0.10:51000-8.8.8.8:53535",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  }
]
```
