# Test Case Report: test_10_smtp_response

- **Mục tiêu**: SMTP Responses
- **Yêu cầu kiểm thử**: Parse SMTP status codes (220, 250, 354)
- **File PCAP**: `TEST/BT1/test_10_smtp_response/test.pcap`
- **File Output JSONL**: `TEST/BT1/test_10_smtp_response/output.jsonl`
- **Số gói tin đã xử lý**: 3
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT1/test_10_smtp_response/test.pcap)
[*] Writing normalized events to: TEST/BT1/test_10_smtp_response/output.jsonl
[*] Writing flow records to: /tmp/ids_flows_bajj9edo/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.25 -> 192.168.1.100 (TCP):25 -> :45000 [ACK,PSH] | SMTP (response) [len=73]
[0002] 10.0.0.25 -> 192.168.1.100 (TCP):25 -> :45000 [ACK,PSH] | SMTP (response) [len=70]
[0003] 10.0.0.25 -> 192.168.1.100 (TCP):25 -> :45000 [ACK,PSH] | SMTP (response) [len=77]
[FLOW] TCP-10.0.0.25:25-192.168.1.100:45000 state=ESTABLISHED pkts=3 bytes=220 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 3 packets in 0.00s (1425.5 pkts/s)
[+] Output saved to: TEST/BT1/test_10_smtp_response/output.jsonl
[+] Flow records saved to: /tmp/ids_flows_bajj9edo/flows.jsonl
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
        "status_code": 220
      }
    }
  },
  {
    "application": {
      "protocol": "SMTP",
      "details": {
        "status_code": 250
      }
    }
  },
  {
    "application": {
      "protocol": "SMTP",
      "details": {
        "status_code": 354
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
      "flow_id": "TCP-10.0.0.25:25-192.168.1.100:45000",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
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
      "flow_id": "TCP-10.0.0.25:25-192.168.1.100:45000",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": false
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
      "flow_id": "TCP-10.0.0.25:25-192.168.1.100:45000",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": false
    },
    "errors": []
  }
]
```
