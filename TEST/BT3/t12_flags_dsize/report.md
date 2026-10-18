# Test Case Report: bt3_t12_flags_dsize

- **Mục tiêu**: flags (tập chữ cái) và dsize (so sánh kích thước payload)
- **Yêu cầu kiểm thử**: Packet PSH-ACK payload 20 byte khớp rule flags:PA dsize:>10 nhưng không khớp rule dsize:<10; packet FIN không payload khớp rule flags:F dsize:0.
- **File PCAP**: `TEST/BT3/t12_flags_dsize/test.pcap`
- **File Output JSONL**: `TEST/BT3/t12_flags_dsize/output.jsonl`
- **File Detections**: `TEST/BT3/t12_flags_dsize/detections.jsonl`
- **Số detection**: 2
- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT3/t12_flags_dsize/test.pcap)
[*] Writing normalized events to: TEST/BT3/t12_flags_dsize/output.jsonl
[*] Writing flow records to: TEST/BT3/t12_flags_dsize/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
[*] Rules: files=1 loaded=3 invalid=0 unsupported=0
[*] Writing detections to: TEST/BT3/t12_flags_dsize/detections.jsonl
------------------------------------------------------------
[ALERT] sid=1100101 rev=1 "data push larger than ten bytes" 10.0.0.10:52000 -> 10.0.0.20:80 (TCP/UNKNOWN) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] [len=60]
[ALERT] sid=1100103 rev=1 "connection teardown" 10.0.0.10:52000 -> 10.0.0.20:80 (TCP/UNKNOWN) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[0002] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [FIN] [len=40]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=CLOSING pkts=2 bytes=100 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (941.4 pkts/s)
[+] Output saved to: TEST/BT3/t12_flags_dsize/output.jsonl
[+] Flow records saved to: TEST/BT3/t12_flags_dsize/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
[+] Rules: loaded=3 events_evaluated=2 candidate_rules=6 matches=2
[+] Detections: 2 written to TEST/BT3/t12_flags_dsize/detections.jsonl
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **2**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "transport": {
      "layer": "TCP",
      "flags": [
        "PSH",
        "ACK"
      ],
      "payload_len": 20
    }
  },
  {
    "transport": {
      "layer": "TCP",
      "flags": [
        "FIN"
      ],
      "payload_len": 0
    }
  }
]
```

- Số detection tối thiểu: **2**
- Danh sách detection subset bắt buộc phải khớp:
```json
[
  {
    "sid": 1100101,
    "packet_id": 1,
    "matched": {
      "fields": [
        "flags:PA",
        "dsize:>10"
      ]
    }
  },
  {
    "sid": 1100103,
    "packet_id": 2,
    "matched": {
      "fields": [
        "flags:F",
        "dsize:0"
      ]
    }
  }
]
```
- Danh sách detection bị cấm (không được xuất hiện):
```json
[
  {
    "sid": 1100102
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
    "timestamp": 1700000000.0,
    "timestamp_iso": "2023-11-14T22:13:20+00:00",
    "raw_len": 60,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 60,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 20,
      "seq": 1000,
      "ack": 0,
      "flags": [
        "ACK",
        "PSH"
      ],
      "window": 8192,
      "data_offset": 5
    },
    "application": {
      "protocol": "UNKNOWN",
      "type": "unknown",
      "details": {
        "detection_method": "default"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {},
      "warnings": []
    },
    "preprocess": {
      "preprocess_status": "partial",
      "processing_action": "forward",
      "reason": "unsupported_protocol",
      "normalizations": [],
      "warnings": []
    },
    "flow": {
      "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1700000000.1,
    "timestamp_iso": "2023-11-14T22:13:20.100000+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 40,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 0,
      "seq": 1020,
      "ack": 0,
      "flags": [
        "FIN"
      ],
      "window": 8192,
      "data_offset": 5
    },
    "application": null,
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {},
      "warnings": []
    },
    "preprocess": {
      "preprocess_status": "partial",
      "processing_action": "forward",
      "reason": "no_application_layer",
      "normalizations": [],
      "warnings": []
    },
    "flow": {
      "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
      "direction": "forward",
      "state": "CLOSING",
      "is_new_flow": false
    },
    "errors": []
  }
]
```

## 6. Detection Events (detections.jsonl)
- **Số detection**: 2
- **Số detection tối thiểu**: 2
- **Kỳ vọng detection (JSON subset bắt buộc khớp)**:
```json
[
  {
    "sid": 1100101,
    "packet_id": 1,
    "matched": {
      "fields": [
        "flags:PA",
        "dsize:>10"
      ]
    }
  },
  {
    "sid": 1100103,
    "packet_id": 2,
    "matched": {
      "fields": [
        "flags:F",
        "dsize:0"
      ]
    }
  }
]
```
- **Kỳ vọng detection bị cấm**:
```json
[
  {
    "sid": 1100102
  }
]
```
- **Chi tiết detection records**:
```json
[
  {
    "packet_id": 1,
    "timestamp": 1700000000.0,
    "timestamp_iso": "2023-11-14T22:13:20+00:00",
    "action": "alert",
    "sid": 1100101,
    "rev": 1,
    "msg": "data push larger than ten bytes",
    "classtype": null,
    "priority": null,
    "protocol": "TCP",
    "application_protocol": "UNKNOWN",
    "src_ip": "10.0.0.10",
    "src_port": 52000,
    "dst_ip": "10.0.0.20",
    "dst_port": 80,
    "direction": "forward",
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "flow_state": "ESTABLISHED",
    "matched": {
      "contents": [],
      "fields": [
        "flags:PA",
        "dsize:>10"
      ]
    },
    "rule_file": "TEST/BT3/t12_flags_dsize/test.rules"
  },
  {
    "packet_id": 2,
    "timestamp": 1700000000.1,
    "timestamp_iso": "2023-11-14T22:13:20.100000+00:00",
    "action": "alert",
    "sid": 1100103,
    "rev": 1,
    "msg": "connection teardown",
    "classtype": null,
    "priority": null,
    "protocol": "TCP",
    "application_protocol": "",
    "src_ip": "10.0.0.10",
    "src_port": 52000,
    "dst_ip": "10.0.0.20",
    "dst_port": 80,
    "direction": "forward",
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "flow_state": "CLOSING",
    "matched": {
      "contents": [],
      "fields": [
        "flags:F",
        "dsize:0"
      ]
    },
    "rule_file": "TEST/BT3/t12_flags_dsize/test.rules"
  }
]
```
