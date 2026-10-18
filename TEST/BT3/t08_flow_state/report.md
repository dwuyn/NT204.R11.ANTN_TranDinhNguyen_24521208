# Test Case Report: bt3_t08_flow_state

- **Mục tiêu**: Trạng thái flow: not_established khớp SYN, established chỉ khớp sau bắt tay
- **Yêu cầu kiểm thử**: Rule flow:not_established alert đúng packet SYN đầu tiên (flow_state HANDSHAKE) và không alert các packet sau; rule flow:to_server,established chứa 'HELLO' chỉ alert packet 4 khi flow đã ESTABLISHED qua bắt tay ba bước.
- **File PCAP**: `TEST/BT3/t08_flow_state/test.pcap`
- **File Output JSONL**: `TEST/BT3/t08_flow_state/output.jsonl`
- **File Detections**: `TEST/BT3/t08_flow_state/detections.jsonl`
- **Số detection**: 2
- **Số gói tin đã xử lý**: 4
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT3/t08_flow_state/test.pcap)
[*] Writing normalized events to: TEST/BT3/t08_flow_state/output.jsonl
[*] Writing flow records to: TEST/BT3/t08_flow_state/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
[*] Rules: files=1 loaded=2 invalid=0 unsupported=0
[*] Writing detections to: TEST/BT3/t08_flow_state/detections.jsonl
------------------------------------------------------------
[ALERT] sid=1100062 rev=1 "connection not established yet" 10.0.0.10:52000 -> 10.0.0.20:80 (TCP/UNKNOWN) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [SYN] [len=40]
[0002] 10.0.0.20 -> 10.0.0.10 (TCP):80 -> :52000 [SYN,ACK] [len=40]
[0003] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK] [len=40]
[ALERT] sid=1100061 rev=1 "established client data" 10.0.0.10:52000 -> 10.0.0.20:80 (TCP/UNKNOWN) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[0004] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] [len=49]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=ESTABLISHED pkts=4 bytes=169 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 4 packets in 0.00s (1682.6 pkts/s)
[+] Output saved to: TEST/BT3/t08_flow_state/output.jsonl
[+] Flow records saved to: TEST/BT3/t08_flow_state/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
[+] Rules: loaded=2 events_evaluated=4 candidate_rules=6 matches=2
[+] Detections: 2 written to TEST/BT3/t08_flow_state/detections.jsonl
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **4**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "transport": {
      "handshake": "SYN"
    },
    "flow": {
      "state": "HANDSHAKE"
    }
  },
  {
    "transport": {
      "layer": "TCP"
    }
  }
]
```

- Số detection tối thiểu: **2**
- Danh sách detection subset bắt buộc phải khớp:
```json
[
  {
    "sid": 1100062,
    "packet_id": 1,
    "direction": "forward",
    "flow_state": "HANDSHAKE",
    "msg": "connection not established yet"
  },
  {
    "sid": 1100061,
    "packet_id": 4,
    "flow_state": "ESTABLISHED",
    "matched": {
      "contents": [
        {
          "content": "HELLO",
          "offset": 0,
          "length": 5
        }
      ]
    }
  }
]
```
- Danh sách detection bị cấm (không được xuất hiện):
```json
[
  {
    "sid": 1100061,
    "packet_id": 1
  },
  {
    "sid": 1100062,
    "packet_id": 4
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
      "seq": 1000,
      "ack": 0,
      "flags": [
        "SYN"
      ],
      "handshake": "SYN",
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
      "state": "HANDSHAKE",
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
      "src_ip": "10.0.0.20",
      "dst_ip": "10.0.0.10",
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
      "src_port": 80,
      "dst_port": 52000,
      "payload_len": 0,
      "seq": 5000,
      "ack": 1001,
      "flags": [
        "SYN",
        "ACK"
      ],
      "handshake": "SYN-ACK",
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
      "direction": "backward",
      "state": "HANDSHAKE",
      "is_new_flow": false
    },
    "errors": []
  },
  {
    "packet_id": 3,
    "timestamp": 1700000000.2,
    "timestamp_iso": "2023-11-14T22:13:20.200000+00:00",
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
      "seq": 1001,
      "ack": 5001,
      "flags": [
        "ACK"
      ],
      "handshake": "ACK",
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
      "state": "ESTABLISHED",
      "is_new_flow": false
    },
    "errors": []
  },
  {
    "packet_id": 4,
    "timestamp": 1700000000.3,
    "timestamp_iso": "2023-11-14T22:13:20.300000+00:00",
    "raw_len": 49,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 49,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 9,
      "seq": 1001,
      "ack": 5001,
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
    "sid": 1100062,
    "packet_id": 1,
    "direction": "forward",
    "flow_state": "HANDSHAKE",
    "msg": "connection not established yet"
  },
  {
    "sid": 1100061,
    "packet_id": 4,
    "flow_state": "ESTABLISHED",
    "matched": {
      "contents": [
        {
          "content": "HELLO",
          "offset": 0,
          "length": 5
        }
      ]
    }
  }
]
```
- **Kỳ vọng detection bị cấm**:
```json
[
  {
    "sid": 1100061,
    "packet_id": 1
  },
  {
    "sid": 1100062,
    "packet_id": 4
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
    "sid": 1100062,
    "rev": 1,
    "msg": "connection not established yet",
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
    "flow_state": "HANDSHAKE",
    "matched": {
      "contents": [],
      "fields": [
        "flow:not_established"
      ]
    },
    "rule_file": "TEST/BT3/t08_flow_state/test.rules"
  },
  {
    "packet_id": 4,
    "timestamp": 1700000000.3,
    "timestamp_iso": "2023-11-14T22:13:20.300000+00:00",
    "action": "alert",
    "sid": 1100061,
    "rev": 1,
    "msg": "established client data",
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
      "contents": [
        {
          "content": "HELLO",
          "offset": 0,
          "length": 5,
          "nocase": false
        }
      ],
      "fields": [
        "flow:to_server,established"
      ]
    },
    "rule_file": "TEST/BT3/t08_flow_state/test.rules"
  }
]
```
