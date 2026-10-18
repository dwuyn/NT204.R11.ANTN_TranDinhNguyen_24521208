# Test Case Report: bt3_t13_multi_rule_match

- **Mục tiêu**: Mặc định không dừng ở match đầu: một packet khớp cả ba rule
- **Yêu cầu kiểm thử**: Packet POST /login khớp đồng thời ba rule (content 'POST', POST+flow+flags+dsize và '/login') và cả ba detection đều được sinh cho packet 4; các packet bắt tay không sinh detection nào.
- **File PCAP**: `TEST/BT3/t13_multi_rule_match/test.pcap`
- **File Output JSONL**: `TEST/BT3/t13_multi_rule_match/output.jsonl`
- **File Detections**: `TEST/BT3/t13_multi_rule_match/detections.jsonl`
- **Số detection**: 3
- **Số gói tin đã xử lý**: 4
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT3/t13_multi_rule_match/test.pcap)
[*] Writing normalized events to: TEST/BT3/t13_multi_rule_match/output.jsonl
[*] Writing flow records to: TEST/BT3/t13_multi_rule_match/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
[*] Rules: files=1 loaded=3 invalid=0 unsupported=0
[*] Writing detections to: TEST/BT3/t13_multi_rule_match/detections.jsonl
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [SYN] [len=40]
[0002] 10.0.0.20 -> 10.0.0.10 (TCP):80 -> :52000 [SYN,ACK] [len=40]
[0003] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK] [len=40]
[ALERT] sid=1100111 rev=1 "http post seen" 10.0.0.10:52000 -> 10.0.0.20:80 (TCP/HTTP) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[ALERT] sid=1100112 rev=1 "established post with data" 10.0.0.10:52000 -> 10.0.0.20:80 (TCP/HTTP) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[ALERT] sid=1100113 rev=1 "login endpoint" 10.0.0.10:52000 -> 10.0.0.20:80 (TCP/HTTP) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[0004] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=107]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=ESTABLISHED pkts=4 bytes=227 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 4 packets in 0.00s (1478.2 pkts/s)
[+] Output saved to: TEST/BT3/t13_multi_rule_match/output.jsonl
[+] Flow records saved to: TEST/BT3/t13_multi_rule_match/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
[+] Rules: loaded=3 events_evaluated=4 candidate_rules=9 matches=3
[+] Detections: 3 written to TEST/BT3/t13_multi_rule_match/detections.jsonl
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **4**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "application": {
      "protocol": "HTTP",
      "type": "request"
    }
  }
]
```

- Số detection tối thiểu: **3**
- Danh sách detection subset bắt buộc phải khớp:
```json
[
  {
    "sid": 1100111,
    "packet_id": 4,
    "msg": "http post seen"
  },
  {
    "sid": 1100112,
    "packet_id": 4,
    "matched": {
      "fields": [
        "flow:to_server,established",
        "flags:PA",
        "dsize:>0"
      ]
    }
  },
  {
    "sid": 1100113,
    "packet_id": 4,
    "matched": {
      "contents": [
        {
          "content": "/login"
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
    "sid": 1100111,
    "packet_id": 1
  },
  {
    "sid": 1100112,
    "packet_id": 1
  },
  {
    "sid": 1100113,
    "packet_id": 1
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
    "raw_len": 107,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 107,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 67,
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
      "protocol": "HTTP",
      "type": "request",
      "details": {
        "method": "POST",
        "uri": "/login",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "ids.local",
          "Content-Length": "7"
        },
        "body": "user=ab",
        "detection_method": "payload_signature",
        "uri_normalized": "/login"
      }
    },
    "decode": {
      "decode_status": "decoded",
      "decoders": [
        "html_entities"
      ],
      "fields": {
        "uri_decoded": "/login",
        "body_charset": "utf-8",
        "body_decode_status": "ok",
        "body_decoded": "user=ab"
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
- **Số detection**: 3
- **Số detection tối thiểu**: 3
- **Kỳ vọng detection (JSON subset bắt buộc khớp)**:
```json
[
  {
    "sid": 1100111,
    "packet_id": 4,
    "msg": "http post seen"
  },
  {
    "sid": 1100112,
    "packet_id": 4,
    "matched": {
      "fields": [
        "flow:to_server,established",
        "flags:PA",
        "dsize:>0"
      ]
    }
  },
  {
    "sid": 1100113,
    "packet_id": 4,
    "matched": {
      "contents": [
        {
          "content": "/login"
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
    "sid": 1100111,
    "packet_id": 1
  },
  {
    "sid": 1100112,
    "packet_id": 1
  },
  {
    "sid": 1100113,
    "packet_id": 1
  }
]
```
- **Chi tiết detection records**:
```json
[
  {
    "packet_id": 4,
    "timestamp": 1700000000.3,
    "timestamp_iso": "2023-11-14T22:13:20.300000+00:00",
    "action": "alert",
    "sid": 1100111,
    "rev": 1,
    "msg": "http post seen",
    "classtype": null,
    "priority": null,
    "protocol": "TCP",
    "application_protocol": "HTTP",
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
          "content": "POST",
          "offset": 0,
          "length": 4,
          "nocase": false
        }
      ],
      "fields": []
    },
    "rule_file": "TEST/BT3/t13_multi_rule_match/test.rules"
  },
  {
    "packet_id": 4,
    "timestamp": 1700000000.3,
    "timestamp_iso": "2023-11-14T22:13:20.300000+00:00",
    "action": "alert",
    "sid": 1100112,
    "rev": 1,
    "msg": "established post with data",
    "classtype": null,
    "priority": null,
    "protocol": "TCP",
    "application_protocol": "HTTP",
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
          "content": "POST",
          "offset": 0,
          "length": 4,
          "nocase": false
        }
      ],
      "fields": [
        "flow:to_server,established",
        "flags:PA",
        "dsize:>0"
      ]
    },
    "rule_file": "TEST/BT3/t13_multi_rule_match/test.rules"
  },
  {
    "packet_id": 4,
    "timestamp": 1700000000.3,
    "timestamp_iso": "2023-11-14T22:13:20.300000+00:00",
    "action": "alert",
    "sid": 1100113,
    "rev": 1,
    "msg": "login endpoint",
    "classtype": null,
    "priority": null,
    "protocol": "TCP",
    "application_protocol": "HTTP",
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
          "content": "/login",
          "offset": 5,
          "length": 6,
          "nocase": false
        }
      ],
      "fields": []
    },
    "rule_file": "TEST/BT3/t13_multi_rule_match/test.rules"
  }
]
```
