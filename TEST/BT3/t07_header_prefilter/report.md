# Test Case Report: bt3_t07_header_prefilter

- **Mục tiêu**: Header rule quyết định: cùng content 'EVIL' nhưng chỉ đúng đích mới alert
- **Yêu cầu kiểm thử**: Ba packet TCP đều chứa 'EVIL' nhưng chỉ packet tới 10.0.0.50:80 khớp rule 1100052 và packet tới 10.0.0.100:4444 khớp rule 1100051; packet tới 10.0.0.60:9999 không khớp rule nào; packet UDP chứa 'version.bind' khớp rule DNS 1100053.
- **File PCAP**: `TEST/BT3/t07_header_prefilter/test.pcap`
- **File Output JSONL**: `TEST/BT3/t07_header_prefilter/output.jsonl`
- **File Detections**: `TEST/BT3/t07_header_prefilter/detections.jsonl`
- **Số detection**: 3
- **Số gói tin đã xử lý**: 4
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT3/t07_header_prefilter/test.pcap)
[*] Writing normalized events to: TEST/BT3/t07_header_prefilter/output.jsonl
[*] Writing flow records to: TEST/BT3/t07_header_prefilter/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
[*] Rules: files=1 loaded=3 invalid=0 unsupported=0
[*] Writing detections to: TEST/BT3/t07_header_prefilter/detections.jsonl
------------------------------------------------------------
[ALERT] sid=1100052 rev=1 "evil over http" 10.0.0.10:50000 -> 10.0.0.50:80 (TCP/HTTP) flow=TCP-10.0.0.10:50000-10.0.0.50:80
[0001] 10.0.0.10 -> 10.0.0.50 (TCP):50000 -> :80 [ACK,PSH] | HTTP (request) [len=75]
[ALERT] sid=1100051 rev=1 "evil on service port" 10.0.0.11:50001 -> 10.0.0.100:4444 (TCP/UNKNOWN) flow=TCP-10.0.0.11:50001-10.0.0.100:4444
[0002] 10.0.0.11 -> 10.0.0.100 (TCP):50001 -> :4444 [ACK,PSH] [len=52]
[0003] 10.0.0.12 -> 10.0.0.60 (TCP):50002 -> :9999 [ACK,PSH] [len=50]
[ALERT] sid=1100053 rev=1 "dns version bind attempt" 10.0.0.13:53000 -> 8.8.8.8:53 (UDP/DNS) flow=UDP-10.0.0.13:53000-8.8.8.8:53
[0004] 10.0.0.13 -> 8.8.8.8 (UDP):53000 -> :53 | DNS (query) [len=40]
[FLOW] TCP-10.0.0.10:50000-10.0.0.50:80 state=ESTABLISHED pkts=1 bytes=75 reason=end_of_capture
[FLOW] TCP-10.0.0.11:50001-10.0.0.100:4444 state=ESTABLISHED pkts=1 bytes=52 reason=end_of_capture
[FLOW] TCP-10.0.0.12:50002-10.0.0.60:9999 state=ESTABLISHED pkts=1 bytes=50 reason=end_of_capture
[FLOW] UDP-10.0.0.13:53000-8.8.8.8:53 state=ESTABLISHED pkts=1 bytes=40 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 4 packets in 0.36s (11.2 pkts/s)
[+] Output saved to: TEST/BT3/t07_header_prefilter/output.jsonl
[+] Flow records saved to: TEST/BT3/t07_header_prefilter/flows.jsonl
[+] Flows: created=4 closed=4 active_flushed=4
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=4
[+] Dropped events (preprocessor): 0
[+] Rules: loaded=3 events_evaluated=4 candidate_rules=3 matches=3
[+] Detections: 3 written to TEST/BT3/t07_header_prefilter/detections.jsonl
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **4**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "transport": {
      "layer": "UDP",
      "payload_len": 12
    }
  }
]
```

- Số detection tối thiểu: **3**
- Danh sách detection subset bắt buộc phải khớp:
```json
[
  {
    "sid": 1100052,
    "packet_id": 1,
    "dst_ip": "10.0.0.50",
    "dst_port": 80
  },
  {
    "sid": 1100051,
    "packet_id": 2,
    "dst_ip": "10.0.0.100",
    "dst_port": 4444
  },
  {
    "sid": 1100053,
    "packet_id": 4,
    "protocol": "UDP",
    "dst_ip": "8.8.8.8",
    "dst_port": 53,
    "matched": {
      "contents": [
        {
          "content": "version.bind",
          "nocase": true
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
    "sid": 1100051,
    "packet_id": 1
  },
  {
    "sid": 1100052,
    "packet_id": 2
  },
  {
    "dst_port": 9999
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
    "raw_len": 75,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.50",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 75,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 50000,
      "dst_port": 80,
      "payload_len": 35,
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
        "uri": "/x?q=EVIL",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "t"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/x?q=EVIL"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/x?q=EVIL"
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
      "flow_id": "TCP-10.0.0.10:50000-10.0.0.50:80",
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
    "raw_len": 52,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.11",
      "dst_ip": "10.0.0.100",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 52,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 50001,
      "dst_port": 4444,
      "payload_len": 12,
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
      "flow_id": "TCP-10.0.0.11:50001-10.0.0.100:4444",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  },
  {
    "packet_id": 3,
    "timestamp": 1700000000.2,
    "timestamp_iso": "2023-11-14T22:13:20.200000+00:00",
    "raw_len": 50,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.12",
      "dst_ip": "10.0.0.60",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 50,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 50002,
      "dst_port": 9999,
      "payload_len": 10,
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
      "flow_id": "TCP-10.0.0.12:50002-10.0.0.60:9999",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  },
  {
    "packet_id": 4,
    "timestamp": 1700000000.3,
    "timestamp_iso": "2023-11-14T22:13:20.300000+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.13",
      "dst_ip": "8.8.8.8",
      "proto": "UDP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 40,
      "flags": []
    },
    "transport": {
      "layer": "UDP",
      "src_port": 53000,
      "dst_port": 53,
      "payload_len": 12,
      "checksum": 34087
    },
    "application": {
      "protocol": "DNS",
      "type": "query",
      "details": {
        "transaction_id": 30309,
        "qr": 0,
        "opcode": "OPCODE_14",
        "rcode": "NXDOMAIN",
        "queries": [
          {
            "name": "www.example.com",
            "type": "A"
          }
        ],
        "answers": [],
        "detection_method": "scapy_layer"
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
      "flow_id": "UDP-10.0.0.13:53000-8.8.8.8:53",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
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
    "sid": 1100052,
    "packet_id": 1,
    "dst_ip": "10.0.0.50",
    "dst_port": 80
  },
  {
    "sid": 1100051,
    "packet_id": 2,
    "dst_ip": "10.0.0.100",
    "dst_port": 4444
  },
  {
    "sid": 1100053,
    "packet_id": 4,
    "protocol": "UDP",
    "dst_ip": "8.8.8.8",
    "dst_port": 53,
    "matched": {
      "contents": [
        {
          "content": "version.bind",
          "nocase": true
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
    "sid": 1100051,
    "packet_id": 1
  },
  {
    "sid": 1100052,
    "packet_id": 2
  },
  {
    "dst_port": 9999
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
    "sid": 1100052,
    "rev": 1,
    "msg": "evil over http",
    "classtype": null,
    "priority": null,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "src_ip": "10.0.0.10",
    "src_port": 50000,
    "dst_ip": "10.0.0.50",
    "dst_port": 80,
    "direction": "forward",
    "flow_id": "TCP-10.0.0.10:50000-10.0.0.50:80",
    "flow_state": "ESTABLISHED",
    "matched": {
      "contents": [
        {
          "content": "EVIL",
          "offset": 9,
          "length": 4,
          "nocase": false
        }
      ],
      "fields": []
    },
    "rule_file": "TEST/BT3/t07_header_prefilter/test.rules"
  },
  {
    "packet_id": 2,
    "timestamp": 1700000000.1,
    "timestamp_iso": "2023-11-14T22:13:20.100000+00:00",
    "action": "alert",
    "sid": 1100051,
    "rev": 1,
    "msg": "evil on service port",
    "classtype": null,
    "priority": null,
    "protocol": "TCP",
    "application_protocol": "UNKNOWN",
    "src_ip": "10.0.0.11",
    "src_port": 50001,
    "dst_ip": "10.0.0.100",
    "dst_port": 4444,
    "direction": "forward",
    "flow_id": "TCP-10.0.0.11:50001-10.0.0.100:4444",
    "flow_state": "ESTABLISHED",
    "matched": {
      "contents": [
        {
          "content": "EVIL",
          "offset": 0,
          "length": 4,
          "nocase": false
        }
      ],
      "fields": []
    },
    "rule_file": "TEST/BT3/t07_header_prefilter/test.rules"
  },
  {
    "packet_id": 4,
    "timestamp": 1700000000.3,
    "timestamp_iso": "2023-11-14T22:13:20.300000+00:00",
    "action": "alert",
    "sid": 1100053,
    "rev": 1,
    "msg": "dns version bind attempt",
    "classtype": null,
    "priority": null,
    "protocol": "UDP",
    "application_protocol": "DNS",
    "src_ip": "10.0.0.13",
    "src_port": 53000,
    "dst_ip": "8.8.8.8",
    "dst_port": 53,
    "direction": "forward",
    "flow_id": "UDP-10.0.0.13:53000-8.8.8.8:53",
    "flow_state": "ESTABLISHED",
    "matched": {
      "contents": [
        {
          "content": "version.bind",
          "offset": 0,
          "length": 12,
          "nocase": true
        }
      ],
      "fields": []
    },
    "rule_file": "TEST/BT3/t07_header_prefilter/test.rules"
  }
]
```
