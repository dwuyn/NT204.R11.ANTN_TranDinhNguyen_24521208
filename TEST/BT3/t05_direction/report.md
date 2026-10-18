# Test Case Report: bt3_t05_direction

- **Mục tiêu**: Hướng flow: to_server chỉ khớp chiều đi, to_client chỉ khớp chiều về
- **Yêu cầu kiểm thử**: Rule flow:to_server,established chỉ alert packet request (forward, packet 4) chứa 'SECRET', rule flow:to_client,established chỉ alert packet response (backward, packet 5) chứa 'TOKEN'; không có detection nào sai chiều.
- **File PCAP**: `TEST/BT3/t05_direction/test.pcap`
- **File Output JSONL**: `TEST/BT3/t05_direction/output.jsonl`
- **File Detections**: `TEST/BT3/t05_direction/detections.jsonl`
- **Số detection**: 2
- **Số gói tin đã xử lý**: 5
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT3/t05_direction/test.pcap)
[*] Writing normalized events to: TEST/BT3/t05_direction/output.jsonl
[*] Writing flow records to: TEST/BT3/t05_direction/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
[*] Rules: files=1 loaded=2 invalid=0 unsupported=0
[*] Writing detections to: TEST/BT3/t05_direction/detections.jsonl
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [SYN] [len=40]
[0002] 10.0.0.20 -> 10.0.0.10 (TCP):80 -> :52000 [SYN,ACK] [len=40]
[0003] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK] [len=40]
[ALERT] sid=1100041 rev=1 "secret prefixed request field" 10.0.0.10:52000 -> 10.0.0.20:80 (TCP/HTTP) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[0004] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=85]
[ALERT] sid=1100042 rev=1 "token in server response" 10.0.0.20:80 -> 10.0.0.10:52000 (TCP/HTTP) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[0005] 10.0.0.20 -> 10.0.0.10 (TCP):80 -> :52000 [ACK,PSH] | HTTP (response) [len=87]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=ESTABLISHED pkts=5 bytes=292 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 5 packets in 0.00s (1778.5 pkts/s)
[+] Output saved to: TEST/BT3/t05_direction/output.jsonl
[+] Flow records saved to: TEST/BT3/t05_direction/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
[+] Rules: loaded=2 events_evaluated=5 candidate_rules=10 matches=2
[+] Detections: 2 written to TEST/BT3/t05_direction/detections.jsonl
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **5**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "transport": {
      "layer": "TCP",
      "payload_len": 45
    }
  }
]
```

- Số detection tối thiểu: **2**
- Danh sách detection subset bắt buộc phải khớp:
```json
[
  {
    "sid": 1100041,
    "packet_id": 4,
    "direction": "forward",
    "flow_state": "ESTABLISHED",
    "action": "alert",
    "src_port": 52000,
    "dst_port": 80
  },
  {
    "sid": 1100042,
    "packet_id": 5,
    "direction": "backward",
    "flow_state": "ESTABLISHED",
    "src_port": 80,
    "dst_port": 52000
  }
]
```
- Danh sách detection bị cấm (không được xuất hiện):
```json
[
  {
    "sid": 1100041,
    "direction": "backward"
  },
  {
    "sid": 1100042,
    "direction": "forward"
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
    "raw_len": 85,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 85,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 45,
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
        "method": "GET",
        "uri": "/data",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "ids.local"
        },
        "body": "SECRET",
        "detection_method": "payload_signature",
        "uri_normalized": "/data"
      }
    },
    "decode": {
      "decode_status": "decoded",
      "decoders": [
        "html_entities"
      ],
      "fields": {
        "uri_decoded": "/data",
        "body_charset": "utf-8",
        "body_decode_status": "ok",
        "body_decoded": "SECRET"
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
  },
  {
    "packet_id": 5,
    "timestamp": 1700000000.4,
    "timestamp_iso": "2023-11-14T22:13:20.400000+00:00",
    "raw_len": 87,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.20",
      "dst_ip": "10.0.0.10",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 87,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 80,
      "dst_port": 52000,
      "payload_len": 47,
      "seq": 5001,
      "ack": 1046,
      "flags": [
        "ACK",
        "PSH"
      ],
      "window": 8192,
      "data_offset": 5
    },
    "application": {
      "protocol": "HTTP",
      "type": "response",
      "details": {
        "version": "HTTP/1.1",
        "status_code": 200,
        "reason": "OK",
        "headers": {
          "Content-Length": "9"
        },
        "body": "TOKEN=abc",
        "detection_method": "payload_signature"
      }
    },
    "decode": {
      "decode_status": "decoded",
      "decoders": [
        "html_entities"
      ],
      "fields": {
        "body_charset": "utf-8",
        "body_decode_status": "ok",
        "body_decoded": "TOKEN=abc"
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
      "direction": "backward",
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
    "sid": 1100041,
    "packet_id": 4,
    "direction": "forward",
    "flow_state": "ESTABLISHED",
    "action": "alert",
    "src_port": 52000,
    "dst_port": 80
  },
  {
    "sid": 1100042,
    "packet_id": 5,
    "direction": "backward",
    "flow_state": "ESTABLISHED",
    "src_port": 80,
    "dst_port": 52000
  }
]
```
- **Kỳ vọng detection bị cấm**:
```json
[
  {
    "sid": 1100041,
    "direction": "backward"
  },
  {
    "sid": 1100042,
    "direction": "forward"
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
    "sid": 1100041,
    "rev": 1,
    "msg": "secret prefixed request field",
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
          "content": "SECRET",
          "offset": 39,
          "length": 6,
          "nocase": false
        }
      ],
      "fields": [
        "flow:to_server,established"
      ]
    },
    "rule_file": "TEST/BT3/t05_direction/test.rules"
  },
  {
    "packet_id": 5,
    "timestamp": 1700000000.4,
    "timestamp_iso": "2023-11-14T22:13:20.400000+00:00",
    "action": "alert",
    "sid": 1100042,
    "rev": 1,
    "msg": "token in server response",
    "classtype": null,
    "priority": null,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "src_ip": "10.0.0.20",
    "src_port": 80,
    "dst_ip": "10.0.0.10",
    "dst_port": 52000,
    "direction": "backward",
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "flow_state": "ESTABLISHED",
    "matched": {
      "contents": [
        {
          "content": "TOKEN",
          "offset": 38,
          "length": 5,
          "nocase": false
        }
      ],
      "fields": [
        "flow:to_client,established"
      ]
    },
    "rule_file": "TEST/BT3/t05_direction/test.rules"
  }
]
```
