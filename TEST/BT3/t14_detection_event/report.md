# Test Case Report: bt3_t14_detection_event

- **Mục tiêu**: Detection Event đầy đủ trường theo mục 5 của đề bài
- **Yêu cầu kiểm thử**: Detection cho packet 4 chứa đủ thông tin: timestamp (1700000000.3), sid/rev/msg, classtype attempted-admin, priority 1, 5-tuple, protocol TCP/HTTP, direction forward, flow_id/flow_state, thông tin match (content /etc/passwd offset 7 kèm các field flow/flags/dsize) và file rule nguồn.
- **File PCAP**: `TEST/BT3/t14_detection_event/test.pcap`
- **File Output JSONL**: `TEST/BT3/t14_detection_event/output.jsonl`
- **File Flow Records**: `TEST/BT3/t14_detection_event/flows.jsonl`
- **Số flow record**: 1
- **File Detections**: `TEST/BT3/t14_detection_event/detections.jsonl`
- **Số detection**: 1
- **Số gói tin đã xử lý**: 4
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT3/t14_detection_event/test.pcap)
[*] Writing normalized events to: TEST/BT3/t14_detection_event/output.jsonl
[*] Writing flow records to: TEST/BT3/t14_detection_event/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
[*] Rules: files=1 loaded=1 invalid=0 unsupported=0
[*] Writing detections to: TEST/BT3/t14_detection_event/detections.jsonl
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [SYN] [len=40]
[0002] 10.0.0.20 -> 10.0.0.10 (TCP):80 -> :52000 [SYN,ACK] [len=40]
[0003] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK] [len=40]
[ALERT] sid=1100121 rev=2 "Directory traversal detected" 10.0.0.10:52000 -> 10.0.0.20:80 (TCP/HTTP) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[0004] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=88]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=ESTABLISHED pkts=4 bytes=208 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 4 packets in 0.00s (1659.3 pkts/s)
[+] Output saved to: TEST/BT3/t14_detection_event/output.jsonl
[+] Flow records saved to: TEST/BT3/t14_detection_event/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
[+] Rules: loaded=1 events_evaluated=4 candidate_rules=3 matches=1
[+] Detections: 1 written to TEST/BT3/t14_detection_event/detections.jsonl
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
- Số flow tối thiểu: **1**
- Danh sách flow subset bắt buộc phải khớp:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "application_protocol": "HTTP",
    "state": "ESTABLISHED",
    "packet_count": 4
  }
]
```
- Số detection tối thiểu: **1**
- Danh sách detection subset bắt buộc phải khớp:
```json
[
  {
    "packet_id": 4,
    "timestamp": 1700000000.3,
    "timestamp_iso": "2023-11-14T22:13:20.300000+00:00",
    "action": "alert",
    "sid": 1100121,
    "rev": 2,
    "msg": "Directory traversal detected",
    "classtype": "attempted-admin",
    "priority": 1,
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
          "content": "/etc/passwd",
          "offset": 7,
          "length": 11,
          "nocase": true
        }
      ],
      "fields": [
        "flow:to_server,established",
        "flags:PA",
        "dsize:>0"
      ]
    },
    "rule_file": "TEST/BT3/t14_detection_event/test.rules"
  }
]
```
- Danh sách detection bị cấm (không được xuất hiện):
```json
[
  {
    "sid": 1100121,
    "direction": "backward"
  },
  {
    "sid": 1100121,
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
    "raw_len": 88,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 88,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 48,
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
        "uri": "/../etc/passwd",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "ids.local"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/etc/passwd"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/../etc/passwd"
      },
      "warnings": []
    },
    "preprocess": {
      "preprocess_status": "valid",
      "processing_action": "forward",
      "reason": null,
      "normalizations": [
        "uri_path"
      ],
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

## 5. Flow Records (flows.jsonl)
- **Số flow record**: 1
- **Số flow tối thiểu**: 1
- **Kỳ vọng flow (JSON subset)**:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "application_protocol": "HTTP",
    "state": "ESTABLISHED",
    "packet_count": 4
  }
]
```
- **Chi tiết flow records**:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "flow_seq": 1,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "endpoint_a": {
      "ip": "10.0.0.10",
      "port": 52000
    },
    "endpoint_b": {
      "ip": "10.0.0.20",
      "port": 80
    },
    "state": "ESTABLISHED",
    "start_time": 1700000000.0,
    "last_seen": 1700000000.3,
    "duration": 0.3,
    "packet_count": 4,
    "byte_count": 208,
    "forward": {
      "packet_count": 3,
      "byte_count": 168
    },
    "backward": {
      "packet_count": 1,
      "byte_count": 40
    },
    "syn_count": 2,
    "ack_count": 3,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "end_of_capture"
  }
]
```

## 6. Detection Events (detections.jsonl)
- **Số detection**: 1
- **Số detection tối thiểu**: 1
- **Kỳ vọng detection (JSON subset bắt buộc khớp)**:
```json
[
  {
    "packet_id": 4,
    "timestamp": 1700000000.3,
    "timestamp_iso": "2023-11-14T22:13:20.300000+00:00",
    "action": "alert",
    "sid": 1100121,
    "rev": 2,
    "msg": "Directory traversal detected",
    "classtype": "attempted-admin",
    "priority": 1,
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
          "content": "/etc/passwd",
          "offset": 7,
          "length": 11,
          "nocase": true
        }
      ],
      "fields": [
        "flow:to_server,established",
        "flags:PA",
        "dsize:>0"
      ]
    },
    "rule_file": "TEST/BT3/t14_detection_event/test.rules"
  }
]
```
- **Kỳ vọng detection bị cấm**:
```json
[
  {
    "sid": 1100121,
    "direction": "backward"
  },
  {
    "sid": 1100121,
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
    "sid": 1100121,
    "rev": 2,
    "msg": "Directory traversal detected",
    "classtype": "attempted-admin",
    "priority": 1,
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
          "content": "/etc/passwd",
          "offset": 7,
          "length": 11,
          "nocase": true
        }
      ],
      "fields": [
        "flow:to_server,established",
        "flags:PA",
        "dsize:>0"
      ]
    },
    "rule_file": "TEST/BT3/t14_detection_event/test.rules"
  }
]
```
