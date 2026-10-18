# Test Case Report: bt3_t09_content_nocase

- **Mục tiêu**: nocase khớp không phân biệt hoa thường, content thường phải khớp đúng byte
- **Yêu cầu kiểm thử**: Payload chứa 'AdMiN' chỉ khớp rule nocase 1100071; payload chứa 'ADMIN' khớp cả rule nocase 1100071 lẫn rule phân biệt hoa thường 1100072; rule 1100072 không được alert trên packet 1 (vị trí match offset 11, length 5).
- **File PCAP**: `TEST/BT3/t09_content_nocase/test.pcap`
- **File Output JSONL**: `TEST/BT3/t09_content_nocase/output.jsonl`
- **File Detections**: `TEST/BT3/t09_content_nocase/detections.jsonl`
- **Số detection**: 3
- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT3/t09_content_nocase/test.pcap)
[*] Writing normalized events to: TEST/BT3/t09_content_nocase/output.jsonl
[*] Writing flow records to: TEST/BT3/t09_content_nocase/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
[*] Rules: files=1 loaded=2 invalid=0 unsupported=0
[*] Writing detections to: TEST/BT3/t09_content_nocase/detections.jsonl
------------------------------------------------------------
[ALERT] sid=1100071 rev=1 "admin token any case" 10.0.0.10:52000 -> 10.0.0.20:80 (TCP/HTTP) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=69]
[ALERT] sid=1100071 rev=1 "admin token any case" 10.0.0.11:52001 -> 10.0.0.20:80 (TCP/HTTP) flow=TCP-10.0.0.11:52001-10.0.0.20:80
[ALERT] sid=1100072 rev=1 "admin token exact case" 10.0.0.11:52001 -> 10.0.0.20:80 (TCP/HTTP) flow=TCP-10.0.0.11:52001-10.0.0.20:80
[0002] 10.0.0.11 -> 10.0.0.20 (TCP):52001 -> :80 [ACK,PSH] | HTTP (request) [len=69]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=ESTABLISHED pkts=1 bytes=69 reason=end_of_capture
[FLOW] TCP-10.0.0.11:52001-10.0.0.20:80 state=ESTABLISHED pkts=1 bytes=69 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (948.9 pkts/s)
[+] Output saved to: TEST/BT3/t09_content_nocase/output.jsonl
[+] Flow records saved to: TEST/BT3/t09_content_nocase/flows.jsonl
[+] Flows: created=2 closed=2 active_flushed=2
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=2
[+] Dropped events (preprocessor): 0
[+] Rules: loaded=2 events_evaluated=2 candidate_rules=4 matches=3
[+] Detections: 3 written to TEST/BT3/t09_content_nocase/detections.jsonl
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **2**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "application": {
      "protocol": "HTTP"
    }
  }
]
```

- Số detection tối thiểu: **3**
- Danh sách detection subset bắt buộc phải khớp:
```json
[
  {
    "sid": 1100071,
    "packet_id": 1,
    "matched": {
      "contents": [
        {
          "content": "admin",
          "nocase": true,
          "offset": 11,
          "length": 5
        }
      ]
    }
  },
  {
    "sid": 1100072,
    "packet_id": 2,
    "matched": {
      "contents": [
        {
          "content": "ADMIN",
          "nocase": false,
          "offset": 11
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
    "sid": 1100072,
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
    "raw_len": 69,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 69,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 29,
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
        "uri": "/?user=AdMiN",
        "version": "HTTP/1.1",
        "headers": {},
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/?user=AdMiN"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/?user=AdMiN"
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
      "is_new_flow": true
    },
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1700000000.1,
    "timestamp_iso": "2023-11-14T22:13:20.100000+00:00",
    "raw_len": 69,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.11",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 69,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52001,
      "dst_port": 80,
      "payload_len": 29,
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
        "uri": "/?user=ADMIN",
        "version": "HTTP/1.1",
        "headers": {},
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/?user=ADMIN"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/?user=ADMIN"
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
      "flow_id": "TCP-10.0.0.11:52001-10.0.0.20:80",
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
    "sid": 1100071,
    "packet_id": 1,
    "matched": {
      "contents": [
        {
          "content": "admin",
          "nocase": true,
          "offset": 11,
          "length": 5
        }
      ]
    }
  },
  {
    "sid": 1100072,
    "packet_id": 2,
    "matched": {
      "contents": [
        {
          "content": "ADMIN",
          "nocase": false,
          "offset": 11
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
    "sid": 1100072,
    "packet_id": 1
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
    "sid": 1100071,
    "rev": 1,
    "msg": "admin token any case",
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
          "content": "admin",
          "offset": 11,
          "length": 5,
          "nocase": true
        }
      ],
      "fields": []
    },
    "rule_file": "TEST/BT3/t09_content_nocase/test.rules"
  },
  {
    "packet_id": 2,
    "timestamp": 1700000000.1,
    "timestamp_iso": "2023-11-14T22:13:20.100000+00:00",
    "action": "alert",
    "sid": 1100071,
    "rev": 1,
    "msg": "admin token any case",
    "classtype": null,
    "priority": null,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "src_ip": "10.0.0.11",
    "src_port": 52001,
    "dst_ip": "10.0.0.20",
    "dst_port": 80,
    "direction": "forward",
    "flow_id": "TCP-10.0.0.11:52001-10.0.0.20:80",
    "flow_state": "ESTABLISHED",
    "matched": {
      "contents": [
        {
          "content": "admin",
          "offset": 11,
          "length": 5,
          "nocase": true
        }
      ],
      "fields": []
    },
    "rule_file": "TEST/BT3/t09_content_nocase/test.rules"
  },
  {
    "packet_id": 2,
    "timestamp": 1700000000.1,
    "timestamp_iso": "2023-11-14T22:13:20.100000+00:00",
    "action": "alert",
    "sid": 1100072,
    "rev": 1,
    "msg": "admin token exact case",
    "classtype": null,
    "priority": null,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "src_ip": "10.0.0.11",
    "src_port": 52001,
    "dst_ip": "10.0.0.20",
    "dst_port": 80,
    "direction": "forward",
    "flow_id": "TCP-10.0.0.11:52001-10.0.0.20:80",
    "flow_state": "ESTABLISHED",
    "matched": {
      "contents": [
        {
          "content": "ADMIN",
          "offset": 11,
          "length": 5,
          "nocase": false
        }
      ],
      "fields": []
    },
    "rule_file": "TEST/BT3/t09_content_nocase/test.rules"
  }
]
```
