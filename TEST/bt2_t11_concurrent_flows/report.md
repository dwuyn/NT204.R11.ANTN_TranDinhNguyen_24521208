# Test Case Report: bt2_t11_concurrent_flows

- **Mục tiêu**: Theo dõi đồng thời ba flow xen kẽ nhau
- **Yêu cầu kiểm thử**: Sáu packet thuộc ba 5-tuple xen kẽ tạo đúng 3 flow record, mỗi flow 2 packet.
- **File PCAP**: `TEST/bt2_t11_concurrent_flows/test.pcap`
- **File Output JSONL**: `TEST/bt2_t11_concurrent_flows/output.jsonl`
- **File Flow Records**: `TEST/bt2_t11_concurrent_flows/flows.jsonl`
- **Số flow record**: 3- **Số gói tin đã xử lý**: 6
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t11_concurrent_flows/test.pcap)
[*] Writing normalized events to: TEST/bt2_t11_concurrent_flows/output.jsonl
[*] Writing flow records to: TEST/bt2_t11_concurrent_flows/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=69]
[0002] 10.0.0.11 -> 10.0.0.20 (TCP):52001 -> :80 [ACK,PSH] | HTTP (request) [len=69]
[0003] 10.0.0.10 -> 10.0.0.30 (TCP):52002 -> :443 [ACK,PSH] | HTTP (request) [len=69]
[0004] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=70]
[0005] 10.0.0.11 -> 10.0.0.20 (TCP):52001 -> :80 [ACK,PSH] | HTTP (request) [len=70]
[0006] 10.0.0.10 -> 10.0.0.30 (TCP):52002 -> :443 [ACK,PSH] | HTTP (request) [len=70]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=ESTABLISHED pkts=2 bytes=139 reason=end_of_capture
[FLOW] TCP-10.0.0.11:52001-10.0.0.20:80 state=ESTABLISHED pkts=2 bytes=139 reason=end_of_capture
[FLOW] TCP-10.0.0.10:52002-10.0.0.30:443 state=ESTABLISHED pkts=2 bytes=139 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 6 packets in 0.00s (1530.5 pkts/s)
[+] Output saved to: TEST/bt2_t11_concurrent_flows/output.jsonl
[+] Flow records saved to: TEST/bt2_t11_concurrent_flows/flows.jsonl
[+] Flows: created=3 closed=3 active_flushed=3
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=3
[+] Dropped events (preprocessor): 0
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **6**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "flow": {
      "direction": "forward"
    }
  }
]
```
- Số flow tối thiểu: **3**
- Danh sách flow subset bắt buộc phải khớp:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "packet_count": 2
  },
  {
    "flow_id": "TCP-10.0.0.11:52001-10.0.0.20:80",
    "packet_count": 2
  },
  {
    "flow_id": "TCP-10.0.0.10:52002-10.0.0.30:443",
    "packet_count": 2
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
        "uri": "/f1",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "a"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/f1"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/f1"
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
    "timestamp": 1700000000.01,
    "timestamp_iso": "2023-11-14T22:13:20.010000+00:00",
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
        "uri": "/f2",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "a"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/f2"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/f2"
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
  },
  {
    "packet_id": 3,
    "timestamp": 1700000000.02,
    "timestamp_iso": "2023-11-14T22:13:20.020000+00:00",
    "raw_len": 69,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.30",
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
      "src_port": 52002,
      "dst_port": 443,
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
        "uri": "/f3",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "a"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/f3"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/f3"
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
      "flow_id": "TCP-10.0.0.10:52002-10.0.0.30:443",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  },
  {
    "packet_id": 4,
    "timestamp": 1700000000.03,
    "timestamp_iso": "2023-11-14T22:13:20.030000+00:00",
    "raw_len": 70,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
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
      "src_port": 52000,
      "dst_port": 80,
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
      "protocol": "HTTP",
      "type": "request",
      "details": {
        "method": "GET",
        "uri": "/f1b",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "a"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/f1b"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/f1b"
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
    "timestamp": 1700000000.04,
    "timestamp_iso": "2023-11-14T22:13:20.040000+00:00",
    "raw_len": 70,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.11",
      "dst_ip": "10.0.0.20",
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
      "src_port": 52001,
      "dst_port": 80,
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
      "protocol": "HTTP",
      "type": "request",
      "details": {
        "method": "GET",
        "uri": "/f2b",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "a"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/f2b"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/f2b"
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
      "is_new_flow": false
    },
    "errors": []
  },
  {
    "packet_id": 6,
    "timestamp": 1700000000.05,
    "timestamp_iso": "2023-11-14T22:13:20.050000+00:00",
    "raw_len": 70,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.30",
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
      "src_port": 52002,
      "dst_port": 443,
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
      "protocol": "HTTP",
      "type": "request",
      "details": {
        "method": "GET",
        "uri": "/f3b",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "a"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/f3b"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/f3b"
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
      "flow_id": "TCP-10.0.0.10:52002-10.0.0.30:443",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": false
    },
    "errors": []
  }
]
```

## 5. Flow Records (flows.jsonl)
- **Số flow record**: 3
- **Số flow tối thiểu**: 3
- **Kỳ vọng flow (JSON subset)**:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "packet_count": 2
  },
  {
    "flow_id": "TCP-10.0.0.11:52001-10.0.0.20:80",
    "packet_count": 2
  },
  {
    "flow_id": "TCP-10.0.0.10:52002-10.0.0.30:443",
    "packet_count": 2
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
    "last_seen": 1700000000.03,
    "duration": 0.03,
    "packet_count": 2,
    "byte_count": 139,
    "forward": {
      "packet_count": 2,
      "byte_count": 139
    },
    "backward": {
      "packet_count": 0,
      "byte_count": 0
    },
    "syn_count": 0,
    "ack_count": 2,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "end_of_capture"
  },
  {
    "flow_id": "TCP-10.0.0.11:52001-10.0.0.20:80",
    "flow_seq": 2,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "endpoint_a": {
      "ip": "10.0.0.11",
      "port": 52001
    },
    "endpoint_b": {
      "ip": "10.0.0.20",
      "port": 80
    },
    "state": "ESTABLISHED",
    "start_time": 1700000000.01,
    "last_seen": 1700000000.04,
    "duration": 0.03,
    "packet_count": 2,
    "byte_count": 139,
    "forward": {
      "packet_count": 2,
      "byte_count": 139
    },
    "backward": {
      "packet_count": 0,
      "byte_count": 0
    },
    "syn_count": 0,
    "ack_count": 2,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "end_of_capture"
  },
  {
    "flow_id": "TCP-10.0.0.10:52002-10.0.0.30:443",
    "flow_seq": 3,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "endpoint_a": {
      "ip": "10.0.0.10",
      "port": 52002
    },
    "endpoint_b": {
      "ip": "10.0.0.30",
      "port": 443
    },
    "state": "ESTABLISHED",
    "start_time": 1700000000.02,
    "last_seen": 1700000000.05,
    "duration": 0.03,
    "packet_count": 2,
    "byte_count": 139,
    "forward": {
      "packet_count": 2,
      "byte_count": 139
    },
    "backward": {
      "packet_count": 0,
      "byte_count": 0
    },
    "syn_count": 0,
    "ack_count": 2,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "end_of_capture"
  }
]
```
