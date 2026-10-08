# Test Case Report: bt2_t13_statistics

- **Mục tiêu**: Thống kê chi tiết một flow TCP đầy đủ vòng đời
- **Yêu cầu kiểm thử**: Flow 8 packet ghi đúng start_time/last_seen/duration 0.7s, byte_count 392 (192 xuôi + 200 ngược), 2 SYN, 7 ACK, 2 FIN, 0 RST, CLOSED/fin.
- **File PCAP**: `TEST/bt2_t13_statistics/test.pcap`
- **File Output JSONL**: `TEST/bt2_t13_statistics/output.jsonl`
- **File Flow Records**: `TEST/bt2_t13_statistics/flows.jsonl`
- **Số flow record**: 1- **Số gói tin đã xử lý**: 8
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t13_statistics/test.pcap)
[*] Writing normalized events to: TEST/bt2_t13_statistics/output.jsonl
[*] Writing flow records to: TEST/bt2_t13_statistics/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.1.1.1 -> 10.1.1.2 (TCP):40000 -> :80 [SYN] [len=40]
[0002] 10.1.1.2 -> 10.1.1.1 (TCP):80 -> :40000 [SYN,ACK] [len=40]
[0003] 10.1.1.1 -> 10.1.1.2 (TCP):40000 -> :80 [ACK] [len=40]
[0004] 10.1.1.1 -> 10.1.1.2 (TCP):40000 -> :80 [ACK,PSH] | HTTP (request) [len=72]
[0005] 10.1.1.2 -> 10.1.1.1 (TCP):80 -> :40000 [ACK,PSH] | HTTP (response) [len=80]
[0006] 10.1.1.1 -> 10.1.1.2 (TCP):40000 -> :80 [ACK,FIN] [len=40]
[0007] 10.1.1.2 -> 10.1.1.1 (TCP):80 -> :40000 [ACK] [len=40]
[FLOW] TCP-10.1.1.1:40000-10.1.1.2:80 state=CLOSED pkts=8 bytes=392 reason=fin
[0008] 10.1.1.2 -> 10.1.1.1 (TCP):80 -> :40000 [ACK,FIN] [len=40]
------------------------------------------------------------
[+] Finished: Processed 8 packets in 0.01s (1467.1 pkts/s)
[+] Output saved to: TEST/bt2_t13_statistics/output.jsonl
[+] Flow records saved to: TEST/bt2_t13_statistics/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=0
[+] Flow close reasons: fin=1 rst=0 timeout=0 overflow=0 end_of_capture=0
[+] Dropped events (preprocessor): 0
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **8**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "decode": {
      "fields": {
        "body_decoded": "OK"
      }
    }
  }
]
```
- Số flow tối thiểu: **1**
- Danh sách flow subset bắt buộc phải khớp:
```json
[
  {
    "packet_count": 8,
    "byte_count": 392,
    "start_time": 1700000000.0,
    "last_seen": 1700000000.7,
    "duration": 0.7,
    "forward": {
      "packet_count": 4,
      "byte_count": 192
    },
    "backward": {
      "packet_count": 4,
      "byte_count": 200
    },
    "syn_count": 2,
    "ack_count": 7,
    "fin_count": 2,
    "rst_count": 0,
    "state": "CLOSED",
    "close_reason": "fin"
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
      "src_ip": "10.1.1.1",
      "dst_ip": "10.1.1.2",
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
      "src_port": 40000,
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
      "flow_id": "TCP-10.1.1.1:40000-10.1.1.2:80",
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
      "src_ip": "10.1.1.2",
      "dst_ip": "10.1.1.1",
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
      "dst_port": 40000,
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
      "flow_id": "TCP-10.1.1.1:40000-10.1.1.2:80",
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
      "src_ip": "10.1.1.1",
      "dst_ip": "10.1.1.2",
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
      "src_port": 40000,
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
      "flow_id": "TCP-10.1.1.1:40000-10.1.1.2:80",
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
    "raw_len": 72,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.1.1.1",
      "dst_ip": "10.1.1.2",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 72,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 40000,
      "dst_port": 80,
      "payload_len": 32,
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
        "uri": "/stats",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "x"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/stats"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/stats"
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
      "flow_id": "TCP-10.1.1.1:40000-10.1.1.2:80",
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
    "raw_len": 80,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.1.1.2",
      "dst_ip": "10.1.1.1",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 80,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 80,
      "dst_port": 40000,
      "payload_len": 40,
      "seq": 5001,
      "ack": 1033,
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
          "Content-Length": "2"
        },
        "body": "OK",
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
        "body_decoded": "OK"
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
      "flow_id": "TCP-10.1.1.1:40000-10.1.1.2:80",
      "direction": "backward",
      "state": "ESTABLISHED",
      "is_new_flow": false
    },
    "errors": []
  },
  {
    "packet_id": 6,
    "timestamp": 1700000000.5,
    "timestamp_iso": "2023-11-14T22:13:20.500000+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.1.1.1",
      "dst_ip": "10.1.1.2",
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
      "src_port": 40000,
      "dst_port": 80,
      "payload_len": 0,
      "seq": 1001,
      "ack": 5001,
      "flags": [
        "ACK",
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
      "flow_id": "TCP-10.1.1.1:40000-10.1.1.2:80",
      "direction": "forward",
      "state": "CLOSING",
      "is_new_flow": false
    },
    "errors": []
  },
  {
    "packet_id": 7,
    "timestamp": 1700000000.6,
    "timestamp_iso": "2023-11-14T22:13:20.600000+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.1.1.2",
      "dst_ip": "10.1.1.1",
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
      "dst_port": 40000,
      "payload_len": 0,
      "seq": 5001,
      "ack": 1002,
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
      "flow_id": "TCP-10.1.1.1:40000-10.1.1.2:80",
      "direction": "backward",
      "state": "CLOSING",
      "is_new_flow": false
    },
    "errors": []
  },
  {
    "packet_id": 8,
    "timestamp": 1700000000.7,
    "timestamp_iso": "2023-11-14T22:13:20.700000+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.1.1.2",
      "dst_ip": "10.1.1.1",
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
      "dst_port": 40000,
      "payload_len": 0,
      "seq": 5001,
      "ack": 1002,
      "flags": [
        "ACK",
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
      "flow_id": "TCP-10.1.1.1:40000-10.1.1.2:80",
      "direction": "backward",
      "state": "CLOSED",
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
    "packet_count": 8,
    "byte_count": 392,
    "start_time": 1700000000.0,
    "last_seen": 1700000000.7,
    "duration": 0.7,
    "forward": {
      "packet_count": 4,
      "byte_count": 192
    },
    "backward": {
      "packet_count": 4,
      "byte_count": 200
    },
    "syn_count": 2,
    "ack_count": 7,
    "fin_count": 2,
    "rst_count": 0,
    "state": "CLOSED",
    "close_reason": "fin"
  }
]
```
- **Chi tiết flow records**:
```json
[
  {
    "flow_id": "TCP-10.1.1.1:40000-10.1.1.2:80",
    "flow_seq": 1,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "endpoint_a": {
      "ip": "10.1.1.1",
      "port": 40000
    },
    "endpoint_b": {
      "ip": "10.1.1.2",
      "port": 80
    },
    "state": "CLOSED",
    "start_time": 1700000000.0,
    "last_seen": 1700000000.7,
    "duration": 0.7,
    "packet_count": 8,
    "byte_count": 392,
    "forward": {
      "packet_count": 4,
      "byte_count": 192
    },
    "backward": {
      "packet_count": 4,
      "byte_count": 200
    },
    "syn_count": 2,
    "ack_count": 7,
    "fin_count": 2,
    "rst_count": 0,
    "closed": true,
    "close_reason": "fin"
  }
]
```
