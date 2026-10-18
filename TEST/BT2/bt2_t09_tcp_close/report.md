# Test Case Report: bt2_t09_tcp_close

- **Mục tiêu**: Đóng flow TCP bằng FIN hai chiều và bằng RST
- **Yêu cầu kiểm thử**: Flow 1 chuyển CLOSED/fin với 2 FIN và 6 packet; flow 2 chuyển RESET/rst với 1 RST.
- **File PCAP**: `TEST/bt2_t09_tcp_close/test.pcap`
- **File Output JSONL**: `TEST/bt2_t09_tcp_close/output.jsonl`
- **File Flow Records**: `TEST/bt2_t09_tcp_close/flows.jsonl`
- **Số flow record**: 2- **Số gói tin đã xử lý**: 8
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t09_tcp_close/test.pcap)
[*] Writing normalized events to: TEST/bt2_t09_tcp_close/output.jsonl
[*] Writing flow records to: TEST/bt2_t09_tcp_close/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.30 (TCP):51001 -> :80 [SYN] [len=40]
[0002] 10.0.0.30 -> 10.0.0.10 (TCP):80 -> :51001 [SYN,ACK] [len=40]
[0003] 10.0.0.10 -> 10.0.0.30 (TCP):51001 -> :80 [ACK] [len=40]
[0004] 10.0.0.10 -> 10.0.0.30 (TCP):51001 -> :80 [ACK,FIN] [len=40]
[0005] 10.0.0.30 -> 10.0.0.10 (TCP):80 -> :51001 [ACK] [len=40]
[FLOW] TCP-10.0.0.10:51001-10.0.0.30:80 state=CLOSED pkts=6 bytes=240 reason=fin
[0006] 10.0.0.30 -> 10.0.0.10 (TCP):80 -> :51001 [ACK,FIN] [len=40]
[0007] 10.0.0.10 -> 10.0.0.30 (TCP):51002 -> :8080 [SYN] [len=40]
[FLOW] TCP-10.0.0.10:51002-10.0.0.30:8080 state=RESET pkts=2 bytes=80 reason=rst
[0008] 10.0.0.10 -> 10.0.0.30 (TCP):51002 -> :8080 [RST] [len=40]
------------------------------------------------------------
[+] Finished: Processed 8 packets in 0.00s (1938.3 pkts/s)
[+] Output saved to: TEST/bt2_t09_tcp_close/output.jsonl
[+] Flow records saved to: TEST/bt2_t09_tcp_close/flows.jsonl
[+] Flows: created=2 closed=2 active_flushed=0
[+] Flow close reasons: fin=1 rst=1 timeout=0 overflow=0 end_of_capture=0
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
      "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
      "state": "CLOSED"
    }
  },
  {
    "flow": {
      "flow_id": "TCP-10.0.0.10:51002-10.0.0.30:8080",
      "state": "RESET"
    }
  }
]
```
- Số flow tối thiểu: **2**
- Danh sách flow subset bắt buộc phải khớp:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
    "state": "CLOSED",
    "close_reason": "fin",
    "fin_count": 2,
    "packet_count": 6
  },
  {
    "flow_id": "TCP-10.0.0.10:51002-10.0.0.30:8080",
    "state": "RESET",
    "close_reason": "rst",
    "rst_count": 1
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
      "dst_ip": "10.0.0.30",
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
      "src_port": 51001,
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
      "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
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
      "src_ip": "10.0.0.30",
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
      "dst_port": 51001,
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
      "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
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
      "dst_ip": "10.0.0.30",
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
      "src_port": 51001,
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
      "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
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
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.30",
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
      "src_port": 51001,
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
      "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
      "direction": "forward",
      "state": "CLOSING",
      "is_new_flow": false
    },
    "errors": []
  },
  {
    "packet_id": 5,
    "timestamp": 1700000000.4,
    "timestamp_iso": "2023-11-14T22:13:20.400000+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.30",
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
      "dst_port": 51001,
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
      "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
      "direction": "backward",
      "state": "CLOSING",
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
      "src_ip": "10.0.0.30",
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
      "dst_port": 51001,
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
      "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
      "direction": "backward",
      "state": "CLOSED",
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
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.30",
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
      "src_port": 51002,
      "dst_port": 8080,
      "payload_len": 0,
      "seq": 2000,
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
      "flow_id": "TCP-10.0.0.10:51002-10.0.0.30:8080",
      "direction": "forward",
      "state": "HANDSHAKE",
      "is_new_flow": true
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
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.30",
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
      "src_port": 51002,
      "dst_port": 8080,
      "payload_len": 0,
      "seq": 2001,
      "ack": 0,
      "flags": [
        "RST"
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
      "flow_id": "TCP-10.0.0.10:51002-10.0.0.30:8080",
      "direction": "forward",
      "state": "RESET",
      "is_new_flow": false
    },
    "errors": []
  }
]
```

## 5. Flow Records (flows.jsonl)
- **Số flow record**: 2
- **Số flow tối thiểu**: 2
- **Kỳ vọng flow (JSON subset)**:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
    "state": "CLOSED",
    "close_reason": "fin",
    "fin_count": 2,
    "packet_count": 6
  },
  {
    "flow_id": "TCP-10.0.0.10:51002-10.0.0.30:8080",
    "state": "RESET",
    "close_reason": "rst",
    "rst_count": 1
  }
]
```
- **Chi tiết flow records**:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
    "flow_seq": 1,
    "protocol": "TCP",
    "application_protocol": null,
    "endpoint_a": {
      "ip": "10.0.0.10",
      "port": 51001
    },
    "endpoint_b": {
      "ip": "10.0.0.30",
      "port": 80
    },
    "state": "CLOSED",
    "start_time": 1700000000.0,
    "last_seen": 1700000000.5,
    "duration": 0.5,
    "packet_count": 6,
    "byte_count": 240,
    "forward": {
      "packet_count": 3,
      "byte_count": 120
    },
    "backward": {
      "packet_count": 3,
      "byte_count": 120
    },
    "syn_count": 2,
    "ack_count": 5,
    "fin_count": 2,
    "rst_count": 0,
    "closed": true,
    "close_reason": "fin"
  },
  {
    "flow_id": "TCP-10.0.0.10:51002-10.0.0.30:8080",
    "flow_seq": 2,
    "protocol": "TCP",
    "application_protocol": null,
    "endpoint_a": {
      "ip": "10.0.0.10",
      "port": 51002
    },
    "endpoint_b": {
      "ip": "10.0.0.30",
      "port": 8080
    },
    "state": "RESET",
    "start_time": 1700000000.6,
    "last_seen": 1700000000.7,
    "duration": 0.1,
    "packet_count": 2,
    "byte_count": 80,
    "forward": {
      "packet_count": 2,
      "byte_count": 80
    },
    "backward": {
      "packet_count": 0,
      "byte_count": 0
    },
    "syn_count": 1,
    "ack_count": 0,
    "fin_count": 0,
    "rst_count": 1,
    "closed": true,
    "close_reason": "rst"
  }
]
```
