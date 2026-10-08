# Test Case Report: bt2_t07_tcp_handshake

- **Mục tiêu**: Theo dõi flow TCP qua ba bước bắt tay SYN, SYN-ACK, ACK
- **Yêu cầu kiểm thử**: Ba packet cùng 5-tuple tạo 1 flow, state HANDSHAKE -> ESTABLISHED, syn_count 2, ack_count 2, close_reason end_of_capture.
- **File PCAP**: `TEST/bt2_t07_tcp_handshake/test.pcap`
- **File Output JSONL**: `TEST/bt2_t07_tcp_handshake/output.jsonl`
- **File Flow Records**: `TEST/bt2_t07_tcp_handshake/flows.jsonl`
- **Số flow record**: 1- **Số gói tin đã xử lý**: 3
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t07_tcp_handshake/test.pcap)
[*] Writing normalized events to: TEST/bt2_t07_tcp_handshake/output.jsonl
[*] Writing flow records to: TEST/bt2_t07_tcp_handshake/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.1 (TCP):51234 -> :80 [SYN] [len=40]
[0002] 10.0.0.1 -> 10.0.0.10 (TCP):80 -> :51234 [SYN,ACK] [len=40]
[0003] 10.0.0.10 -> 10.0.0.1 (TCP):51234 -> :80 [ACK] [len=40]
[FLOW] TCP-10.0.0.10:51234-10.0.0.1:80 state=ESTABLISHED pkts=3 bytes=120 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 3 packets in 0.00s (1722.7 pkts/s)
[+] Output saved to: TEST/bt2_t07_tcp_handshake/output.jsonl
[+] Flow records saved to: TEST/bt2_t07_tcp_handshake/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **3**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "transport": {
      "handshake": "SYN"
    },
    "flow": {
      "direction": "forward",
      "is_new_flow": true,
      "state": "HANDSHAKE"
    }
  },
  {
    "transport": {
      "handshake": "SYN-ACK"
    },
    "flow": {
      "direction": "backward"
    }
  },
  {
    "transport": {
      "handshake": "ACK"
    },
    "flow": {
      "state": "ESTABLISHED",
      "flow_id": "TCP-10.0.0.10:51234-10.0.0.1:80"
    }
  }
]
```
- Số flow tối thiểu: **1**
- Danh sách flow subset bắt buộc phải khớp:
```json
[
  {
    "state": "ESTABLISHED",
    "packet_count": 3,
    "forward": {
      "packet_count": 2
    },
    "backward": {
      "packet_count": 1
    },
    "syn_count": 2,
    "ack_count": 2,
    "fin_count": 0,
    "rst_count": 0,
    "close_reason": "end_of_capture"
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
      "dst_ip": "10.0.0.1",
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
      "src_port": 51234,
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
      "flow_id": "TCP-10.0.0.10:51234-10.0.0.1:80",
      "direction": "forward",
      "state": "HANDSHAKE",
      "is_new_flow": true
    },
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1700000000.001,
    "timestamp_iso": "2023-11-14T22:13:20.001000+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.1",
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
      "dst_port": 51234,
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
      "flow_id": "TCP-10.0.0.10:51234-10.0.0.1:80",
      "direction": "backward",
      "state": "HANDSHAKE",
      "is_new_flow": false
    },
    "errors": []
  },
  {
    "packet_id": 3,
    "timestamp": 1700000000.002,
    "timestamp_iso": "2023-11-14T22:13:20.002000+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.1",
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
      "src_port": 51234,
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
      "flow_id": "TCP-10.0.0.10:51234-10.0.0.1:80",
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
    "state": "ESTABLISHED",
    "packet_count": 3,
    "forward": {
      "packet_count": 2
    },
    "backward": {
      "packet_count": 1
    },
    "syn_count": 2,
    "ack_count": 2,
    "fin_count": 0,
    "rst_count": 0,
    "close_reason": "end_of_capture"
  }
]
```
- **Chi tiết flow records**:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:51234-10.0.0.1:80",
    "flow_seq": 1,
    "protocol": "TCP",
    "application_protocol": null,
    "endpoint_a": {
      "ip": "10.0.0.10",
      "port": 51234
    },
    "endpoint_b": {
      "ip": "10.0.0.1",
      "port": 80
    },
    "state": "ESTABLISHED",
    "start_time": 1700000000.0,
    "last_seen": 1700000000.002,
    "duration": 0.002,
    "packet_count": 3,
    "byte_count": 120,
    "forward": {
      "packet_count": 2,
      "byte_count": 80
    },
    "backward": {
      "packet_count": 1,
      "byte_count": 40
    },
    "syn_count": 2,
    "ack_count": 2,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "end_of_capture"
  }
]
```
