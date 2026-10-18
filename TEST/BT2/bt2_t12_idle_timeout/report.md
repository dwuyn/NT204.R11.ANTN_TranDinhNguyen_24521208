# Test Case Report: bt2_t12_idle_timeout

- **Mục tiêu**: Đóng flow TCP khi vượt idle timeout cấu hình được
- **Yêu cầu kiểm thử**: Với --tcp-timeout 5, flow im lặng 29.99s bị đóng reason timeout (state ESTABLISHED, 2 packet); flow thứ hai flush end_of_capture.
- **File PCAP**: `TEST/bt2_t12_idle_timeout/test.pcap`
- **File Output JSONL**: `TEST/bt2_t12_idle_timeout/output.jsonl`
- **File Flow Records**: `TEST/bt2_t12_idle_timeout/flows.jsonl`
- **Số flow record**: 2- **Số gói tin đã xử lý**: 3
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t12_idle_timeout/test.pcap)
[*] Writing normalized events to: TEST/bt2_t12_idle_timeout/output.jsonl
[*] Writing flow records to: TEST/bt2_t12_idle_timeout/flows.jsonl
[*] Flow tracker: tcp_timeout=5.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [SYN] [len=40]
[0002] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK] [len=40]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=ESTABLISHED pkts=2 bytes=80 reason=timeout
[0003] 10.0.0.11 -> 10.0.0.20 (TCP):53000 -> :8080 [SYN] [len=40]
[FLOW] TCP-10.0.0.11:53000-10.0.0.20:8080 state=HANDSHAKE pkts=1 bytes=40 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 3 packets in 0.00s (1448.3 pkts/s)
[+] Output saved to: TEST/bt2_t12_idle_timeout/output.jsonl
[+] Flow records saved to: TEST/bt2_t12_idle_timeout/flows.jsonl
[+] Flows: created=2 closed=2 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=1 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **3**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "flow": {
      "flow_id": "TCP-10.0.0.11:53000-10.0.0.20:8080",
      "is_new_flow": true
    }
  }
]
```
- Số flow tối thiểu: **2**
- Danh sách flow subset bắt buộc phải khớp:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "close_reason": "timeout",
    "state": "ESTABLISHED",
    "packet_count": 2
  },
  {
    "flow_id": "TCP-10.0.0.11:53000-10.0.0.20:8080",
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
    "timestamp": 1700000000.01,
    "timestamp_iso": "2023-11-14T22:13:20.010000+00:00",
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
      "ack": 0,
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
    "packet_id": 3,
    "timestamp": 1700000030.0,
    "timestamp_iso": "2023-11-14T22:13:50+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.11",
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
      "src_port": 53000,
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
      "flow_id": "TCP-10.0.0.11:53000-10.0.0.20:8080",
      "direction": "forward",
      "state": "HANDSHAKE",
      "is_new_flow": true
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
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "close_reason": "timeout",
    "state": "ESTABLISHED",
    "packet_count": 2
  },
  {
    "flow_id": "TCP-10.0.0.11:53000-10.0.0.20:8080",
    "close_reason": "end_of_capture"
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
    "application_protocol": null,
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
    "last_seen": 1700000000.01,
    "duration": 0.01,
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
    "ack_count": 1,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "timeout"
  },
  {
    "flow_id": "TCP-10.0.0.11:53000-10.0.0.20:8080",
    "flow_seq": 2,
    "protocol": "TCP",
    "application_protocol": null,
    "endpoint_a": {
      "ip": "10.0.0.11",
      "port": 53000
    },
    "endpoint_b": {
      "ip": "10.0.0.20",
      "port": 8080
    },
    "state": "HANDSHAKE",
    "start_time": 1700000030.0,
    "last_seen": 1700000030.0,
    "duration": 0.0,
    "packet_count": 1,
    "byte_count": 40,
    "forward": {
      "packet_count": 1,
      "byte_count": 40
    },
    "backward": {
      "packet_count": 0,
      "byte_count": 0
    },
    "syn_count": 1,
    "ack_count": 0,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "end_of_capture"
  }
]
```
