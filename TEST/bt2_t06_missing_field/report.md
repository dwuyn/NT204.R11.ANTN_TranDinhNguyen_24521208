# Test Case Report: bt2_t06_missing_field

- **Mục tiêu**: Xử lý event thiếu tầng mạng và thiếu giao thức ứng dụng hỗ trợ
- **Yêu cầu kiểm thử**: Packet ARP invalid/missing_network_layer không có flow; payload UDP lạ partial/unsupported_protocol và có 1 flow UDP.
- **File PCAP**: `TEST/bt2_t06_missing_field/test.pcap`
- **File Output JSONL**: `TEST/bt2_t06_missing_field/output.jsonl`
- **File Flow Records**: `TEST/bt2_t06_missing_field/flows.jsonl`
- **Số flow record**: 1- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t06_missing_field/test.pcap)
[*] Writing normalized events to: TEST/bt2_t06_missing_field/output.jsonl
[*] Writing flow records to: TEST/bt2_t06_missing_field/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] NoIP [len=42]
[0002] 10.0.0.30 -> 10.0.0.31 (UDP):40000 -> :40001 [len=52]
[FLOW] UDP-10.0.0.30:40000-10.0.0.31:40001 state=ESTABLISHED pkts=1 bytes=52 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (822.1 pkts/s)
[+] Output saved to: TEST/bt2_t06_missing_field/output.jsonl
[+] Flow records saved to: TEST/bt2_t06_missing_field/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **2**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "network": null,
    "transport": null,
    "flow": null,
    "preprocess": {
      "preprocess_status": "invalid",
      "reason": "missing_network_layer"
    }
  },
  {
    "application": {
      "protocol": "UNKNOWN"
    },
    "preprocess": {
      "preprocess_status": "partial",
      "reason": "unsupported_protocol"
    }
  }
]
```
- Số flow tối thiểu: **1**
- Danh sách flow subset bắt buộc phải khớp:
```json
[]
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
    "raw_len": 42,
    "network": null,
    "transport": null,
    "application": {
      "protocol": "UNKNOWN",
      "type": "unknown",
      "details": {
        "detection_method": "none"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {},
      "warnings": []
    },
    "preprocess": {
      "preprocess_status": "invalid",
      "processing_action": "forward",
      "reason": "missing_network_layer",
      "normalizations": [],
      "warnings": [
        "missing_transport_layer",
        "unsupported_protocol"
      ]
    },
    "flow": null,
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1700000000.1,
    "timestamp_iso": "2023-11-14T22:13:20.100000+00:00",
    "raw_len": 52,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.30",
      "dst_ip": "10.0.0.31",
      "proto": "UDP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 38,
      "flags": []
    },
    "transport": {
      "layer": "UDP",
      "src_port": 40000,
      "dst_port": 40001,
      "payload_len": 10,
      "checksum": 24280
    },
    "application": {
      "protocol": "UNKNOWN",
      "type": "unknown",
      "details": {
        "detection_method": "default"
      }
    },
    "decode": {
      "decode_status": "partial",
      "decoders": [],
      "fields": {},
      "warnings": [
        "invalid_utf8_sequence"
      ]
    },
    "preprocess": {
      "preprocess_status": "partial",
      "processing_action": "forward",
      "reason": "unsupported_protocol",
      "normalizations": [],
      "warnings": []
    },
    "flow": {
      "flow_id": "UDP-10.0.0.30:40000-10.0.0.31:40001",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
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
[]
```
- **Chi tiết flow records**:
```json
[
  {
    "flow_id": "UDP-10.0.0.30:40000-10.0.0.31:40001",
    "flow_seq": 1,
    "protocol": "UDP",
    "application_protocol": null,
    "endpoint_a": {
      "ip": "10.0.0.30",
      "port": 40000
    },
    "endpoint_b": {
      "ip": "10.0.0.31",
      "port": 40001
    },
    "state": "ESTABLISHED",
    "start_time": 1700000000.1,
    "last_seen": 1700000000.1,
    "duration": 0.0,
    "packet_count": 1,
    "byte_count": 52,
    "forward": {
      "packet_count": 1,
      "byte_count": 52
    },
    "backward": {
      "packet_count": 0,
      "byte_count": 0
    },
    "syn_count": 0,
    "ack_count": 0,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "end_of_capture"
  }
]
```
