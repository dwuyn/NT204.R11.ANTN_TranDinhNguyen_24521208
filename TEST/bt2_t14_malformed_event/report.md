# Test Case Report: bt2_t14_malformed_event

- **Mục tiêu**: Xử lý event lỗi và file PCAP bị cắt cụt
- **Yêu cầu kiểm thử**: PCAP cắt cụt vẫn đọc được; packet TCP không payload partial/no_application_layer và tạo flow; packet proto 0 partial/missing_transport_layer.
- **File PCAP**: `TEST/bt2_t14_malformed_event/truncated.pcap`
- **File Output JSONL**: `TEST/bt2_t14_malformed_event/output.jsonl`
- **File Flow Records**: `TEST/bt2_t14_malformed_event/flows.jsonl`
- **Số flow record**: 1- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t14_malformed_event/truncated.pcap)
[*] Writing normalized events to: TEST/bt2_t14_malformed_event/output.jsonl
[*] Writing flow records to: TEST/bt2_t14_malformed_event/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.1 -> 10.0.0.2 (TCP):80 -> :80 [SYN] [len=40]
[0002] 127.0.0.1 -> 127.0.0.1 (PROTO_0) [len=8]
[FLOW] TCP-10.0.0.1:80-10.0.0.2:80 state=HANDSHAKE pkts=1 bytes=40 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (1420.1 pkts/s)
[+] Output saved to: TEST/bt2_t14_malformed_event/output.jsonl
[+] Flow records saved to: TEST/bt2_t14_malformed_event/flows.jsonl
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
    "transport": {
      "layer": "TCP"
    },
    "preprocess": {
      "preprocess_status": "partial",
      "reason": "no_application_layer"
    }
  },
  {
    "network": {
      "proto": "PROTO_0"
    },
    "preprocess": {
      "preprocess_status": "partial",
      "reason": "missing_transport_layer"
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
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.1",
      "dst_ip": "10.0.0.2",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 100,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 80,
      "dst_port": 80,
      "payload_len": 0,
      "seq": 0,
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
      "flow_id": "TCP-10.0.0.1:80-10.0.0.2:80",
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
    "raw_len": 8,
    "network": {
      "layer": "IPv4",
      "src_ip": "127.0.0.1",
      "dst_ip": "127.0.0.1",
      "proto": "PROTO_0",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 23,
      "flags": []
    },
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
      "preprocess_status": "partial",
      "processing_action": "forward",
      "reason": "missing_transport_layer",
      "normalizations": [],
      "warnings": [
        "unsupported_protocol"
      ]
    },
    "flow": null,
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
    "flow_id": "TCP-10.0.0.1:80-10.0.0.2:80",
    "flow_seq": 1,
    "protocol": "TCP",
    "application_protocol": null,
    "endpoint_a": {
      "ip": "10.0.0.1",
      "port": 80
    },
    "endpoint_b": {
      "ip": "10.0.0.2",
      "port": 80
    },
    "state": "HANDSHAKE",
    "start_time": 1700000000.0,
    "last_seen": 1700000000.0,
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
