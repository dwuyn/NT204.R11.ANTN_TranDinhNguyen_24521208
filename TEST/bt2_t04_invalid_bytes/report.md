# Test Case Report: bt2_t04_invalid_bytes

- **Mục tiêu**: Xử lý byte không hợp lệ UTF-8 và payload giao thức không hỗ trợ
- **Yêu cầu kiểm thử**: Body lỗi UTF-8 được decode thay thế với trạng thái partial, payload lạ là UNKNOWN và preprocessor trả partial/unsupported_protocol.
- **File PCAP**: `TEST/bt2_t04_invalid_bytes/test.pcap`
- **File Output JSONL**: `TEST/bt2_t04_invalid_bytes/output.jsonl`
- **File Flow Records**: `TEST/bt2_t04_invalid_bytes/flows.jsonl`
- **Số flow record**: 2- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t04_invalid_bytes/test.pcap)
[*] Writing normalized events to: TEST/bt2_t04_invalid_bytes/output.jsonl
[*] Writing flow records to: TEST/bt2_t04_invalid_bytes/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=141]
[0002] 10.0.0.11 -> 10.0.0.21 (TCP):61000 -> :9999 [ACK,PSH] [len=66]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=ESTABLISHED pkts=1 bytes=141 reason=end_of_capture
[FLOW] TCP-10.0.0.11:61000-10.0.0.21:9999 state=ESTABLISHED pkts=1 bytes=66 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (603.4 pkts/s)
[+] Output saved to: TEST/bt2_t04_invalid_bytes/output.jsonl
[+] Flow records saved to: TEST/bt2_t04_invalid_bytes/flows.jsonl
[+] Flows: created=2 closed=2 active_flushed=2
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=2
[+] Dropped events (preprocessor): 0
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **2**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "decode": {
      "decode_status": "partial",
      "warnings": [
        "invalid_utf8_sequence"
      ]
    }
  },
  {
    "application": {
      "protocol": "UNKNOWN"
    },
    "decode": {
      "decode_status": "partial"
    }
  },
  {
    "preprocess": {
      "preprocess_status": "partial",
      "reason": "unsupported_protocol"
    }
  }
]
```
- Số flow tối thiểu: **0**
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
    "raw_len": 141,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 141,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 101,
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
        "method": "POST",
        "uri": "/upload",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "ids.local",
          "Content-Type": "text/plain",
          "Content-Length": "13"
        },
        "body": "ÿþú invalid ",
        "detection_method": "payload_signature",
        "uri_normalized": "/upload"
      }
    },
    "decode": {
      "decode_status": "partial",
      "decoders": [
        "html_entities"
      ],
      "fields": {
        "uri_decoded": "/upload",
        "body_charset": "utf-8",
        "body_decode_status": "partial",
        "body_decoded": "��� invalid �"
      },
      "warnings": [
        "invalid_utf8_sequence"
      ]
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
    "raw_len": 66,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.11",
      "dst_ip": "10.0.0.21",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 66,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 61000,
      "dst_port": 9999,
      "payload_len": 26,
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
      "flow_id": "TCP-10.0.0.11:61000-10.0.0.21:9999",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  }
]
```

## 5. Flow Records (flows.jsonl)
- **Số flow record**: 2
- **Số flow tối thiểu**: 0
- **Kỳ vọng flow (JSON subset)**:
```json
[]
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
    "last_seen": 1700000000.0,
    "duration": 0.0,
    "packet_count": 1,
    "byte_count": 141,
    "forward": {
      "packet_count": 1,
      "byte_count": 141
    },
    "backward": {
      "packet_count": 0,
      "byte_count": 0
    },
    "syn_count": 0,
    "ack_count": 1,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "end_of_capture"
  },
  {
    "flow_id": "TCP-10.0.0.11:61000-10.0.0.21:9999",
    "flow_seq": 2,
    "protocol": "TCP",
    "application_protocol": null,
    "endpoint_a": {
      "ip": "10.0.0.11",
      "port": 61000
    },
    "endpoint_b": {
      "ip": "10.0.0.21",
      "port": 9999
    },
    "state": "ESTABLISHED",
    "start_time": 1700000000.1,
    "last_seen": 1700000000.1,
    "duration": 0.0,
    "packet_count": 1,
    "byte_count": 66,
    "forward": {
      "packet_count": 1,
      "byte_count": 66
    },
    "backward": {
      "packet_count": 0,
      "byte_count": 0
    },
    "syn_count": 0,
    "ack_count": 1,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "end_of_capture"
  }
]
```
