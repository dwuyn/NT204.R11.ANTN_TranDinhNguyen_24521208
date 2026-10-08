# Test Case Report: bt2_t05_normalization

- **Mục tiêu**: Chuẩn hóa HTTP header, Host, URI path và tên miền DNS
- **Yêu cầu kiểm thử**: Header content-TYPE thành Content-Type, Host viết thường, URI chuẩn hóa thành /admin/secret?q=/, QNAME thành portal.uit.edu.vn, normalizations ghi nhận đúng.
- **File PCAP**: `TEST/bt2_t05_normalization/test.pcap`
- **File Output JSONL**: `TEST/bt2_t05_normalization/output.jsonl`
- **File Flow Records**: `TEST/bt2_t05_normalization/flows.jsonl`
- **Số flow record**: 2- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t05_normalization/test.pcap)
[*] Writing normalized events to: TEST/bt2_t05_normalization/output.jsonl
[*] Writing flow records to: TEST/bt2_t05_normalization/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=148]
[0002] 10.0.0.10 -> 8.8.8.8 (UDP):53000 -> :53 | DNS (query) [len=63]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=ESTABLISHED pkts=1 bytes=148 reason=end_of_capture
[FLOW] UDP-10.0.0.10:53000-8.8.8.8:53 state=ESTABLISHED pkts=1 bytes=63 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (504.0 pkts/s)
[+] Output saved to: TEST/bt2_t05_normalization/output.jsonl
[+] Flow records saved to: TEST/bt2_t05_normalization/flows.jsonl
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
    "application": {
      "details": {
        "headers": {
          "Content-Type": "text/plain",
          "Host": "ids.security.lab:8080"
        }
      }
    }
  },
  {
    "application": {
      "details": {
        "uri_normalized": "/admin/secret?q=/",
        "uri": "//admin//./stats/%2e%2e/secret?q=%2f"
      }
    }
  },
  {
    "preprocess": {
      "normalizations": [
        "http_header_names",
        "uri_path"
      ]
    }
  },
  {
    "application": {
      "details": {
        "queries": [
          {
            "name": "portal.uit.edu.vn"
          }
        ]
      }
    },
    "preprocess": {
      "normalizations": [
        "domain_lowercase"
      ]
    }
  }
]
```
- Số flow tối thiểu: **2**
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
    "raw_len": 148,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 148,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 108,
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
        "uri": "//admin//./stats/%2e%2e/secret?q=%2f",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "ids.security.lab:8080",
          "Content-Type": "text/plain"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/admin/secret?q=/"
      }
    },
    "decode": {
      "decode_status": "decoded",
      "decoders": [
        "percent_url"
      ],
      "fields": {
        "uri_decoded": "//admin//./stats/../secret?q=/"
      },
      "warnings": []
    },
    "preprocess": {
      "preprocess_status": "valid",
      "processing_action": "forward",
      "reason": null,
      "normalizations": [
        "http_header_names",
        "host_header",
        "uri_path"
      ],
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
    "raw_len": 63,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "8.8.8.8",
      "proto": "UDP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 63,
      "flags": []
    },
    "transport": {
      "layer": "UDP",
      "src_port": 53000,
      "dst_port": 53,
      "payload_len": 35,
      "checksum": 16693
    },
    "application": {
      "protocol": "DNS",
      "type": "query",
      "details": {
        "transaction_id": 16962,
        "qr": 0,
        "opcode": "QUERY",
        "rcode": "NOERROR",
        "queries": [
          {
            "name": "portal.uit.edu.vn",
            "type": "A"
          }
        ],
        "answers": [],
        "detection_method": "scapy_layer"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {},
      "warnings": []
    },
    "preprocess": {
      "preprocess_status": "valid",
      "processing_action": "forward",
      "reason": null,
      "normalizations": [
        "domain_lowercase"
      ],
      "warnings": []
    },
    "flow": {
      "flow_id": "UDP-10.0.0.10:53000-8.8.8.8:53",
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
- **Số flow tối thiểu**: 2
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
    "byte_count": 148,
    "forward": {
      "packet_count": 1,
      "byte_count": 148
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
    "flow_id": "UDP-10.0.0.10:53000-8.8.8.8:53",
    "flow_seq": 2,
    "protocol": "UDP",
    "application_protocol": "DNS",
    "endpoint_a": {
      "ip": "10.0.0.10",
      "port": 53000
    },
    "endpoint_b": {
      "ip": "8.8.8.8",
      "port": 53
    },
    "state": "ESTABLISHED",
    "start_time": 1700000000.1,
    "last_seen": 1700000000.1,
    "duration": 0.0,
    "packet_count": 1,
    "byte_count": 63,
    "forward": {
      "packet_count": 1,
      "byte_count": 63
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
