# Test Case Report: bt2_t10_udp_dns

- **Mục tiêu**: Theo dõi flow UDP cho cặp DNS query/response
- **Yêu cầu kiểm thử**: Query/response DNS cùng 5-tuple tạo 1 flow UDP ESTABLISHED, 2 packet 159 byte chia đều hai chiều, application_protocol DNS, syn_count 0.
- **File PCAP**: `TEST/bt2_t10_udp_dns/test.pcap`
- **File Output JSONL**: `TEST/bt2_t10_udp_dns/output.jsonl`
- **File Flow Records**: `TEST/bt2_t10_udp_dns/flows.jsonl`
- **Số flow record**: 1- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t10_udp_dns/test.pcap)
[*] Writing normalized events to: TEST/bt2_t10_udp_dns/output.jsonl
[*] Writing flow records to: TEST/bt2_t10_udp_dns/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 192.168.1.100 -> 8.8.8.8 (UDP):53000 -> :53 | DNS (query) [len=63]
[0002] 8.8.8.8 -> 192.168.1.100 (UDP):53 -> :53000 | DNS (response) [len=96]
[FLOW] UDP-192.168.1.100:53000-8.8.8.8:53 state=ESTABLISHED pkts=2 bytes=159 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (926.0 pkts/s)
[+] Output saved to: TEST/bt2_t10_udp_dns/output.jsonl
[+] Flow records saved to: TEST/bt2_t10_udp_dns/flows.jsonl
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
    "application": {
      "type": "query"
    },
    "flow": {
      "flow_id": "UDP-192.168.1.100:53000-8.8.8.8:53"
    }
  },
  {
    "application": {
      "type": "response"
    }
  }
]
```
- Số flow tối thiểu: **1**
- Danh sách flow subset bắt buộc phải khớp:
```json
[
  {
    "protocol": "UDP",
    "state": "ESTABLISHED",
    "packet_count": 2,
    "byte_count": 159,
    "forward": {
      "packet_count": 1
    },
    "backward": {
      "packet_count": 1
    },
    "application_protocol": "DNS",
    "syn_count": 0
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
    "raw_len": 63,
    "network": {
      "layer": "IPv4",
      "src_ip": "192.168.1.100",
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
      "checksum": 46972
    },
    "application": {
      "protocol": "DNS",
      "type": "query",
      "details": {
        "transaction_id": 4919,
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
      "normalizations": [],
      "warnings": []
    },
    "flow": {
      "flow_id": "UDP-192.168.1.100:53000-8.8.8.8:53",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1700000000.005,
    "timestamp_iso": "2023-11-14T22:13:20.005000+00:00",
    "raw_len": 96,
    "network": {
      "layer": "IPv4",
      "src_ip": "8.8.8.8",
      "dst_ip": "192.168.1.100",
      "proto": "UDP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 96,
      "flags": []
    },
    "transport": {
      "layer": "UDP",
      "src_port": 53,
      "dst_port": 53000,
      "payload_len": 68,
      "checksum": 46851
    },
    "application": {
      "protocol": "DNS",
      "type": "response",
      "details": {
        "transaction_id": 4919,
        "qr": 1,
        "opcode": "QUERY",
        "rcode": "NOERROR",
        "queries": [
          {
            "name": "portal.uit.edu.vn",
            "type": "A"
          }
        ],
        "answers": [
          {
            "name": "portal.uit.edu.vn",
            "type": "A",
            "rdata": "118.69.123.45",
            "ttl": 300
          }
        ],
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
      "normalizations": [],
      "warnings": []
    },
    "flow": {
      "flow_id": "UDP-192.168.1.100:53000-8.8.8.8:53",
      "direction": "backward",
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
    "protocol": "UDP",
    "state": "ESTABLISHED",
    "packet_count": 2,
    "byte_count": 159,
    "forward": {
      "packet_count": 1
    },
    "backward": {
      "packet_count": 1
    },
    "application_protocol": "DNS",
    "syn_count": 0
  }
]
```
- **Chi tiết flow records**:
```json
[
  {
    "flow_id": "UDP-192.168.1.100:53000-8.8.8.8:53",
    "flow_seq": 1,
    "protocol": "UDP",
    "application_protocol": "DNS",
    "endpoint_a": {
      "ip": "192.168.1.100",
      "port": 53000
    },
    "endpoint_b": {
      "ip": "8.8.8.8",
      "port": 53
    },
    "state": "ESTABLISHED",
    "start_time": 1700000000.0,
    "last_seen": 1700000000.005,
    "duration": 0.005,
    "packet_count": 2,
    "byte_count": 159,
    "forward": {
      "packet_count": 1,
      "byte_count": 63
    },
    "backward": {
      "packet_count": 1,
      "byte_count": 96
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
