# Test Case Report: test_07_dns_query

- **Mục tiêu**: DNS Query
- **Yêu cầu kiểm thử**: Parse domain và query type
- **File PCAP**: `TEST/BT1/test_07_dns_query/test.pcap`
- **File Output JSONL**: `TEST/BT1/test_07_dns_query/output.jsonl`
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT1/test_07_dns_query/test.pcap)
[*] Writing normalized events to: TEST/BT1/test_07_dns_query/output.jsonl
[*] Writing flow records to: /tmp/ids_flows_3g4tmpg7/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 192.168.1.100 -> 8.8.8.8 (UDP):53000 -> :53 | DNS (query) [len=63]
[FLOW] UDP-192.168.1.100:53000-8.8.8.8:53 state=ESTABLISHED pkts=1 bytes=63 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (743.3 pkts/s)
[+] Output saved to: TEST/BT1/test_07_dns_query/output.jsonl
[+] Flow records saved to: /tmp/ids_flows_3g4tmpg7/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **1**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "application": {
      "protocol": "DNS",
      "type": "query",
      "details": {
        "queries": [
          {
            "name": "portal.uit.edu.vn",
            "type": "A"
          }
        ]
      }
    }
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
    "timestamp": 1790269306.148273,
    "timestamp_iso": "2026-09-24T17:01:46.148273+00:00",
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
  }
]
```
