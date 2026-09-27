# Test Case Report: test_07_dns_query

- **Mục tiêu**: DNS Query
- **Yêu cầu kiểm thử**: Parse domain và query type
- **File PCAP**: `TEST/test_07_dns_query/test.pcap`
- **File Output JSONL**: `TEST/test_07_dns_query/output.jsonl`
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_07_dns_query/test.pcap)
[*] Writing normalized events to: TEST/test_07_dns_query/output.jsonl
------------------------------------------------------------
[0001] 192.168.1.100 -> 8.8.8.8 (UDP):53000 -> :53 | DNS (query) [len=63]
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (836.0 pkts/s)
[+] Output saved to: TEST/test_07_dns_query/output.jsonl
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
    "errors": []
  }
]
```
