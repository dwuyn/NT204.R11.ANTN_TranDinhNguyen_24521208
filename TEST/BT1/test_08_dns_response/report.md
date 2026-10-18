# Test Case Report: test_08_dns_response

- **Mục tiêu**: DNS Response
- **Yêu cầu kiểm thử**: Parse ít nhất một answer record gồm name, type, rdata, ttl
- **File PCAP**: `TEST/test_08_dns_response/test.pcap`
- **File Output JSONL**: `TEST/test_08_dns_response/output.jsonl`
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_08_dns_response/test.pcap)
[*] Writing normalized events to: TEST/test_08_dns_response/output.jsonl
------------------------------------------------------------
[0001] 8.8.8.8 -> 192.168.1.100 (UDP):53 -> :53000 | DNS (response) [len=96]
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (620.9 pkts/s)
[+] Output saved to: TEST/test_08_dns_response/output.jsonl
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
      "type": "response",
      "details": {
        "answers": [
          {
            "name": "portal.uit.edu.vn",
            "type": "A",
            "rdata": "118.69.123.45"
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
    "timestamp": 1790269306.148735,
    "timestamp_iso": "2026-09-24T17:01:46.148735+00:00",
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
    "errors": []
  }
]
```
