# Test Case Report: test_03_udp

- **Mục tiêu**: UDP Datagram
- **Yêu cầu kiểm thử**: Parse UDP packet, trích xuất port và payload
- **File PCAP**: `TEST/test_03_udp/test.pcap`
- **File Output JSONL**: `TEST/test_03_udp/output.jsonl`
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_03_udp/test.pcap)
[*] Writing normalized events to: TEST/test_03_udp/output.jsonl
------------------------------------------------------------
[0001] 192.168.1.100 -> 192.168.1.200 (UDP):12345 -> :54321 [len=75]
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (887.1 pkts/s)
[+] Output saved to: TEST/test_03_udp/output.jsonl
============================================================
```

## 2. Chi tiết Normalized Events (JSON)
```json
[
  {
    "packet_id": 1,
    "timestamp": 1790269306.147281,
    "timestamp_iso": "2026-09-24T17:01:46.147281+00:00",
    "raw_len": 75,
    "network": {
      "layer": "IPv4",
      "src_ip": "192.168.1.100",
      "dst_ip": "192.168.1.200",
      "proto": "UDP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 75,
      "flags": []
    },
    "transport": {
      "layer": "UDP",
      "src_port": 12345,
      "dst_port": 54321,
      "payload_len": 47,
      "checksum": 16013
    },
    "application": {
      "protocol": "UNKNOWN",
      "type": "unknown",
      "details": {
        "detection_method": "default"
      }
    },
    "errors": []
  }
]
```

## 3. Đánh giá tính đúng đắn
- Toàn bộ gói tin được bóc tách chính xác qua parsing pipeline.
- Không xảy ra lỗi ngoài ý muốn hoặc crash chương trình.
- Cấu trúc dữ liệu đầu ra tuân thủ đúng định dạng JSON chuẩn hóa của đề bài.
