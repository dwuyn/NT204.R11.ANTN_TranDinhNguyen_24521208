# Test Case Report: test_02_tcp_data

- **Mục tiêu**: TCP Data Packet
- **Yêu cầu kiểm thử**: Parse TCP packet có payload và kiểm tra độ dài payload
- **File PCAP**: `TEST/test_02_tcp_data/test.pcap`
- **File Output JSONL**: `TEST/test_02_tcp_data/output.jsonl`
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_02_tcp_data/test.pcap)
[*] Writing normalized events to: TEST/test_02_tcp_data/output.jsonl
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.1 (TCP):51234 -> :80 [ACK,PSH] [len=84]
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (855.1 pkts/s)
[+] Output saved to: TEST/test_02_tcp_data/output.jsonl
============================================================
```

## 2. Chi tiết Normalized Events (JSON)
```json
[
  {
    "packet_id": 1,
    "timestamp": 1790269306.147002,
    "timestamp_iso": "2026-09-24T17:01:46.147002+00:00",
    "raw_len": 84,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.1",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 84,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 51234,
      "dst_port": 80,
      "payload_len": 44,
      "seq": 1001,
      "ack": 5001,
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
    "errors": []
  }
]
```

## 3. Đánh giá tính đúng đắn
- Toàn bộ gói tin được bóc tách chính xác qua parsing pipeline.
- Không xảy ra lỗi ngoài ý muốn hoặc crash chương trình.
- Cấu trúc dữ liệu đầu ra tuân thủ đúng định dạng JSON chuẩn hóa của đề bài.
