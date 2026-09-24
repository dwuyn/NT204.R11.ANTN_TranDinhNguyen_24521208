# Test Case Report: test_04_http_get

- **Mục tiêu**: HTTP GET Request
- **Yêu cầu kiểm thử**: Parse method, URI, version, headers
- **File PCAP**: `TEST/test_04_http_get/test.pcap`
- **File Output JSONL**: `TEST/test_04_http_get/output.jsonl`
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_04_http_get/test.pcap)
[*] Writing normalized events to: TEST/test_04_http_get/output.jsonl
------------------------------------------------------------
[0001] 192.168.1.100 -> 93.184.216.34 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=140]
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (1188.5 pkts/s)
[+] Output saved to: TEST/test_04_http_get/output.jsonl
============================================================
```

## 2. Chi tiết Normalized Events (JSON)
```json
[
  {
    "packet_id": 1,
    "timestamp": 1790269306.14752,
    "timestamp_iso": "2026-09-24T17:01:46.147520+00:00",
    "raw_len": 140,
    "network": {
      "layer": "IPv4",
      "src_ip": "192.168.1.100",
      "dst_ip": "93.184.216.34",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 140,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 100,
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
        "uri": "/api/v1/network/stats",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "ids.security.lab",
          "User-Agent": "Mozilla/5.0",
          "Accept": "*/*"
        },
        "body": "",
        "detection_method": "payload_signature"
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
