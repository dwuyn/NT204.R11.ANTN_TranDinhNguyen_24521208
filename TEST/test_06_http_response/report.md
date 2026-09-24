# Test Case Report: test_06_http_response

- **Mục tiêu**: HTTP Response
- **Yêu cầu kiểm thử**: Parse HTTP version, status code, reason phrase, headers, body
- **File PCAP**: `TEST/test_06_http_response/test.pcap`
- **File Output JSONL**: `TEST/test_06_http_response/output.jsonl`
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_06_http_response/test.pcap)
[*] Writing normalized events to: TEST/test_06_http_response/output.jsonl
------------------------------------------------------------
[0001] 93.184.216.34 -> 192.168.1.100 (TCP):80 -> :52000 [ACK,PSH] | HTTP (response) [len=176]
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (1022.8 pkts/s)
[+] Output saved to: TEST/test_06_http_response/output.jsonl
============================================================
```

## 2. Chi tiết Normalized Events (JSON)
```json
[
  {
    "packet_id": 1,
    "timestamp": 1790269306.148022,
    "timestamp_iso": "2026-09-24T17:01:46.148022+00:00",
    "raw_len": 176,
    "network": {
      "layer": "IPv4",
      "src_ip": "93.184.216.34",
      "dst_ip": "192.168.1.100",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 176,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 80,
      "dst_port": 52000,
      "payload_len": 136,
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
      "type": "response",
      "details": {
        "version": "HTTP/1.1",
        "status_code": 200,
        "reason": "OK",
        "headers": {
          "Server": "Apache/2.4.41 (Ubuntu)",
          "Content-Type": "text/html",
          "Content-Length": "40"
        },
        "body": "<html><body>Access Granted</body></html>",
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
