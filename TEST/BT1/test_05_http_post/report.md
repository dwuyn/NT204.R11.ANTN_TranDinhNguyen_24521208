# Test Case Report: test_05_http_post

- **Mục tiêu**: HTTP POST Request
- **Yêu cầu kiểm thử**: Parse method, headers và trích xuất request body
- **File PCAP**: `TEST/BT1/test_05_http_post/test.pcap`
- **File Output JSONL**: `TEST/BT1/test_05_http_post/output.jsonl`
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT1/test_05_http_post/test.pcap)
[*] Writing normalized events to: TEST/BT1/test_05_http_post/output.jsonl
[*] Writing flow records to: /tmp/ids_flows_st_tvbco/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 192.168.1.100 -> 93.184.216.34 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=202]
[FLOW] TCP-192.168.1.100:52000-93.184.216.34:80 state=ESTABLISHED pkts=1 bytes=202 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (844.1 pkts/s)
[+] Output saved to: TEST/BT1/test_05_http_post/output.jsonl
[+] Flow records saved to: /tmp/ids_flows_st_tvbco/flows.jsonl
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
      "protocol": "HTTP",
      "type": "request",
      "details": {
        "method": "POST",
        "uri": "/api/login",
        "body": "username=admin&password=secretPassword123"
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
    "timestamp": 1790269306.147771,
    "timestamp_iso": "2026-09-24T17:01:46.147771+00:00",
    "raw_len": 202,
    "network": {
      "layer": "IPv4",
      "src_ip": "192.168.1.100",
      "dst_ip": "93.184.216.34",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 202,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 162,
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
        "uri": "/api/login",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "ids.security.lab",
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": "41"
        },
        "body": "username=admin&password=secretPassword123",
        "detection_method": "payload_signature",
        "uri_normalized": "/api/login"
      }
    },
    "decode": {
      "decode_status": "decoded",
      "decoders": [
        "form_urlencoded"
      ],
      "fields": {
        "uri_decoded": "/api/login",
        "body_decoded": "username=admin&password=secretPassword123",
        "form_fields": {
          "username": "admin",
          "password": "secretPassword123"
        },
        "body_charset": "utf-8",
        "body_decode_status": "ok"
      },
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
      "flow_id": "TCP-192.168.1.100:52000-93.184.216.34:80",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  }
]
```
