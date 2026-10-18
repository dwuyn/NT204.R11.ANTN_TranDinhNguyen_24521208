# Test Case Report: test_04_http_get

- **Mục tiêu**: HTTP GET Request
- **Yêu cầu kiểm thử**: Parse method, URI, version, headers
- **File PCAP**: `TEST/BT1/test_04_http_get/test.pcap`
- **File Output JSONL**: `TEST/BT1/test_04_http_get/output.jsonl`
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT1/test_04_http_get/test.pcap)
[*] Writing normalized events to: TEST/BT1/test_04_http_get/output.jsonl
[*] Writing flow records to: /tmp/ids_flows_xq_h2klv/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 192.168.1.100 -> 93.184.216.34 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=140]
[FLOW] TCP-192.168.1.100:52000-93.184.216.34:80 state=ESTABLISHED pkts=1 bytes=140 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (807.7 pkts/s)
[+] Output saved to: TEST/BT1/test_04_http_get/output.jsonl
[+] Flow records saved to: /tmp/ids_flows_xq_h2klv/flows.jsonl
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
        "method": "GET",
        "uri": "/api/v1/network/stats",
        "version": "HTTP/1.1"
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
        "detection_method": "payload_signature",
        "uri_normalized": "/api/v1/network/stats"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/api/v1/network/stats"
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
