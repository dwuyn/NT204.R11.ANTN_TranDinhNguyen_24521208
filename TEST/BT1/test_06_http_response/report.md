# Test Case Report: test_06_http_response

- **Mục tiêu**: HTTP Response
- **Yêu cầu kiểm thử**: Parse HTTP version, status code, reason phrase, headers, body
- **File PCAP**: `TEST/BT1/test_06_http_response/test.pcap`
- **File Output JSONL**: `TEST/BT1/test_06_http_response/output.jsonl`
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT1/test_06_http_response/test.pcap)
[*] Writing normalized events to: TEST/BT1/test_06_http_response/output.jsonl
[*] Writing flow records to: /tmp/ids_flows_69an2st7/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 93.184.216.34 -> 192.168.1.100 (TCP):80 -> :52000 [ACK,PSH] | HTTP (response) [len=176]
[FLOW] TCP-93.184.216.34:80-192.168.1.100:52000 state=ESTABLISHED pkts=1 bytes=176 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (749.3 pkts/s)
[+] Output saved to: TEST/BT1/test_06_http_response/output.jsonl
[+] Flow records saved to: /tmp/ids_flows_69an2st7/flows.jsonl
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
      "type": "response",
      "details": {
        "status_code": 200,
        "reason": "OK"
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
    "decode": {
      "decode_status": "decoded",
      "decoders": [
        "html_entities"
      ],
      "fields": {
        "body_charset": "utf-8",
        "body_decode_status": "ok",
        "body_decoded": "<html><body>Access Granted</body></html>"
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
      "flow_id": "TCP-93.184.216.34:80-192.168.1.100:52000",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  }
]
```
