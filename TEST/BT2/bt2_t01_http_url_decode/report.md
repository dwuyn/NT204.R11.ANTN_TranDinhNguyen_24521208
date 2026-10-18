# Test Case Report: bt2_t01_http_url_decode

- **Mục tiêu**: Giải mã percent-encoding trên URI của HTTP request
- **Yêu cầu kiểm thử**: Event HTTP request giữ nguyên URI gốc đã mã hóa, decode.fields.uri_decoded chứa chuỗi %27%20OR%201%3D1 đã giải mã, event hợp lệ (forward) và có 1 flow TCP.
- **File PCAP**: `TEST/bt2_t01_http_url_decode/test.pcap`
- **File Output JSONL**: `TEST/bt2_t01_http_url_decode/output.jsonl`
- **File Flow Records**: `TEST/bt2_t01_http_url_decode/flows.jsonl`
- **Số flow record**: 1- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t01_http_url_decode/test.pcap)
[*] Writing normalized events to: TEST/bt2_t01_http_url_decode/output.jsonl
[*] Writing flow records to: TEST/bt2_t01_http_url_decode/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=108]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=ESTABLISHED pkts=1 bytes=108 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (499.6 pkts/s)
[+] Output saved to: TEST/bt2_t01_http_url_decode/output.jsonl
[+] Flow records saved to: TEST/bt2_t01_http_url_decode/flows.jsonl
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
      "details": {
        "uri": "/search?q=%27%20OR%201%3D1&lang=en"
      }
    }
  },
  {
    "decode": {
      "decode_status": "decoded",
      "fields": {
        "uri_decoded": "/search?q=' OR 1=1&lang=en"
      }
    }
  },
  {
    "preprocess": {
      "preprocess_status": "valid",
      "processing_action": "forward"
    }
  }
]
```
- Số flow tối thiểu: **1**
- Danh sách flow subset bắt buộc phải khớp:
```json
[]
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
    "timestamp": 1700000000.0,
    "timestamp_iso": "2023-11-14T22:13:20+00:00",
    "raw_len": 108,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 108,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 68,
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
        "uri": "/search?q=%27%20OR%201%3D1&lang=en",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "ids.local"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/search?q=' OR 1=1&lang=en"
      }
    },
    "decode": {
      "decode_status": "decoded",
      "decoders": [
        "percent_url"
      ],
      "fields": {
        "uri_decoded": "/search?q=' OR 1=1&lang=en"
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
      "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  }
]
```

## 5. Flow Records (flows.jsonl)
- **Số flow record**: 1
- **Số flow tối thiểu**: 1
- **Kỳ vọng flow (JSON subset)**:
```json
[]
```
- **Chi tiết flow records**:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "flow_seq": 1,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "endpoint_a": {
      "ip": "10.0.0.10",
      "port": 52000
    },
    "endpoint_b": {
      "ip": "10.0.0.20",
      "port": 80
    },
    "state": "ESTABLISHED",
    "start_time": 1700000000.0,
    "last_seen": 1700000000.0,
    "duration": 0.0,
    "packet_count": 1,
    "byte_count": 108,
    "forward": {
      "packet_count": 1,
      "byte_count": 108
    },
    "backward": {
      "packet_count": 0,
      "byte_count": 0
    },
    "syn_count": 0,
    "ack_count": 1,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "end_of_capture"
  }
]
```
