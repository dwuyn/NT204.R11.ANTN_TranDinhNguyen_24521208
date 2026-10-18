# Test Case Report: bt2_t02_html_entity

- **Mục tiêu**: Giải mã HTML entity trong body của HTTP response text/html
- **Yêu cầu kiểm thử**: Body gốc vẫn giữ nguyên entity, decode.fields.body_decoded đã unescape, charset utf-8 và body_decode_status ok.
- **File PCAP**: `TEST/bt2_t02_html_entity/test.pcap`
- **File Output JSONL**: `TEST/bt2_t02_html_entity/output.jsonl`
- **File Flow Records**: `TEST/bt2_t02_html_entity/flows.jsonl`
- **Số flow record**: 1- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t02_html_entity/test.pcap)
[*] Writing normalized events to: TEST/bt2_t02_html_entity/output.jsonl
[*] Writing flow records to: TEST/bt2_t02_html_entity/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.20 -> 10.0.0.10 (TCP):80 -> :52000 [ACK,PSH] | HTTP (response) [len=183]
[FLOW] TCP-10.0.0.20:80-10.0.0.10:52000 state=ESTABLISHED pkts=1 bytes=183 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (702.3 pkts/s)
[+] Output saved to: TEST/bt2_t02_html_entity/output.jsonl
[+] Flow records saved to: TEST/bt2_t02_html_entity/flows.jsonl
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
        "body": "<p>Hello &lt;script&gt;alert(1)&lt;/script&gt; &amp; welcome</p>"
      }
    }
  },
  {
    "decode": {
      "decoders": [
        "html_entities"
      ],
      "fields": {
        "body_decoded": "<p>Hello <script>alert(1)</script> & welcome</p>",
        "body_charset": "utf-8",
        "body_decode_status": "ok"
      }
    }
  }
]
```
- Số flow tối thiểu: **0**
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
    "raw_len": 183,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.20",
      "dst_ip": "10.0.0.10",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 183,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 80,
      "dst_port": 52000,
      "payload_len": 143,
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
          "Content-Type": "text/html; charset=utf-8",
          "Content-Length": "64"
        },
        "body": "<p>Hello &lt;script&gt;alert(1)&lt;/script&gt; &amp; welcome</p>",
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
        "body_decoded": "<p>Hello <script>alert(1)</script> & welcome</p>"
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
      "flow_id": "TCP-10.0.0.20:80-10.0.0.10:52000",
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
- **Số flow tối thiểu**: 0
- **Kỳ vọng flow (JSON subset)**:
```json
[]
```
- **Chi tiết flow records**:
```json
[
  {
    "flow_id": "TCP-10.0.0.20:80-10.0.0.10:52000",
    "flow_seq": 1,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "endpoint_a": {
      "ip": "10.0.0.20",
      "port": 80
    },
    "endpoint_b": {
      "ip": "10.0.0.10",
      "port": 52000
    },
    "state": "ESTABLISHED",
    "start_time": 1700000000.0,
    "last_seen": 1700000000.0,
    "duration": 0.0,
    "packet_count": 1,
    "byte_count": 183,
    "forward": {
      "packet_count": 1,
      "byte_count": 183
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
