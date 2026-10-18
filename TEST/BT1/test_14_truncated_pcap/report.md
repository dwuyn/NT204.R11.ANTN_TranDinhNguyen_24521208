# Test Case Report: test_14_truncated_pcap

- **Mục tiêu**: Truncated PCAP
- **Yêu cầu kiểm thử**: Không crash khi file PCAP bị cắt cụt, vẫn parse gói đầy đủ đầu tiên
- **File PCAP**: `TEST/BT1/test_14_truncated_pcap/truncated.pcap`
- **File Output JSONL**: `TEST/BT1/test_14_truncated_pcap/output.jsonl`
- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT1/test_14_truncated_pcap/truncated.pcap)
[*] Writing normalized events to: TEST/BT1/test_14_truncated_pcap/output.jsonl
[*] Writing flow records to: /tmp/ids_flows_lp9hijdm/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.30 -> 10.0.0.40 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=90]
[0002] 127.0.0.1 -> 127.0.0.1 (PROTO_0) [len=8]
[FLOW] TCP-10.0.0.30:52000-10.0.0.40:80 state=ESTABLISHED pkts=1 bytes=90 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (1357.8 pkts/s)
[+] Output saved to: TEST/BT1/test_14_truncated_pcap/output.jsonl
[+] Flow records saved to: /tmp/ids_flows_lp9hijdm/flows.jsonl
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
      "details": {
        "method": "GET"
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
    "timestamp": 1790531041.314243,
    "timestamp_iso": "2026-09-27T17:44:01.314243+00:00",
    "raw_len": 90,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.30",
      "dst_ip": "10.0.0.40",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 90,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 50,
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
        "uri": "/truncated",
        "version": "HTTP/1.1",
        "headers": {
          "Host": "truncated.local"
        },
        "body": "",
        "detection_method": "payload_signature",
        "uri_normalized": "/truncated"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {
        "uri_decoded": "/truncated"
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
      "flow_id": "TCP-10.0.0.30:52000-10.0.0.40:80",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1790531041.314512,
    "timestamp_iso": "2026-09-27T17:44:01.314512+00:00",
    "raw_len": 8,
    "network": {
      "layer": "IPv4",
      "src_ip": "127.0.0.1",
      "dst_ip": "127.0.0.1",
      "proto": "PROTO_0",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 90,
      "flags": []
    },
    "transport": null,
    "application": {
      "protocol": "UNKNOWN",
      "type": "unknown",
      "details": {
        "detection_method": "none"
      }
    },
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {},
      "warnings": []
    },
    "preprocess": {
      "preprocess_status": "partial",
      "processing_action": "forward",
      "reason": "missing_transport_layer",
      "normalizations": [],
      "warnings": [
        "unsupported_protocol"
      ]
    },
    "flow": null,
    "errors": []
  }
]
```
