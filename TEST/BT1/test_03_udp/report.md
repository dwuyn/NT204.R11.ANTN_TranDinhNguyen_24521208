# Test Case Report: test_03_udp

- **Mục tiêu**: UDP Datagram
- **Yêu cầu kiểm thử**: Parse UDP packet, trích xuất port và payload
- **File PCAP**: `TEST/BT1/test_03_udp/test.pcap`
- **File Output JSONL**: `TEST/BT1/test_03_udp/output.jsonl`
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT1/test_03_udp/test.pcap)
[*] Writing normalized events to: TEST/BT1/test_03_udp/output.jsonl
[*] Writing flow records to: /tmp/ids_flows_82lqfe35/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 192.168.1.100 -> 192.168.1.200 (UDP):12345 -> :54321 [len=75]
[FLOW] UDP-192.168.1.100:12345-192.168.1.200:54321 state=ESTABLISHED pkts=1 bytes=75 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (726.8 pkts/s)
[+] Output saved to: TEST/BT1/test_03_udp/output.jsonl
[+] Flow records saved to: /tmp/ids_flows_82lqfe35/flows.jsonl
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
    "transport": {
      "layer": "UDP",
      "payload_len": 47
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
    "decode": {
      "decode_status": "unchanged",
      "decoders": [],
      "fields": {},
      "warnings": []
    },
    "preprocess": {
      "preprocess_status": "partial",
      "processing_action": "forward",
      "reason": "unsupported_protocol",
      "normalizations": [],
      "warnings": []
    },
    "flow": {
      "flow_id": "UDP-192.168.1.100:12345-192.168.1.200:54321",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  }
]
```
