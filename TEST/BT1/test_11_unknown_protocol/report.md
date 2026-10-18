# Test Case Report: test_11_unknown_protocol

- **Mục tiêu**: Unknown Protocol
- **Yêu cầu kiểm thử**: Xử lý an toàn không crash khi gặp giao thức không hỗ trợ
- **File PCAP**: `TEST/test_11_unknown_protocol/test.pcap`
- **File Output JSONL**: `TEST/test_11_unknown_protocol/output.jsonl`
- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_11_unknown_protocol/test.pcap)
[*] Writing normalized events to: TEST/test_11_unknown_protocol/output.jsonl
------------------------------------------------------------
[0001] 10.0.0.1 -> 10.0.0.2 (PROTO_253) [len=28]
[0002] 10.0.0.1 -> 10.0.0.2 (TCP):61111 -> :62222 [ACK,PSH] [len=58]
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (1442.8 pkts/s)
[+] Output saved to: TEST/test_11_unknown_protocol/output.jsonl
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **2**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "application": {
      "protocol": "UNKNOWN"
    }
  },
  {
    "errors": []
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
    "timestamp": 1790269306.151401,
    "timestamp_iso": "2026-09-24T17:01:46.151401+00:00",
    "raw_len": 28,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.1",
      "dst_ip": "10.0.0.2",
      "proto": "PROTO_253",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 28,
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
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1790269306.151548,
    "timestamp_iso": "2026-09-24T17:01:46.151548+00:00",
    "raw_len": 58,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.1",
      "dst_ip": "10.0.0.2",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 58,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 61111,
      "dst_port": 62222,
      "payload_len": 18,
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
