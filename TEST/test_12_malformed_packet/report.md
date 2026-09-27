# Test Case Report: test_12_malformed_packet

- **Mục tiêu**: Malformed Packet
- **Yêu cầu kiểm thử**: Xử lý an toàn không crash khi gặp packet hỏng/cắt cụt
- **File PCAP**: `TEST/test_12_malformed_packet/test.pcap`
- **File Output JSONL**: `TEST/test_12_malformed_packet/output.jsonl`
- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_12_malformed_packet/test.pcap)
[*] Writing normalized events to: TEST/test_12_malformed_packet/output.jsonl
------------------------------------------------------------
[0001] 10.0.0.1 -> 10.0.0.2 (TCP):80 -> :80 [SYN] [len=40]
[0002] 10.0.0.2 -> 10.0.0.1 (PROTO_0) [len=23]
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (1759.7 pkts/s)
[+] Output saved to: TEST/test_12_malformed_packet/output.jsonl
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **2**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "transport": {
      "handshake": "SYN"
    }
  },
  {
    "application": {
      "protocol": "UNKNOWN"
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
    "timestamp": 1790269306.151901,
    "timestamp_iso": "2026-09-24T17:01:46.151901+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.1",
      "dst_ip": "10.0.0.2",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 100,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 80,
      "dst_port": 80,
      "payload_len": 0,
      "seq": 0,
      "ack": 0,
      "flags": [
        "SYN"
      ],
      "handshake": "SYN",
      "window": 8192,
      "data_offset": 5
    },
    "application": null,
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1790269306.152067,
    "timestamp_iso": "2026-09-24T17:01:46.152067+00:00",
    "raw_len": 23,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.2",
      "dst_ip": "10.0.0.1",
      "proto": "PROTO_0",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 23,
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
  }
]
```
