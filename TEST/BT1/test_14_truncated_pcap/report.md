# Test Case Report: test_14_truncated_pcap

- **Mục tiêu**: Truncated PCAP
- **Yêu cầu kiểm thử**: Không crash khi file PCAP bị cắt cụt, vẫn parse gói đầy đủ đầu tiên
- **File PCAP**: `TEST/test_14_truncated_pcap/truncated.pcap`
- **File Output JSONL**: `TEST/test_14_truncated_pcap/output.jsonl`
- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_14_truncated_pcap/truncated.pcap)
[*] Writing normalized events to: TEST/test_14_truncated_pcap/output.jsonl
------------------------------------------------------------
[0001] 10.0.0.30 -> 10.0.0.40 (TCP):52000 -> :80 [ACK,PSH] | HTTP (request) [len=90]
[0002] 127.0.0.1 -> 127.0.0.1 (PROTO_0) [len=8]
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (1822.4 pkts/s)
[+] Output saved to: TEST/test_14_truncated_pcap/output.jsonl
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
        "detection_method": "payload_signature"
      }
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
    "errors": []
  }
]
```
