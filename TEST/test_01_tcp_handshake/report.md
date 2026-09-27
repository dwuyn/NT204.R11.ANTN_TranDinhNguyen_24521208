# Test Case Report: test_01_tcp_handshake

- **Mục tiêu**: TCP 3-way Handshake
- **Yêu cầu kiểm thử**: Nhận diện đúng SYN, SYN/ACK, ACK
- **File PCAP**: `TEST/test_01_tcp_handshake/test.pcap`
- **File Output JSONL**: `TEST/test_01_tcp_handshake/output.jsonl`
- **Số gói tin đã xử lý**: 3
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Packet Capture & Parser Engine
============================================================
[*] Mode: PCAP Import (TEST/test_01_tcp_handshake/test.pcap)
[*] Writing normalized events to: TEST/test_01_tcp_handshake/output.jsonl
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.1 (TCP):51234 -> :80 [SYN] [len=40]
[0002] 10.0.0.1 -> 10.0.0.10 (TCP):80 -> :51234 [SYN,ACK] [len=40]
[0003] 10.0.0.10 -> 10.0.0.1 (TCP):51234 -> :80 [ACK] [len=40]
------------------------------------------------------------
[+] Finished: Processed 3 packets in 0.00s (2192.1 pkts/s)
[+] Output saved to: TEST/test_01_tcp_handshake/output.jsonl
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **3**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "transport": {
      "handshake": "SYN"
    }
  },
  {
    "transport": {
      "handshake": "SYN-ACK"
    }
  },
  {
    "transport": {
      "handshake": "ACK"
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
    "timestamp": 1790269306.1465,
    "timestamp_iso": "2026-09-24T17:01:46.146500+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.1",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 40,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 51234,
      "dst_port": 80,
      "payload_len": 0,
      "seq": 1000,
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
    "timestamp": 1790269306.146753,
    "timestamp_iso": "2026-09-24T17:01:46.146753+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.1",
      "dst_ip": "10.0.0.10",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 40,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 80,
      "dst_port": 51234,
      "payload_len": 0,
      "seq": 5000,
      "ack": 1001,
      "flags": [
        "SYN",
        "ACK"
      ],
      "handshake": "SYN-ACK",
      "window": 8192,
      "data_offset": 5
    },
    "application": null,
    "errors": []
  },
  {
    "packet_id": 3,
    "timestamp": 1790269306.14688,
    "timestamp_iso": "2026-09-24T17:01:46.146880+00:00",
    "raw_len": 40,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.1",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 40,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 51234,
      "dst_port": 80,
      "payload_len": 0,
      "seq": 1001,
      "ack": 5001,
      "flags": [
        "ACK"
      ],
      "handshake": "ACK",
      "window": 8192,
      "data_offset": 5
    },
    "application": null,
    "errors": []
  }
]
```
