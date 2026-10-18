# Test Case Report: bt3_t11_distance_within

- **Mục tiêu**: Cửa sổ tương đối distance/within tính từ match trước đó
- **Yêu cầu kiểm thử**: Payload 'XXaaYYbbZZ': rule content 'aa' rồi 'bb' với distance:2 within:2 khớp (aa tại offset 2, bb tại offset 6); rule with within:1 chỉ mở cửa sổ 1 byte sau distance nên không khớp.
- **File PCAP**: `TEST/BT3/t11_distance_within/test.pcap`
- **File Output JSONL**: `TEST/BT3/t11_distance_within/output.jsonl`
- **File Detections**: `TEST/BT3/t11_distance_within/detections.jsonl`
- **Số detection**: 1
- **Số gói tin đã xử lý**: 1
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor, Flow Tracker & Core Engine
============================================================
[*] Mode: PCAP Import (TEST/BT3/t11_distance_within/test.pcap)
[*] Writing normalized events to: TEST/BT3/t11_distance_within/output.jsonl
[*] Writing flow records to: TEST/BT3/t11_distance_within/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
[*] Rules: files=1 loaded=2 invalid=0 unsupported=0
[*] Writing detections to: TEST/BT3/t11_distance_within/detections.jsonl
------------------------------------------------------------
[ALERT] sid=1100091 rev=1 "commands two bytes apart" 10.0.0.10:52000 -> 10.0.0.20:80 (TCP/UNKNOWN) flow=TCP-10.0.0.10:52000-10.0.0.20:80
[0001] 10.0.0.10 -> 10.0.0.20 (TCP):52000 -> :80 [ACK,PSH] [len=50]
[FLOW] TCP-10.0.0.10:52000-10.0.0.20:80 state=ESTABLISHED pkts=1 bytes=50 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 1 packets in 0.00s (710.1 pkts/s)
[+] Output saved to: TEST/BT3/t11_distance_within/output.jsonl
[+] Flow records saved to: TEST/BT3/t11_distance_within/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
[+] Rules: loaded=2 events_evaluated=1 candidate_rules=2 matches=1
[+] Detections: 1 written to TEST/BT3/t11_distance_within/detections.jsonl
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **1**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "transport": {
      "layer": "TCP",
      "payload_len": 10
    }
  }
]
```

- Số detection tối thiểu: **1**
- Danh sách detection subset bắt buộc phải khớp:
```json
[
  {
    "sid": 1100091,
    "matched": {
      "contents": [
        {
          "content": "aa",
          "offset": 2
        },
        {
          "content": "bb",
          "offset": 6
        }
      ]
    }
  }
]
```
- Danh sách detection bị cấm (không được xuất hiện):
```json
[
  {
    "sid": 1100092
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
    "timestamp": 1700000000.0,
    "timestamp_iso": "2023-11-14T22:13:20+00:00",
    "raw_len": 50,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.20",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 50,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 52000,
      "dst_port": 80,
      "payload_len": 10,
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
      "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  }
]
```

## 6. Detection Events (detections.jsonl)
- **Số detection**: 1
- **Số detection tối thiểu**: 1
- **Kỳ vọng detection (JSON subset bắt buộc khớp)**:
```json
[
  {
    "sid": 1100091,
    "matched": {
      "contents": [
        {
          "content": "aa",
          "offset": 2
        },
        {
          "content": "bb",
          "offset": 6
        }
      ]
    }
  }
]
```
- **Kỳ vọng detection bị cấm**:
```json
[
  {
    "sid": 1100092
  }
]
```
- **Chi tiết detection records**:
```json
[
  {
    "packet_id": 1,
    "timestamp": 1700000000.0,
    "timestamp_iso": "2023-11-14T22:13:20+00:00",
    "action": "alert",
    "sid": 1100091,
    "rev": 1,
    "msg": "commands two bytes apart",
    "classtype": null,
    "priority": null,
    "protocol": "TCP",
    "application_protocol": "UNKNOWN",
    "src_ip": "10.0.0.10",
    "src_port": 52000,
    "dst_ip": "10.0.0.20",
    "dst_port": 80,
    "direction": "forward",
    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
    "flow_state": "ESTABLISHED",
    "matched": {
      "contents": [
        {
          "content": "aa",
          "offset": 2,
          "length": 2,
          "nocase": false
        },
        {
          "content": "bb",
          "offset": 6,
          "length": 2,
          "nocase": false
        }
      ],
      "fields": []
    },
    "rule_file": "TEST/BT3/t11_distance_within/test.rules"
  }
]
```
