# Test Case Report: bt2_t03_smtp_mime

- **Mục tiêu**: Giải mã MIME base64, quoted-printable và header RFC 2047 trong SMTP DATA
- **Yêu cầu kiểm thử**: Hai packet MIME được nhận là SMTP data, body base64 và quoted-printable giải mã đúng, header Subject RFC 2047 giải mã thành 'Tái khoan', cùng một flow SMTP.
- **File PCAP**: `TEST/bt2_t03_smtp_mime/test.pcap`
- **File Output JSONL**: `TEST/bt2_t03_smtp_mime/output.jsonl`
- **File Flow Records**: `TEST/bt2_t03_smtp_mime/flows.jsonl`
- **Số flow record**: 1- **Số gói tin đã xử lý**: 2
- **Trạng thái**: **PASS (Thành công)**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
============================================================
  IDS Capture, Decoder, Preprocessor & Flow Tracker
============================================================
[*] Mode: PCAP Import (TEST/bt2_t03_smtp_mime/test.pcap)
[*] Writing normalized events to: TEST/bt2_t03_smtp_mime/output.jsonl
[*] Writing flow records to: TEST/bt2_t03_smtp_mime/flows.jsonl
[*] Flow tracker: tcp_timeout=120.0s udp_timeout=30.0s max_active_flows=10000
[*] Decoder: max_decode_size=1048576 bytes decode_html_entities=True
------------------------------------------------------------
[0001] 10.0.0.10 -> 10.0.0.25 (TCP):45000 -> :25 [ACK,PSH] | SMTP (data) [len=274]
[0002] 10.0.0.10 -> 10.0.0.25 (TCP):45000 -> :25 [ACK,PSH] | SMTP (data) [len=198]
[FLOW] TCP-10.0.0.10:45000-10.0.0.25:25 state=ESTABLISHED pkts=2 bytes=472 reason=end_of_capture
------------------------------------------------------------
[+] Finished: Processed 2 packets in 0.00s (615.8 pkts/s)
[+] Output saved to: TEST/bt2_t03_smtp_mime/output.jsonl
[+] Flow records saved to: TEST/bt2_t03_smtp_mime/flows.jsonl
[+] Flows: created=1 closed=1 active_flushed=1
[+] Flow close reasons: fin=0 rst=0 timeout=0 overflow=0 end_of_capture=1
[+] Dropped events (preprocessor): 0
============================================================
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **2**
- Danh sách JSON subset bắt buộc phải khớp:
```json
[
  {
    "application": {
      "protocol": "SMTP",
      "type": "data"
    }
  },
  {
    "decode": {
      "fields": {
        "mime_body_decoded": "Hello World! This is a base64 message.",
        "content_transfer_encoding": "base64"
      },
      "decoders": [
        "base64"
      ]
    }
  },
  {
    "decode": {
      "fields": {
        "mime_body_decoded": "Hệ thống IDS đang hoạt động.",
        "content_transfer_encoding": "quoted-printable"
      },
      "decoders": [
        "quoted_printable"
      ]
    }
  },
  {
    "decode": {
      "fields": {
        "headers_decoded": {
          "Subject": "Tái khoan"
        }
      }
    }
  }
]
```
- Số flow tối thiểu: **1**
- Danh sách flow subset bắt buộc phải khớp:
```json
[
  {
    "application_protocol": "SMTP",
    "packet_count": 2
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
    "raw_len": 274,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.25",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 274,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 45000,
      "dst_port": 25,
      "payload_len": 234,
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
      "protocol": "SMTP",
      "type": "data",
      "details": {
        "headers": {
          "From": "sender@uit.edu.vn",
          "To": "rcpt@uit.edu.vn",
          "Subject": "=?utf-8?B?VMOhaSBraG9hbg==?=",
          "MIME-Version": "1.0",
          "Content-Type": "text/plain; charset=utf-8",
          "Content-Transfer-Encoding": "base64"
        },
        "body": "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgbWVzc2FnZS4=",
        "mime": true,
        "detection_method": "payload_signature"
      }
    },
    "decode": {
      "decode_status": "decoded",
      "decoders": [
        "base64",
        "rfc2047"
      ],
      "fields": {
        "content_transfer_encoding": "base64",
        "mime_charset": "utf-8",
        "mime_body_decoded": "Hello World! This is a base64 message.",
        "headers_decoded": {
          "Subject": "Tái khoan"
        }
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
      "flow_id": "TCP-10.0.0.10:45000-10.0.0.25:25",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": true
    },
    "errors": []
  },
  {
    "packet_id": 2,
    "timestamp": 1700000000.1,
    "timestamp_iso": "2023-11-14T22:13:20.100000+00:00",
    "raw_len": 198,
    "network": {
      "layer": "IPv4",
      "src_ip": "10.0.0.10",
      "dst_ip": "10.0.0.25",
      "proto": "TCP",
      "ttl": 64,
      "id": 1,
      "ihl": 5,
      "tos": 0,
      "total_len": 198,
      "flags": []
    },
    "transport": {
      "layer": "TCP",
      "src_port": 45000,
      "dst_port": 25,
      "payload_len": 158,
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
      "protocol": "SMTP",
      "type": "data",
      "details": {
        "headers": {
          "Content-Type": "text/plain; charset=utf-8",
          "Content-Transfer-Encoding": "quoted-printable"
        },
        "body": "H=E1=BB=87 th=E1=BB=91ng IDS =C4=91ang ho=E1=BA=A1t =C4=91=E1=BB=99ng.",
        "mime": true,
        "detection_method": "payload_signature"
      }
    },
    "decode": {
      "decode_status": "decoded",
      "decoders": [
        "quoted_printable"
      ],
      "fields": {
        "content_transfer_encoding": "quoted-printable",
        "mime_charset": "utf-8",
        "mime_body_decoded": "Hệ thống IDS đang hoạt động."
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
      "flow_id": "TCP-10.0.0.10:45000-10.0.0.25:25",
      "direction": "forward",
      "state": "ESTABLISHED",
      "is_new_flow": false
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
[
  {
    "application_protocol": "SMTP",
    "packet_count": 2
  }
]
```
- **Chi tiết flow records**:
```json
[
  {
    "flow_id": "TCP-10.0.0.10:45000-10.0.0.25:25",
    "flow_seq": 1,
    "protocol": "TCP",
    "application_protocol": "SMTP",
    "endpoint_a": {
      "ip": "10.0.0.10",
      "port": 45000
    },
    "endpoint_b": {
      "ip": "10.0.0.25",
      "port": 25
    },
    "state": "ESTABLISHED",
    "start_time": 1700000000.0,
    "last_seen": 1700000000.1,
    "duration": 0.1,
    "packet_count": 2,
    "byte_count": 472,
    "forward": {
      "packet_count": 2,
      "byte_count": 472
    },
    "backward": {
      "packet_count": 0,
      "byte_count": 0
    },
    "syn_count": 0,
    "ack_count": 2,
    "fin_count": 0,
    "rst_count": 0,
    "closed": true,
    "close_reason": "end_of_capture"
  }
]
```
