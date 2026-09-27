# BÀI TẬP 1: PACKET CAPTURE & PARSER CHO HỆ THỐNG IDS

> **Môn học**: NT204.R11.ANTN - An toàn mạng  
> **Sinh viên**: Trần Đình Nguyên  
> **MSSV**: 24521208  
> **Lớp**: NT204.R11.ANTN  
> **Giảng viên hướng dẫn**: Bộ môn Mạng máy tính & Truyền thông  
> **Repository**: `dwuyn/NT204.R11.ANTN_TranDinhNguyen_24521208`  

---

## 1. Giới thiệu Tổng quan

Dự án này là module **Packet Capture & Parser** - thành phần nền tảng đầu vào của một hệ thống phát hiện xâm nhập (**Intrusion Detection System - IDS**). Module có nhiệm vụ:
- Thu thập lưu lượng mạng từ **card mạng (live capture)** hoặc từ **file PCAP**.
- Đưa toàn bộ gói tin qua **một pipeline xử lý thống nhất** để phân tích các giao thức mạng:
  - **Network Layer**: IPv4 (trích xuất đầy đủ IP header, cờ phân mảnh DF/MF, TTL, Protocol ID).
  - **Transport Layer**: TCP (bóc tách cờ SYN, ACK, FIN, RST, PSH, URG; nhận diện TCP 3-way handshake) và UDP.
  - **Application Layer**: HTTP/1.x, DNS, SMTP (kết hợp nhận diện bằng signature payload và port heuristic, hỗ trợ nhận diện trên non-standard port).
- Chuẩn hóa toàn bộ gói tin thành một đối tượng dữ liệu duy nhất (**Normalized IDS Event**) và xuất ra định dạng **JSON Lines (`.jsonl`)** để phục vụ các bài toán phân tích & phát hiện tấn công ở các module IDS phía sau mà không cần truy cập trực tiếp raw packet.

---

## 2. Kiến trúc Hệ thống & Pipeline Xử lý

Quy trình xử lý một gói tin tuân thủ nghiêm ngặt theo mô hình pipeline 5 giai đoạn:

```text
       [ Raw Packet ] (từ Live Interface hoặc PCAP File)
             │
             ▼
     [ Network Parser ] (IPv4: Header, TTL, Cờ phân mảnh DF/MF, Protocol)
             │
             ▼
    [ Transport Parser ] (TCP: Flags, Handshake, Seq/Ack / UDP: Ports, Length)
             │
             ▼
 [ App Protocol Detector ] (Kiểm tra Payload Signature + Port Heuristics)
             │
             ▼
  [ App Protocol Parser ] (HTTP/1.x, DNS, SMTP chuyên biệt)
             │
             ▼
   [ Normalized Event ] ──► [ JSON Lines Logger ] ──► [ output.jsonl & Console ]
```

### Đặc điểm thiết kế:
- **Unified Pipeline**: Không tạo hai parser riêng biệt cho Live traffic và PCAP import. Cả hai nguồn đều được streaming qua generator `CapturedPacket` và đưa vào cùng một pipeline.
- **Deep Packet Inspection (DPI)**: Không phụ thuộc tuyệt đối vào cổng dịch vụ (port). Hệ thống soi trực tiếp byte đầu payload để nhận diện HTTP method (`GET`, `POST`), SMTP command (`HELO`, `MAIL FROM`), DNS wire structure ngay cả khi chạy trên port lạ (non-standard port).
- **Zero-Crash Fault Tolerance**: Hệ thống được bọc try-catch tại từng tầng, bảo đảm không bị dừng (crash) khi gặp gói tin bị cắt cụt (truncated), header sai lệch (malformed) hay dữ liệu binary không decode được.

---

## 3. Cấu trúc Thư mục

```text
NT204.R11.ANTN_TranDinhNguyen_24521208/
├── .gitignore                      # Cấu hình bỏ qua file nhị phân và cache
├── README.md                       # Tài liệu hướng dẫn & AI disclosure
├── requirements.txt                # Thư viện Python cần thiết (scapy)
├── main.py                         # CLI entrypoint của chương trình IDS
├── capture/
│   ├── __init__.py
│   └── capturer.py                 # Module thu thập packet (PCAP & Live sniff)
├── parsers/
│   ├── __init__.py
│   ├── models.py                   # Dataclass cấu trúc Normalized IDS Event
│   ├── network.py                  # Module parse IPv4
│   ├── transport.py                # Module parse TCP (handshake/flags) & UDP
│   ├── detector.py                 # Module nhận diện Layer 7 (DPI & Port)
│   └── application/
│       ├── __init__.py
│       ├── http.py                 # Parser HTTP/1.x (GET/POST có body, Response)
│       ├── dns.py                  # Parser DNS (Query domain/type, Answers)
│       └── smtp.py                 # Parser SMTP (Commands, Status codes)
├── pipeline/
│   ├── __init__.py
│   └── pipeline.py                 # Pipeline điều phối kết nối các parser
├── storage/
│   ├── __init__.py
│   └── logger.py                   # Module ghi log JSON Lines và format console
├── tests/                          # Bộ unit tests tự động
│   ├── generate_test_pcaps.py      # Script sinh dữ liệu PCAP chuẩn cho 12 test case
│   ├── run_case.py                 # Script chạy test case và xuất báo cáo markdown
│   ├── test_models.py
│   ├── test_capturer.py
│   ├── test_network_parser.py
│   ├── test_transport_parser.py
│   ├── test_detector.py
│   ├── test_http_parser.py
│   ├── test_dns_parser.py
│   ├── test_smtp_parser.py
│   └── test_pipeline.py
└── TEST/                           # Thư mục chứa 12 test cases bắt buộc theo đề bài
    ├── test_01_tcp_handshake/      # Test TCP Handshake (SYN, SYN-ACK, ACK)
    ├── test_02_tcp_data/           # Test TCP Data có payload
    ├── test_03_udp/                # Test UDP Datagram
    ├── test_04_http_get/           # Test HTTP GET Request
    ├── test_05_http_post/          # Test HTTP POST Request có Body
    ├── test_06_http_response/      # Test HTTP Response
    ├── test_07_dns_query/          # Test DNS Query
    ├── test_08_dns_response/       # Test DNS Response
    ├── test_09_smtp_command/       # Test SMTP Commands (HELO, MAIL, RCPT)
    ├── test_10_smtp_response/      # Test SMTP Responses (220, 250, 354)
    ├── test_11_unknown_protocol/   # Test Giao thức lạ không bị crash
    └── test_12_malformed_packet/   # Test Gói tin hỏng/cắt cụt không bị crash
```

---

## 4. Hướng dẫn Cài đặt & Sử dụng

### 4.1. Môi trường yêu cầu
- **Hệ điều hành**: Linux (Ubuntu, Debian, Fedora, Arch Linux, v.v.)
- **Python**: Phiên bản `>= 3.10`
- **Thư viện yêu cầu**: `scapy >= 2.5.0` (`pip install -r requirements.txt`)

### 4.2. Hướng dẫn chạy CLI (`main.py`)

#### A. Đọc và phân tích file PCAP:
```bash
python3 main.py --pcap TEST/test_01_tcp_handshake/test.pcap --output output.jsonl
```

#### B. Thu thập và phân tích trực tiếp từ card mạng (Live Capture):
> *Lưu ý*: Cần quyền quản trị (`sudo`) để mở socket thô (`AF_PACKET / SOCK_RAW`).
```bash
# Bắt packet trên interface eth0
sudo python3 main.py --interface eth0 --output live_traffic.jsonl

# Bắt tối đa 100 packet trên interface loopback kèm bộ lọc BPF
sudo python3 main.py --interface lo --count 100 --bpf "tcp or udp" --output lo.jsonl
```

#### C. Chạy bộ kiểm thử tự động (Unit Tests):
```bash
python3 -m unittest discover -v tests
```

---

## 5. Đặc tả Cấu trúc Output Chuẩn hóa (`NormalizedEvent`)

Mỗi dòng trong file `.jsonl` là một đối tượng JSON độc lập đại diện cho 1 gói tin được chuẩn hóa:

```json
{
  "packet_id": 1,
  "timestamp": 1774399768.123456,
  "timestamp_iso": "2026-03-24T17:42:48.123456+00:00",
  "raw_len": 74,
  "network": {
    "layer": "IPv4",
    "src_ip": "192.168.1.100",
    "dst_ip": "93.184.216.34",
    "proto": "TCP",
    "ttl": 64,
    "id": 1234,
    "ihl": 5,
    "tos": 0,
    "total_len": 60,
    "flags": ["DF"]
  },
  "transport": {
    "layer": "TCP",
    "src_port": 52000,
    "dst_port": 80,
    "payload_len": 120,
    "seq": 1001,
    "ack": 5001,
    "flags": ["PSH", "ACK"],
    "handshake": null,
    "window": 64240,
    "data_offset": 8
  },
  "application": {
    "protocol": "HTTP",
    "type": "request",
    "details": {
      "method": "POST",
      "uri": "/api/login",
      "version": "HTTP/1.1",
      "headers": {
        "Host": "ids.security.lab",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "41"
      },
      "body": "username=admin&password=secretPassword123",
      "detection_method": "payload_signature"
    }
  },
  "errors": []
}
```

---

## 6. Kết quả Thực hiện 12 Test Cases Bắt buộc

Toàn bộ 12 test cases đều được tạo PCAP độc lập, chạy phân tích và lưu báo cáo chi tiết kèm log JSON trong thư mục `TEST/`:

| STT | Tên Test Case | Mục tiêu kiểm thử | Trạng thái | Thư mục lưu trữ |
|:---:|:---|:---|:---:|:---|
| 01 | **TCP Handshake** | Nhận diện đúng SYN, SYN/ACK, ACK | **PASS** | `TEST/test_01_tcp_handshake/` |
| 02 | **TCP Data** | Parse TCP packet có payload và kiểm tra độ dài | **PASS** | `TEST/test_02_tcp_data/` |
| 03 | **UDP** | Parse UDP packet, trích xuất port, payload | **PASS** | `TEST/test_03_udp/` |
| 04 | **HTTP GET** | Parse HTTP request method, URI, headers | **PASS** | `TEST/test_04_http_get/` |
| 05 | **HTTP POST** | Parse HTTP request có body, headers | **PASS** | `TEST/test_05_http_post/` |
| 06 | **HTTP Response** | Parse HTTP status code, headers, reason | **PASS** | `TEST/test_06_http_response/` |
| 07 | **DNS Query** | Parse domain name và query type (A, AAAA...) | **PASS** | `TEST/test_07_dns_query/` |
| 08 | **DNS Response** | Parse answer records (name, type, rdata, ttl) | **PASS** | `TEST/test_08_dns_response/` |
| 09 | **SMTP Command** | Parse HELO/EHLO, MAIL FROM, RCPT TO | **PASS** | `TEST/test_09_smtp_command/` |
| 10 | **SMTP Response** | Parse SMTP status codes (220, 250, 354) | **PASS** | `TEST/test_10_smtp_response/` |
| 11 | **Unknown Protocol** | Xử lý an toàn không crash khi gặp protocol lạ | **PASS** | `TEST/test_11_unknown_protocol/` |
| 12 | **Malformed Packet** | Xử lý an toàn không crash khi gặp packet hỏng/cắt cụt | **PASS** | `TEST/test_12_malformed_packet/` |

---

## 7. AI Disclosure

- **Công cụ AI sử dụng**: Antigravity (Gemini 3.8 flash)
- **Mục đích sử dụng**:
  - Hỗ trợ xây dựng kế hoạch phân rã tính năng (task breakdown) theo đúng phương pháp luận kỹ thuật phần mềm.
  - Hỗ trợ thiết kế kiến trúc pipeline 5 tầng (`parsers/`, `pipeline/`, `capture/`, `storage/`).
  - Hỗ trợ tạo các bộ dữ liệu test case mẫu chuẩn cho 12 kịch bản bắt buộc bằng Scapy.
- **Phần mã nguồn có sự hỗ trợ của AI**:
  - Cấu trúc dataclass trong `parsers/models.py`.
  - Biểu thức chính quy (Regex) và logic bóc tách trong `parsers/detector.py`, `parsers/application/http.py`, `parsers/application/smtp.py`.
  - Module thread-safe capture trong `capture/capturer.py`.
