# BÀI TẬP 1 & BÀI TẬP 2: PACKET CAPTURE & PARSER, DECODER, PREPROCESSOR, FLOW TRACKER CHO HỆ THỐNG IDS

> **Môn học**: NT204.R11.ANTN - An toàn mạng  
> **Sinh viên**: Trần Đình Nguyên  
> **MSSV**: 24521208  
> **Lớp**: NT204.R11.ANTN  
> **Giảng viên hướng dẫn**: Bộ môn Mạng máy tính & Truyền thông  
> **Repository**: `dwuyn/NT204.R11.ANTN_TranDinhNguyen_24521208`  

---

## 1. Giới thiệu Tổng quan

Dự án là module nền tảng đầu vào của một hệ thống phát hiện xâm nhập (**Intrusion Detection System - IDS**), được phát triển theo hai bài tập nối tiếp nhau:

**Bài tập 1 — Packet Capture & Parser**
- Thu thập lưu lượng mạng từ **card mạng (live capture)** hoặc từ **file PCAP**.
- Đưa gói tin qua **pipeline phân tích giao thức**: Network (IPv4) → Transport (TCP/UDP) → Application (HTTP/1.x, DNS, SMTP).
- Chuẩn hóa thành đối tượng **Normalized IDS Event** và xuất ra **JSON Lines (`.jsonl`)**.

**Bài tập 2 — Decoder, Preprocessor & Flow/Connection Tracker**
- **Decoder**: giải mã percent-encoding, `+`-as-space, HTML entity, MIME `base64`/`quoted-printable`, header RFC 2047 và character decoding (ASCII/UTF-8) **không bao giờ crash** khi gặp byte không hợp lệ.
- **Preprocessor**: kiểm tra tính hợp lệ (`valid`/`partial`/`invalid` + `reason`), chuẩn hóa protocol name, địa chỉ IP, tên header HTTP, `Host`, tên miền DNS, URI path; xử lý missing/unsupported field nhất quán theo cấu hình.
- **Flow/Connection Tracker**: gom packet thành **flow hai chiều theo 5-tuple**, giữ `flow_id` ổn định, theo dõi **máy trạng thái TCP** (`HANDSHAKE` → `ESTABLISHED` → `CLOSING` → `CLOSED`/`RESET`), timeout riêng cho TCP/UDP, thống kê chi tiết từng flow và ghi ra `flows.jsonl`.
- Toàn bộ **timeout, giới hạn kích thước decode, số flow tối đa và chính sách bỏ packet** đều **cấu hình được** qua file JSON và tham số CLI.

---

## 2. Kiến trúc Hệ thống & Pipeline Xử lý

Pipeline xử lý một gói tin gồm 8 tầng (5 tầng của Bài tập 1 và 3 tầng mới của Bài tập 2):

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
 [ App Protocol Detector ] (Signature Payload + Port Heuristics, MIME payload)
             │
             ▼
  [ App Protocol Parser ] (HTTP/1.x, DNS, SMTP - gồm SMTP DATA/MIME)
             │
             ▼
      [ Decoder ] (percent/URL, form-urlencoded, HTML entity, base64,
                   quoted-printable, RFC 2047, charset ASCII/UTF-8)
             │
             ▼
   [ Preprocessor ] (Validation valid/partial/invalid + Normalization)
             │
             ▼
 [ Flow/Connection Tracker ] (5-tuple 2 chiều, TCP state machine,
                              UDP timeout, per-flow statistics)
             │
             ├──► [ JSON Lines Logger ] ──► output.jsonl  (event + decode + preprocess + flow)
             └──► [ Flow Logger ]       ──► flows.jsonl   (1 dòng / flow khi đóng)
```

### Đặc điểm thiết kế:
- **Unified Pipeline**: Không tạo hai pipeline riêng cho Live traffic và PCAP import; cả hai nguồn đều streaming qua generator `CapturedPacket` vào cùng `IDSEngine`.
- **Deep Packet Inspection (DPI)**: Không phụ thuộc tuyệt đối vào cổng dịch vụ, nhận diện HTTP/SMTP/DNS/MIME trực tiếp từ byte payload (hỗ trợ non-standard port).
- **Zero-Crash Fault Tolerance**: Mỗi tầng đều bọc `try/except`; lỗi được ghi vào `decode.warnings` / `preprocess.warnings` / `errors` và chương trình **không bao giờ dừng** vì một gói tin lỗi.
- **Deterministic Replay**: Đồng hồ của Flow Tracker lấy từ **timestamp của packet** (không dùng wall-clock), do đó chạy lại cùng một file PCAP luôn cho kết quả giống nhau (bao gồm cả các test case timeout).
- **Config-driven**: Timeout TCP/UDP, `max_decode_size`, `max_active_flows`, `drop_invalid`, `exclude_unknown`… đều có trong file cấu hình JSON và có thể override bằng CLI.

---

## 3. Cấu trúc Thư mục

```text
NT204.R11.ANTN_TranDinhNguyen_24521208/
├── .gitignore                      # Cấu hình bỏ qua file cache và artifact output mặc định
├── README.md                       # Tài liệu hướng dẫn & AI disclosure
├── requirements.txt                # Thư viện Python cần thiết (scapy)
├── config.py                       # Cấu hình decoder/preprocessor/flow/pipeline (JSON + CLI)
├── main.py                         # CLI entrypoint của chương trình IDS
├── capture/
│   ├── __init__.py
│   └── capturer.py                 # Module thu thập packet (PCAP & Live sniff)
├── parsers/
│   ├── __init__.py
│   ├── models.py                   # Dataclass NormalizedEvent + DecodeInfo/PreprocessInfo/FlowRef
│   ├── network.py                  # Module parse IPv4
│   ├── transport.py                # Module parse TCP (handshake/flags) & UDP
│   ├── detector.py                 # Module nhận diện Layer 7 (DPI, port, MIME payload)
│   └── application/
│       ├── __init__.py
│       ├── http.py                 # Parser HTTP/1.x (GET/POST có body, Response)
│       ├── dns.py                  # Parser DNS (Query domain/type, Answers)
│       └── smtp.py                 # Parser SMTP (Commands, Status codes, DATA/MIME)
├── decoder/
│   ├── __init__.py
│   └── decoder.py                  # Decoder: percent/URL, form, HTML entity, MIME, charset
├── preprocessor/
│   ├── __init__.py
│   └── preprocessor.py             # Validation + normalization của event
├── flow/
│   ├── __init__.py
│   ├── models.py                   # Flow/FlowCounters + state & close-reason constants
│   └── tracker.py                  # FlowTracker: 5-tuple, TCP state machine, timeout
├── pipeline/
│   ├── __init__.py
│   ├── pipeline.py                 # ParsingPipeline: parse() -> (event, raw_payload)
│   └── engine.py                   # IDSEngine: parse -> decode -> preprocess -> flow
├── storage/
│   ├── __init__.py
│   └── logger.py                   # Ghi log JSON Lines (event và flow record)
├── tests/                          # Bộ unit tests tự động
│   ├── generate_test_pcaps.py      # Sinh PCAP cho 14 test case Bài tập 1
│   ├── generate_bt2_test_pcaps.py  # Sinh PCAP cho 14 test case Bài tập 2 (timestamp cố định)
│   ├── run_case.py                 # Runner: event + flow assertions, mode `all`
│   ├── test_models.py
│   ├── test_capturer.py
│   ├── test_network_parser.py
│   ├── test_transport_parser.py
│   ├── test_detector.py
│   ├── test_http_parser.py
│   ├── test_dns_parser.py
│   ├── test_smtp_parser.py
│   ├── test_pipeline.py
│   ├── test_config.py              # Unit test module cấu hình
│   ├── test_decoder.py             # Unit test decoder (percent/form/HTML/MIME/charset)
│   ├── test_preprocessor.py        # Unit test validation & normalization
│   ├── test_flow_tracker.py        # Unit test flow tracker (state, timeout, thống kê)
│   └── test_engine.py              # Unit test tích hợp toàn pipeline
└── TEST/                           # Thư mục chứa test cases của cả hai bài tập
    ├── test_01_tcp_handshake/      # BT1 - Test TCP Handshake (SYN, SYN-ACK, ACK)
    ├── ...                         # BT1 - test_02 ... test_14
    ├── test_14_truncated_pcap/     # BT1 - file PCAP bị cắt cụt
    ├── bt2_t01_http_url_decode/    # BT2 - Decoder: percent-encoding trên URI
    ├── bt2_t02_html_entity/        # BT2 - Decoder: HTML entity
    ├── bt2_t03_smtp_mime/          # BT2 - Decoder: MIME base64 / quoted-printable / RFC 2047
    ├── bt2_t04_invalid_bytes/      # BT2 - Decoder: byte không hợp lệ UTF-8
    ├── bt2_t05_normalization/      # BT2 - Preprocessor: chuẩn hóa header/Host/URI/domain
    ├── bt2_t06_missing_field/      # BT2 - Preprocessor: thiếu tầng mạng / protocol lạ
    ├── bt2_t07_tcp_handshake/      # BT2 - Flow: bắt tay TCP
    ├── bt2_t08_bidirectional/      # BT2 - Flow: một flow hai chiều
    ├── bt2_t09_tcp_close/          # BT2 - Flow: đóng bằng FIN và bằng RST
    ├── bt2_t10_udp_dns/            # BT2 - Flow: UDP DNS query/response
    ├── bt2_t11_concurrent_flows/   # BT2 - Flow: nhiều flow đồng thời
    ├── bt2_t12_idle_timeout/       # BT2 - Flow: idle timeout cấu hình được
    ├── bt2_t13_statistics/         # BT2 - Flow: thống kê chi tiết
    └── bt2_t14_malformed_event/    # BT2 - Event lỗi + PCAP cắt cụt
```

Mỗi thư mục test case chứa: `test.pcap` (hoặc `truncated.pcap`), `output.jsonl`, `flows.jsonl` (với case Bài tập 2) và `report.md` mô tả kết quả kiểm thử.

---

## 4. Hướng dẫn Cài đặt & Sử dụng

### 4.1. Môi trường yêu cầu
- **Hệ điều hành**: Linux (Ubuntu, Debian, Fedora, Arch Linux, v.v.)
- **Python**: Phiên bản `>= 3.10` (đã kiểm thử với Python 3.14)
- **Thư viện yêu cầu**: `scapy >= 2.5.0` (`pip install -r requirements.txt`)

### 4.2. Tham số dòng lệnh (`main.py`)

| Tham số | Mô tả | Mặc định |
|:---|:---|:---|
| `--interface`, `-i` | Interface để bắt live packet (loại trừ với `--pcap`) | — |
| `--pcap`, `-p` | Đường dẫn file PCAP/PCAPNG cần phân tích | — |
| `--output`, `-o` | File JSON Lines chứa normalized events | `output.jsonl` |
| `--flows-output` | File JSON Lines chứa flow records | `flows.jsonl` |
| `--config` | File cấu hình JSON (xem mục 4.3) | — |
| `--count`, `-c` | Số packet tối đa cần xử lý | không giới hạn |
| `--bpf` | Biểu thức lọc BPF (chỉ dùng với live capture) | — |
| `--tcp-timeout` | Idle timeout của flow TCP (giây) | `120` |
| `--udp-timeout` | Idle timeout của flow UDP (giây) | `30` |
| `--max-active-flows` | Số flow theo dõi đồng thời tối đa | `10000` |
| `--max-decode-size` | Giới hạn kích thước payload được decode (byte) | `1048576` |
| `--drop-invalid` | Loại bỏ (không forward) event bị preprocessor đánh `invalid` | tắt |
| `--exclude-unknown` | Không xuất event cho packet có protocol ứng dụng không xác định | tắt |
| `--quiet`, `-q` | Tắt tóm tắt từng packet trên console | tắt |

### 4.3. File cấu hình JSON

Thứ tự ưu tiên: **giá trị mặc định < file `--config` < tham số CLI**. Key lạ hoặc sai kiểu dữ liệu sẽ báo lỗi và thoát với mã 2.

```json
{
  "decoder": {
    "max_decode_size": 1048576,
    "decode_html_entities": true,
    "decode_form_urlencoded": true,
    "decode_mime": true
  },
  "preprocessor": {
    "drop_invalid": false,
    "normalize_headers": true,
    "normalize_domains": true,
    "normalize_uri": true
  },
  "flow": {
    "tcp_idle_timeout": 120.0,
    "udp_idle_timeout": 30.0,
    "max_active_flows": 10000,
    "flush_on_eof": true
  },
  "pipeline": {
    "include_unknown": true
  }
}
```

### 4.4. Ví dụ sử dụng

```bash
# A. Phân tích file PCAP (ghi event + flow record)
python3 main.py --pcap TEST/bt2_t13_statistics/test.pcap \
                --output output.jsonl --flows-output flows.jsonl

# B. Bật cấu hình từ file JSON và override timeout bằng CLI
python3 main.py --pcap traffic.pcap --config config.json --tcp-timeout 5

# C. Loại bỏ event invalid và không xuất giao thức lạ
python3 main.py --pcap traffic.pcap --drop-invalid --exclude-unknown --quiet

# D. Giới hạn decode payload lớn (payload vượt ngưỡng sẽ có decode_status = "skipped")
python3 main.py --pcap traffic.pcap --max-decode-size 1024

# E. Thu thập trực tiếp từ card mạng (cần quyền root)
sudo python3 main.py --interface eth0 --count 100 --bpf "tcp or udp" --output live.jsonl
```

### 4.5. Chạy kiểm thử

```bash
# Unit tests toàn bộ module
python3 -m unittest discover -v tests

# Sinh dữ liệu PCAP cho Bài tập 2 (14 case, timestamp cố định)
python3 tests/generate_bt2_test_pcaps.py

# Chạy toàn bộ test case Bài tập 2 và sinh report
python3 tests/run_case.py all

# Chạy một test case riêng (Bài tập 1 hoặc Bài tập 2)
python3 tests/run_case.py bt2_t07_tcp_handshake "<mục tiêu>" "<tiêu chí kiểm thử>"
```

---

## 5. Đặc tả Cấu trúc Output Chuẩn hóa

### 5.1. Normalized Event (`output.jsonl`)

Mỗi dòng là một event JSON. Ba section `decode`, `preprocess`, `flow` là phần mở rộng của Bài tập 2; mọi key của Bài tập 1 được giữ nguyên.

```json
{
  "packet_id": 1,
  "timestamp": 1700000000.0,
  "timestamp_iso": "2023-11-14T22:13:20+00:00",
  "raw_len": 84,
  "network": {
    "layer": "IPv4",
    "src_ip": "10.0.0.10",
    "dst_ip": "10.0.0.20",
    "proto": "TCP",
    "ttl": 64,
    "id": 1234,
    "ihl": 5,
    "tos": 0,
    "total_len": 60,
    "flags": []
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
      "uri": "/search?q=%27%20OR%201%3D1",
      "uri_normalized": "/search?q=' OR 1=1",
      "version": "HTTP/1.1",
      "headers": {
        "Host": "ids.security.lab",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "41"
      },
      "body": "username=admin&password=a%20b",
      "detection_method": "payload_signature"
    }
  },
  "decode": {
    "decode_status": "decoded",
    "decoders": ["percent_url", "form_urlencoded"],
    "fields": {
      "uri_decoded": "/search?q=' OR 1=1",
      "body_decoded": "username=admin&password=a b",
      "form_fields": {"username": "admin", "password": "a b"},
      "body_charset": "utf-8",
      "body_decode_status": "ok"
    },
    "warnings": []
  },
  "preprocess": {
    "preprocess_status": "valid",
    "processing_action": "forward",
    "reason": null,
    "normalizations": ["http_header_names", "host_header", "uri_path"],
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
```

- `decode`, `preprocess`, `flow` bằng `null` khi event được tạo bằng API Bài tập 1 (không qua engine) hoặc khi event bị `processing_action = "dropped"` / không có tầng transport.
- `errors` **chỉ** chứa lỗi tầng parse (như Bài tập 1). Warning của decoder/preprocessor nằm trong `decode.warnings` / `preprocess.warnings`.

### 5.2. Literal của Decoder

- `decode_status` (ưu tiên giảm dần: `error` > `partial` > `decoded` > `skipped` > `unchanged`):
  - `decoded` — có ít nhất một decoder thực sự biến đổi dữ liệu.
  - `partial` — gặp byte sequence không hợp lệ UTF-8 (đã thay thế, không crash).
  - `skipped` — payload vượt `max_decode_size`.
  - `unchanged` — không có dữ liệu cần giải mã.
  - `error` — có exception khi decode (đã bắt, pipeline tiếp tục).
- `decoders` (theo thứ tự áp dụng): `percent_url`, `form_urlencoded`, `html_entities`, `base64`, `quoted_printable`, `rfc2047`.
- `fields`: `uri_decoded`, `body_decoded`, `body_charset`, `body_decode_status`, `form_fields`, `content_transfer_encoding`, `mime_body_decoded`, `mime_charset`, `headers_decoded`.
- `warnings`: `invalid_utf8_sequence`, `payload_too_large`, `binary_body_not_decoded`, `base64_decode_error`, `quoted_printable_decode_error`, `rfc2047_decode_error`, `unknown_charset`, `duplicate_form_field`, `decode_exception`.

### 5.3. Literal của Preprocessor

- `preprocess_status`: `valid` | `partial` | `invalid`; `processing_action`: `forward` | `dropped`.
- `reason` (matching theo thứ tự, rule đầu tiên khớp được chọn):

| # | `reason` | Trạng thái | Điều kiện |
|:--:|:---|:---:|:---|
| 1 | `invalid_timestamp` | invalid | `timestamp` không phải số hoặc ≤ 0 |
| 2 | `invalid_ip_address` | invalid | `src_ip`/`dst_ip` rỗng hoặc không parse được |
| 3 | `missing_network_layer` | invalid | không có tầng network (ví dụ packet ARP) |
| 4 | `invalid_port` | invalid | port ngoài `0..65535` hoặc không phải số nguyên |
| 5 | `missing_transport_layer` | partial | không có tầng transport |
| 6 | `unsupported_transport_protocol` | partial | transport không phải TCP/UDP |
| 7 | `no_application_layer` | partial | không có tầng application |
| 8 | `unsupported_protocol` | partial | application protocol là `UNKNOWN` |
| 9 | `timestamp_in_future` | partial | `timestamp > now + 86400` |

  Không khớp rule nào ⇒ `valid` và `reason = null`. Các rule khớp thêm được ghi vào `warnings`.
- `normalizations` (chỉ ghi khi giá trị thực sự đổi): `protocol_name`, `ip_address`, `http_header_names`, `domain_lowercase`, `host_header`, `uri_path`.
- `processing_action = "dropped"` chỉ khi bật cấu hình `drop_invalid` **và** `preprocess_status == "invalid"`.

### 5.4. Flow Record (`flows.jsonl`)

Mỗi flow được ghi **một dòng** khi đóng (FIN/RST/timeout/overflow) hoặc khi kết thúc capture (`end_of_capture`):

```json
{
  "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
  "flow_seq": 1,
  "protocol": "TCP",
  "application_protocol": "HTTP",
  "endpoint_a": {"ip": "10.0.0.10", "port": 52000},
  "endpoint_b": {"ip": "10.0.0.20", "port": 80},
  "state": "ESTABLISHED",
  "start_time": 1700000000.0,
  "last_seen": 1700000000.2,
  "duration": 0.2,
  "packet_count": 3,
  "byte_count": 216,
  "forward": {"packet_count": 2, "byte_count": 144},
  "backward": {"packet_count": 1, "byte_count": 72},
  "syn_count": 2,
  "ack_count": 2,
  "fin_count": 0,
  "rst_count": 0,
  "closed": true,
  "close_reason": "fin"
}
```

Quy ước:

- **`flow_id`** = `"<PROTOCOL>-<A_ip>:<A_port>-<B_ip>:<B_port>"`, trong đó **A là endpoint nguồn của packet đầu tiên** tạo flow (bên khởi tạo). Packet đi A→B có `direction = "forward"`, packet đi B→A có `direction = "backward"` (flow là **hai chiều**, hai chiều dùng chung một record).
- **`flow_seq`** là số thứ tự tạo flow (1-based). Nếu cùng một 5-tuple được dùng lại sau khi flow cũ đã đóng (ví dụ DNS client giữ nguyên source port), `flow_id` sẽ trùng nhau nhưng `flow_seq` khác nhau để phân biệt các instance.
- **`state`**: với TCP là `NEW`, `HANDSHAKE`, `ESTABLISHED`, `CLOSING`, `CLOSED`, `RESET`; với UDP luôn là `ESTABLISHED` ngay từ packet đầu vì UDP không có handshake để quan sát.
- **`close_reason`**: `fin` (đã thấy FIN từ cả hai phía), `rst`, `timeout` (vượt idle timeout), `overflow` (bị loại để giải phóng bảng flow khi vượt `max_active_flows`), `end_of_capture` (flush khi kết thúc capture).
- **Đếm cờ theo bit**: packet SYN-ACK được tính vào **cả** `syn_count` và `ack_count`; `fin_count`/`rst_count` đếm số packet mang cờ tương ứng. UDP luôn có các counter này bằng 0.
- **Timeout chỉ được đánh dấu khi quan sát được độ trễ**: tracker lấy timestamp của **packet** làm đồng hồ. Vì vậy flow chỉ được đóng với `close_reason = "timeout"` khi có một packet đến trễ hơn timeout (hoặc khi đã idle quá timeout tại thời điểm `finalize()`); nếu capture kết thúc trước khi timeout trôi qua, flow còn lại được ghi `end_of_capture`. Đây là chủ đích thiết kế để replay PCAP cho kết quả tất định.
- **Thống kê**: `byte_count` = tổng `raw_len` của các packet thuộc flow, chia theo hai chiều `forward`/`backward`; `duration = round(last_seen - start_time, 6)`; timestamp được làm tròn 6 chữ số thập phân.

---

## 6. Kết quả Bài tập 1 — 14 Test Cases

| STT | Tên Test Case | Mục tiêu kiểm thử | Trạng thái | Thư mục |
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
| 12 | **Malformed Packet** | Xử lý an toàn không crash khi gặp packet hỏng | **PASS** | `TEST/test_12_malformed_packet/` |
| 13 | **Non-standard Port** (bổ sung) | Nhận diện HTTP/SMTP/DNS trên port phi tiêu chuẩn | **PASS** | `TEST/test_13_non_standard_port/` |
| 14 | **Truncated PCAP** (bổ sung) | Không crash khi file PCAP bị cắt cụt | **PASS** | `TEST/test_14_truncated_pcap/` |

---

## 7. Kết quả Bài tập 2 — 14 Test Cases (T01–T14)

```bash
python3 tests/generate_bt2_test_pcaps.py   # sinh PCAP (timestamp cố định)
python3 tests/run_case.py all              # chạy và sinh report cho cả 14 case
```

| Case | Tên Test Case | Mục tiêu kiểm thử | Kết quả chính | Trạng thái | Thư mục |
|:---:|:---|:---|:---|:---:|:---|
| T01 | **HTTP URL Decode** | Percent-encoding trên URI | `uri_decoded = "/search?q=' OR 1=1&lang=en"`, URI gốc giữ nguyên, 1 flow | **PASS** | `TEST/bt2_t01_http_url_decode/` |
| T02 | **HTML Entity** | Giải mã entity trong body `text/html` | `body_decoded = "<p>Hello <script>alert(1)</script> & welcome</p>"`, charset `utf-8` | **PASS** | `TEST/bt2_t02_html_entity/` |
| T03 | **SMTP MIME** | base64, quoted-printable, RFC 2047 | `"Hello World! This is a base64 message."`, `"Hệ thống IDS đang hoạt động."`, `Subject = "Tái khoan"`, 1 flow SMTP | **PASS** | `TEST/bt2_t03_smtp_mime/` |
| T04 | **Invalid Bytes** | Byte không hợp lệ UTF-8 | `decode_status = "partial"`, warning `invalid_utf8_sequence`, payload lạ `UNKNOWN` | **PASS** | `TEST/bt2_t04_invalid_bytes/` |
| T05 | **Normalization** | Header, Host, URI path, domain | `Content-Type`, `Host = "ids.security.lab:8080"`, `uri_normalized = "/admin/secret?q=/"`, `portal.uit.edu.vn`, 2 flow | **PASS** | `TEST/bt2_t05_normalization/` |
| T06 | **Missing Field** | Thiếu tầng mạng / protocol lạ | ARP ⇒ `invalid/missing_network_layer`, `flow = null`; UDP lạ ⇒ `partial/unsupported_protocol`, 1 flow | **PASS** | `TEST/bt2_t06_missing_field/` |
| T07 | **TCP Handshake** | Flow qua 3 bước bắt tay | 1 flow `HANDSHAKE → ESTABLISHED`, `syn_count = 2`, `ack_count = 2`, fwd/bwd `2/1` | **PASS** | `TEST/bt2_t07_tcp_handshake/` |
| T08 | **Bidirectional** | Request/response hai chiều | 1 flow, `direction` `forward`/`backward`, mỗi chiều 1 packet, app `HTTP` | **PASS** | `TEST/bt2_t08_bidirectional/` |
| T09 | **TCP Close** | Đóng bằng FIN hai chiều và RST | Flow 1 `CLOSED`/`fin` (`fin_count = 2`), flow 2 `RESET`/`rst` | **PASS** | `TEST/bt2_t09_tcp_close/` |
| T10 | **UDP DNS Flow** | Flow UDP cho DNS query/response | 1 flow `UDP` `ESTABLISHED`, 2 packet / 159 byte, app `DNS`, `syn_count = 0` | **PASS** | `TEST/bt2_t10_udp_dns/` |
| T11 | **Concurrent Flows** | Ba flow xen kẽ | 3 flow record riêng biệt, mỗi flow 2 packet | **PASS** | `TEST/bt2_t11_concurrent_flows/` |
| T12 | **Idle Timeout** | Timeout cấu hình được (`--tcp-timeout 5`) | Flow im lặng 29.99s ⇒ `close_reason = "timeout"`; flow mới ⇒ `end_of_capture` | **PASS** | `TEST/bt2_t12_idle_timeout/` |
| T13 | **Flow Statistics** | Thống kê chi tiết một flow | 8 packet, 392 byte (192 xuôi + 200 ngược), `duration = 0.7`, `syn/ack/fin = 2/7/2`, `CLOSED`/`fin` | **PASS** | `TEST/bt2_t13_statistics/` |
| T14 | **Malformed Event** | Event lỗi + PCAP cắt cụt | TCP không payload ⇒ `partial/no_application_layer`; IP `PROTO_0` ⇒ `partial/missing_transport_layer` | **PASS** | `TEST/bt2_t14_malformed_event/` |

---

## 8. AI Disclosure

- **Công cụ AI sử dụng**: Antigravity (Gemini 3.8 flash)
- **Mục đích sử dụng**:
  - Hỗ trợ xây dựng kế hoạch phân rã tính năng (task breakdown) theo phương pháp luận kỹ thuật phần mềm.
  - Hỗ trợ thiết kế kiến trúc pipeline 8 tầng (`capture/`, `parsers/`, `decoder/`, `preprocessor/`, `flow/`, `pipeline/`, `storage/`, `config.py`).
  - Hỗ trợ tạo bộ dữ liệu test case mẫu chuẩn bằng Scapy cho 14 kịch bản Bài tập 1 và 14 kịch bản Bài tập 2 (timestamp cố định để kiểm thử timeout/thống kê tất định).
  - Hỗ trợ rà soát (review) logic máy trạng thái TCP, quy tắc chuẩn hóa URI/header và các literal `decode_status`/`reason`/`close_reason` cho khớp đặc tả đề bài.
- **Phần mã nguồn có sự hỗ trợ của AI**:
  - Cấu trúc dataclass trong `parsers/models.py`, `flow/models.py` và module cấu hình `config.py`.
  - Biểu thức chính quy (Regex) và logic bóc tách trong `parsers/detector.py`, `parsers/application/http.py`, `parsers/application/dns.py`, `parsers/application/smtp.py`.
  - Logic giải mã trong `decoder/decoder.py` và logic kiểm tra/chuẩn hóa trong `preprocessor/preprocessor.py`.
  - Máy trạng thái TCP, timeout và thống kê trong `flow/tracker.py`.
  - Phần tích hợp `pipeline/engine.py`, các tham số CLI mới trong `main.py` và script sinh dữ liệu `tests/generate_bt2_test_pcaps.py`.
