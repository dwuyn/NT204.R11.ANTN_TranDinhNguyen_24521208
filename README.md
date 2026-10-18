# BÀI TẬP 1, 2 & 3: PACKET CAPTURE & PARSER, DECODER, PREPROCESSOR, FLOW TRACKER VÀ CORE ENGINE IDS

> **Môn học**: NT204.R11.ANTN - An toàn mạng  
> **Sinh viên**: Trần Đình Nguyên  
> **MSSV**: 24521208  
> **Lớp**: NT204.R11.ANTN  
> **Giảng viên hướng dẫn**: Bộ môn Mạng máy tính & Truyền thông  
> **Repository**: `dwuyn/NT204.R11.ANTN_TranDinhNguyen_24521208`  

---

## 1. Giới thiệu Tổng quan

Dự án là module nền tảng đầu vào của một hệ thống phát hiện xâm nhập (**Intrusion Detection System - IDS**), được phát triển theo ba bài tập nối tiếp nhau:

**Bài tập 1 — Packet Capture & Parser**
- Thu thập lưu lượng mạng từ **card mạng (live capture)** hoặc từ **file PCAP**.
- Đưa gói tin qua **pipeline phân tích giao thức**: Network (IPv4) → Transport (TCP/UDP) → Application (HTTP/1.x, DNS, SMTP).
- Chuẩn hóa thành đối tượng **Normalized IDS Event** và xuất ra **JSON Lines (`.jsonl`)**.

**Bài tập 2 — Decoder, Preprocessor & Flow/Connection Tracker**
- **Decoder**: giải mã percent-encoding, `+`-as-space, HTML entity, MIME `base64`/`quoted-printable`, header RFC 2047 và character decoding (ASCII/UTF-8) **không bao giờ crash** khi gặp byte không hợp lệ.
- **Preprocessor**: kiểm tra tính hợp lệ (`valid`/`partial`/`invalid` + `reason`), chuẩn hóa protocol name, địa chỉ IP, tên header HTTP, `Host`, tên miền DNS, URI path; xử lý missing/unsupported field nhất quán theo cấu hình.
- **Flow/Connection Tracker**: gom packet thành **flow hai chiều theo 5-tuple**, giữ `flow_id` ổn định, theo dõi **máy trạng thái TCP** (`HANDSHAKE` → `ESTABLISHED` → `CLOSING` → `CLOSED`/`RESET`), timeout riêng cho TCP/UDP, thống kê chi tiết từng flow và ghi ra `flows.jsonl`.
- Toàn bộ **timeout, giới hạn kích thước decode, số flow tối đa và chính sách bỏ packet** đều **cấu hình được** qua file JSON và tham số CLI.

**Bài tập 3 — Core Engine & Snort Rule Matching**
- **Rule Loader**: nạp một hoặc nhiều file `.rules`, bỏ qua comment/dòng trống, enable/disable rule theo `sid` hoặc theo file qua cấu hình; lỗi của một rule **không** làm dừng việc nạp.
- **Rule Parser & Validator**: parse rule Snort (subset) thành **Internal Rule Object**; phân loại rõ ràng `valid` / `invalid` (sai cú pháp) / `unsupported` (ngoài phạm vi) kèm lý do.
- **Rule Repository/Indexer**: đánh index rule theo protocol + IP/port hai vế để **chỉ gọi matcher trên candidate rules** thay vì quét toàn bộ ruleset.
- **Matching Engine**: so khớp header (IP/port/chiều), flow state, `flags`, `dsize` và `content` (nocase, offset/depth, distance/within) trên **raw payload byte-exact**.
- **Rule Evaluation + Detection Event**: mặc định **không dừng ở match đầu tiên** (multi-match), sinh **Detection Event** đầy đủ trường và ghi ra `detections.jsonl`.

---

## 2. Kiến trúc Hệ thống & Pipeline Xử lý

Pipeline xử lý một gói tin gồm 9 tầng (5 tầng của Bài tập 1, 3 tầng mới của Bài tập 2 và tầng Rule Evaluation của Bài tập 3):

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
             ▼
 [ Rule Evaluation ] (Rule Indexer → Candidate Prefilter → Matcher:
                      header, flow, flags, dsize, content(nocase/offset/
                      depth/distance/within), multi-match)
             │
             ├──► [ JSON Lines Logger ] ──► output.jsonl      (event + decode + preprocess + flow)
             ├──► [ Flow Logger ]       ──► flows.jsonl       (1 dòng / flow khi đóng)
             └──► [ Detection Logger ]  ──► detections.jsonl  (1 dòng / detection event, khi có rules)
```

### Đặc điểm thiết kế:
- **Unified Pipeline**: Không tạo hai pipeline riêng cho Live traffic và PCAP import; cả hai nguồn đều streaming qua generator `CapturedPacket` vào cùng `IDSEngine`.
- **Deep Packet Inspection (DPI)**: Không phụ thuộc tuyệt đối vào cổng dịch vụ, nhận diện HTTP/SMTP/DNS/MIME trực tiếp từ byte payload (hỗ trợ non-standard port).
- **Zero-Crash Fault Tolerance**: Mỗi tầng đều bọc `try/except`; lỗi được ghi vào `decode.warnings` / `preprocess.warnings` / `errors` và chương trình **không bao giờ dừng** vì một gói tin lỗi.
- **Deterministic Replay**: Đồng hồ của Flow Tracker lấy từ **timestamp của packet** (không dùng wall-clock), do đó chạy lại cùng một file PCAP luôn cho kết quả giống nhau (bao gồm cả các test case timeout).
- **Config-driven**: Timeout TCP/UDP, `max_decode_size`, `max_active_flows`, `drop_invalid`, `exclude_unknown`… đều có trong file cấu hình JSON và có thể override bằng CLI.
- **Rule Evaluation không xâm phạm hành vi cũ**: khi không nạp rules (không truyền `--rules` và không cấu hình `rules.rules_files`), tầng Rule Evaluation bị tắt hoàn toàn — output của Bài tập 1/2 giữ nguyên tuyệt đối.

---

## 3. Cấu trúc Thư mục

```text
NT204.R11.ANTN_TranDinhNguyen_24521208/
├── .gitignore                      # Cấu hình bỏ qua file cache và artifact output mặc định
├── README.md                       # Tài liệu hướng dẫn & AI disclosure
├── requirements.txt                # Thư viện Python cần thiết (scapy)
├── config.py                       # Cấu hình decoder/preprocessor/flow/pipeline/rules (JSON + CLI)
├── main.py                         # CLI entrypoint của chương trình IDS
├── local.rules                     # Ruleset mẫu (Snort subset) cho Bài tập 3
├── capture/
│   ├── __init__.py
│   └── capturer.py                 # Module thu thập packet (PCAP & Live sniff)
├── core/                           # Core Engine - Bài tập 3
│   ├── __init__.py
│   ├── models.py                   # Rule, RuleOption, ContentPattern, LoadResult...
│   ├── parser.py                   # Parser + validator rule Snort (valid/invalid/unsupported)
│   ├── loader.py                   # RuleLoader: nạp nhiều file, enable/disable theo sid/file
│   ├── indexer.py                  # RuleRepository: index protocol + IP/port 2 vế, candidate lookup
│   ├── matcher.py                  # Matcher: header/flow/flags/dsize/content
│   ├── detection.py                # DetectionEvent + sinh event từ match
│   └── evaluator.py                # RuleEvaluator: điều phối indexer + matcher, multi-match
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
│   ├── generate_bt3_test_pcaps.py  # Sinh rules + PCAP cho 14 test case Bài tập 3
│   ├── rule_case.py                # Runner cho case rules-only (loader/parser/indexer)
│   ├── run_case.py                 # Runner: event + flow + detection assertions, mode `all`
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
│   ├── test_engine.py              # Unit test tích hợp toàn pipeline
│   ├── test_rule_models.py         # Unit test dataclass rule (Bài tập 3)
│   ├── test_rule_parser.py         # Unit test parser + validator rule
│   ├── test_rule_loader.py         # Unit test loader (enable/disable, file lỗi)
│   ├── test_rule_indexer.py        # Unit test index + candidate lookup
│   ├── test_rule_matcher.py        # Unit test matcher (header/flow/flags/dsize/content)
│   ├── test_detection.py           # Unit test DetectionEvent
│   └── test_rule_evaluator.py      # Unit test evaluator (multi-match, stop_on_first_match)
└── TEST/                           # Thư mục chứa test cases, chia theo từng bài tập
    ├── BT1/                        # BT1 - Packet Capture & Parser (test_01 ... test_14)
    │   ├── test_01_tcp_handshake/  # BT1 - TCP Handshake (SYN, SYN-ACK, ACK)
    │   ├── ...                     # BT1 - test_02 ... test_13
    │   └── test_14_truncated_pcap/ # BT1 - file PCAP bị cắt cụt
    ├── BT2/                        # BT2 - Decoder, Preprocessor, Flow Tracker
    │   ├── bt2_t01_http_url_decode/    # Decoder: percent-encoding trên URI
    │   ├── bt2_t02_html_entity/        # Decoder: HTML entity
    │   ├── bt2_t03_smtp_mime/          # Decoder: MIME base64 / quoted-printable / RFC 2047
    │   ├── bt2_t04_invalid_bytes/      # Decoder: byte không hợp lệ UTF-8
    │   ├── bt2_t05_normalization/      # Preprocessor: chuẩn hóa header/Host/URI/domain
    │   ├── bt2_t06_missing_field/      # Preprocessor: thiếu tầng mạng / protocol lạ
    │   ├── bt2_t07_tcp_handshake/      # Flow: bắt tay TCP
    │   ├── bt2_t08_bidirectional/      # Flow: một flow hai chiều
    │   ├── bt2_t09_tcp_close/          # Flow: đóng bằng FIN và bằng RST
    │   ├── bt2_t10_udp_dns/            # Flow: UDP DNS query/response
    │   ├── bt2_t11_concurrent_flows/   # Flow: nhiều flow đồng thời
    │   ├── bt2_t12_idle_timeout/       # Flow: idle timeout cấu hình được
    │   ├── bt2_t13_statistics/         # Flow: thống kê chi tiết
    │   └── bt2_t14_malformed_event/    # Event lỗi + PCAP cắt cụt
    └── BT3/                        # BT3 - Core Engine & Snort Rule Matching
        ├── t01_rule_loader/        # BT3 - T01: nạp nhiều file rules, bỏ comment, warning
        ├── t02_invalid_rule/       # BT3 - T02: rule sai cú pháp → invalid + lý do
        ├── t03_unsupported_keyword/# BT3 - T03: keyword/action/protocol ngoài phạm vi → unsupported
        ├── t04_header_parse/       # BT3 - T04: parse header (CIDR, port range, <>)
        ├── t05_direction/          # BT3 - T05: to_server / to_client
        ├── t06_indexer_candidates/ # BT3 - T06: candidate rules theo index
        ├── t07_header_prefilter/   # BT3 - T07: cùng content khác header → chỉ 1 rule khớp
        ├── t08_flow_state/         # BT3 - T08: established / not_established
        ├── t09_content_nocase/     # BT3 - T09: content nocase
        ├── t10_offset_depth/       # BT3 - T10: offset / depth
        ├── t11_distance_within/    # BT3 - T11: distance / within
        ├── t12_flags_dsize/        # BT3 - T12: flags + dsize
        ├── t13_multi_rule_match/   # BT3 - T13: nhiều rule cùng khớp 1 packet
        └── t14_detection_event/    # BT3 - T14: Detection Event đầy đủ trường
```

Mỗi thư mục test case chứa: `test.pcap` (hoặc `truncated.pcap`), `output.jsonl`, `flows.jsonl` (với case Bài tập 2) và `report.md` mô tả kết quả kiểm thử. Riêng case Bài tập 3 còn có `test.rules` (ruleset của case), `detections.jsonl` (case engine) hoặc `result.json` (case rules-only: loader/parser/indexer).

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
| `--rules` | File rules Snort (lặp lại nhiều lần để nạp nhiều file; **thay thế** `rules.rules_files` trong config) | — |
| `--detections-output` | File JSON Lines chứa detection events (chỉ ghi khi có rules được nạp) | `detections.jsonl` |
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
  },
  "rules": {
    "rules_files": ["local.rules"],
    "disabled_sids": [],
    "disabled_files": [],
    "stop_on_first_match": false
  }
}
```

- `rules.rules_files`: danh sách file rules nạp khi khởi động (đường dẫn tương đối tính từ thư mục chạy). CLI `--rules` **thay thế** danh sách này (không gộp).
- `rules.disabled_sids` / `rules.disabled_files`: loại rule theo `sid` hoặc theo tên file.
- `rules.stop_on_first_match`: `false` (mặc định) = một packet có thể khớp **nhiều rule** và sinh nhiều detection; `true` = dừng ở match đầu tiên.

### 4.4. Ví dụ sử dụng

```bash
# A. Phân tích file PCAP (ghi event + flow record)
python3 main.py --pcap TEST/BT2/bt2_t13_statistics/test.pcap \
                --output output.jsonl --flows-output flows.jsonl

# B. Bật cấu hình từ file JSON và override timeout bằng CLI
python3 main.py --pcap traffic.pcap --config config.json --tcp-timeout 5

# C. Loại bỏ event invalid và không xuất giao thức lạ
python3 main.py --pcap traffic.pcap --drop-invalid --exclude-unknown --quiet

# D. Giới hạn decode payload lớn (payload vượt ngưỡng sẽ có decode_status = "skipped")
python3 main.py --pcap traffic.pcap --max-decode-size 1024

# E. Thu thập trực tiếp từ card mạng (cần quyền root)
sudo python3 main.py --interface eth0 --count 100 --bpf "tcp or udp" --output live.jsonl

# F. Phân tích PCAP kèm phát hiện theo rules Snort (ghi detection events)
python3 main.py --pcap TEST/BT3/t13_multi_rule_match/test.pcap \
                --rules TEST/BT3/t13_multi_rule_match/test.rules \
                --detections-output detections.jsonl

# G. Nạp nhiều ruleset + tắt một số rule theo sid
python3 main.py --pcap traffic.pcap --rules rules/emerging.rules --rules local.rules \
                --config config.json   # config có "rules": {"disabled_sids": [1100002]}
```

### 4.5. Chạy kiểm thử

```bash
# Unit tests toàn bộ module
python3 -m unittest discover -v tests

# Sinh dữ liệu PCAP cho Bài tập 2 (14 case, timestamp cố định)
python3 tests/generate_bt2_test_pcaps.py

# Sinh rules + PCAP cho Bài tập 3 (14 case)
python3 tests/generate_bt3_test_pcaps.py
python3 tests/generate_bt3_test_pcaps.py bt3_t05_direction   # chỉ sinh một case

# Chạy toàn bộ test case Bài tập 1 + 2 và sinh report
python3 tests/run_case.py all

# Chạy riêng nhóm test case Bài tập 3 (prefix filter)
python3 tests/run_case.py all bt3

# Chạy một test case riêng (Bài tập 1, 2 hoặc 3)
python3 tests/run_case.py bt2_t07_tcp_handshake "<mục tiêu>" "<tiêu chí kiểm thử>"
python3 tests/run_case.py bt3_t11_distance_within "<mục tiêu>" "<tiêu chí kiểm thử>"

# Chạy trực tiếp case rules-only (loader/parser/indexer) — không cần PCAP
python3 -m tests.rule_case TEST/BT3/t01_rule_loader/test.rules TEST/BT3/t01_rule_loader/result.json
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

### 5.5. Cú pháp Rule hỗ trợ (Snort subset — Bài tập 3)

```text
alert <tcp|udp> <IP> <PORT> ->|<> <IP> <PORT> (options; ...)
```

| Thành phần | Hỗ trợ | Ghi chú |
|:---|:---|:---|
| Action | `alert` | Mọi action khác (`drop`, `pass`…) ⇒ `unsupported` |
| Protocol | `tcp`, `udp` | `icmp`/`ip` ⇒ `unsupported` |
| IP | `any`, IP đơn, CIDR (`10.0.0.0/24`) | Danh sách (`[...]`), phủ định `!`, IPv6 ⇒ `unsupported` |
| Port | `any`, port đơn, dải (`1024:2048`) | Danh sách (`[...]`), phủ định `!` ⇒ `unsupported` |
| Chiều | `->` (một chiều), `<>` (hai chiều) | |
| `msg`, `sid`, `rev` | Bắt buộc `sid` + `msg`; `sid` phải là số nguyên dương | Thiếu ⇒ `invalid` |
| `content` | Chuỗi trong `"..."` (escape `\"` `\\` `\;`), kèm `nocase`, `offset`, `depth`, `distance`, `within` | |
| `flow` | `to_server`, `to_client`, `established`, `not_established` (kết hợp bằng dấu phẩy) | Keyword flow khác ⇒ `unsupported` |
| `flags` | Tập con chữ cái cờ TCP: `S`, `A`, `F`, `R`, `P`, `U` (ví dụ `PA`) | `!`, `*`, `+`, `0` ⇒ `unsupported` |
| `dsize` | `N`, `>N`, `<N` | Dải `A<>B` ⇒ `unsupported` |
| `classtype`, `priority` | Tùy chọn, mặc định `priority = 1` | |

- Rule ngoài phạm vi (ví dụ `pcre`) không làm chương trình dừng: rule được đưa vào danh sách `unsupported` **kèm lý do**.
- Rule sai cú pháp (thiếu option bắt buộc, port không hợp lệ, thiếu dấu `;`…) được đưa vào `unsupported`/`invalid` **kèm số dòng**, các rule còn lại vẫn được nạp bình thường.

### 5.6. Ngữ nghĩa Matching (Bài tập 3)

- **Candidate prefilter (Indexer)**: với mỗi packet, repository chỉ trả về các rule có protocol khớp và IP/port giao nhau theo đúng chiều của packet (rule một chiều chỉ xét vế tương ứng; rule `<>` xét cả hai vế theo cả hai chiều).
- **Thứ tự kiểm tra** (short-circuit): header → `flow` state → `flags` → `dsize` → `content`.
- **Content**: so khớp **byte-exact trên raw payload** (không dựa trên dữ liệu đã decode). `nocase` chỉ lowercase ASCII (a–z ↔ A–Z), byte ≥ 0x80 giữ nguyên.
- **`offset`/`depth`**: cửa sổ tuyệt đối trên payload — tìm trong `[offset, offset + depth)`; mặc định `offset = 0`, `depth` = phần còn lại payload.
- **`distance`/`within`**: tương đối so với content **liền trước** — cửa sổ tìm là `[prev_end + distance, prev_end + distance + within)` (trong đó `prev_end` là vị trí kết thúc match trước đó). Content **không** có `distance`/`within` được tìm **độc lập trên toàn payload** (đúng ngữ nghĩa Snort).
- **`flow`**: `to_server` = chiều forward (client → server), `to_client` = chiều backward (theo endpoint khởi tạo flow của tracker); `established` ⇔ flow state ∈ {`ESTABLISHED`, `CLOSING`} (bao trùm cả flow đang đóng bằng FIN); không có thông tin flow ⇒ các điều kiện `flow` **không** match.
- **Multi-match mặc định**: một packet có thể sinh **nhiều detection event** (mỗi rule khớp 1 event). Đặt `rules.stop_on_first_match = true` nếu chỉ muốn event đầu tiên.
- **Deviation có chủ đích**: với UDP, tracker đánh dấu state `ESTABLISHED` ngay từ packet đầu (UDP không có handshake) — do đó `flow:established` với UDP hiệu lực ngay packet thứ nhất. Snort gốc không coi UDP là established; xem mục 8 để biết chi tiết.

### 5.7. Detection Event (`detections.jsonl`)

Mỗi dòng là một detection event JSON (chỉ sinh khi ruleset không rỗng):

```json
{
  "packet_id": 4,
  "timestamp": 1700000000.3,
  "timestamp_iso": "2023-11-14T22:13:20.300000+00:00",
  "action": "alert",
  "sid": 1100121,
  "rev": 2,
  "msg": "Directory traversal detected",
  "classtype": "attempted-admin",
  "priority": 1,
  "protocol": "TCP",
  "application_protocol": "HTTP",
  "src_ip": "10.0.0.10",
  "src_port": 52000,
  "dst_ip": "10.0.0.20",
  "dst_port": 80,
  "direction": "forward",
  "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
  "flow_state": "ESTABLISHED",
  "matched": {
    "contents": [{"content": "/etc/passwd", "offset": 7, "length": 11, "nocase": true}],
    "fields": ["flow:to_server,established", "flags:PA", "dsize:>0"]
  },
  "rule_file": "TEST/BT3/t14_detection_event/test.rules"
}
```

- `matched.contents`: vị trí (`offset`) và độ dài (`length`) thực tế của từng content khớp trên payload.
- `matched.fields`: các option phi-content đã thỏa (flow/flags/dsize).
- Event chỉ phát sinh cho các packet có tầng transport hợp lệ; packet không có flow (ARP, IP lạ…) không tạo detection.

---

## 6. Kết quả Bài tập 1 — 14 Test Cases

| STT | Tên Test Case | Mục tiêu kiểm thử | Trạng thái | Thư mục |
|:---:|:---|:---|:---:|:---|
| 01 | **TCP Handshake** | Nhận diện đúng SYN, SYN/ACK, ACK | **PASS** | `TEST/BT1/test_01_tcp_handshake/` |
| 02 | **TCP Data** | Parse TCP packet có payload và kiểm tra độ dài | **PASS** | `TEST/BT1/test_02_tcp_data/` |
| 03 | **UDP** | Parse UDP packet, trích xuất port, payload | **PASS** | `TEST/BT1/test_03_udp/` |
| 04 | **HTTP GET** | Parse HTTP request method, URI, headers | **PASS** | `TEST/BT1/test_04_http_get/` |
| 05 | **HTTP POST** | Parse HTTP request có body, headers | **PASS** | `TEST/BT1/test_05_http_post/` |
| 06 | **HTTP Response** | Parse HTTP status code, headers, reason | **PASS** | `TEST/BT1/test_06_http_response/` |
| 07 | **DNS Query** | Parse domain name và query type (A, AAAA...) | **PASS** | `TEST/BT1/test_07_dns_query/` |
| 08 | **DNS Response** | Parse answer records (name, type, rdata, ttl) | **PASS** | `TEST/BT1/test_08_dns_response/` |
| 09 | **SMTP Command** | Parse HELO/EHLO, MAIL FROM, RCPT TO | **PASS** | `TEST/BT1/test_09_smtp_command/` |
| 10 | **SMTP Response** | Parse SMTP status codes (220, 250, 354) | **PASS** | `TEST/BT1/test_10_smtp_response/` |
| 11 | **Unknown Protocol** | Xử lý an toàn không crash khi gặp protocol lạ | **PASS** | `TEST/BT1/test_11_unknown_protocol/` |
| 12 | **Malformed Packet** | Xử lý an toàn không crash khi gặp packet hỏng | **PASS** | `TEST/BT1/test_12_malformed_packet/` |
| 13 | **Non-standard Port** (bổ sung) | Nhận diện HTTP/SMTP/DNS trên port phi tiêu chuẩn | **PASS** | `TEST/BT1/test_13_non_standard_port/` |
| 14 | **Truncated PCAP** (bổ sung) | Không crash khi file PCAP bị cắt cụt | **PASS** | `TEST/BT1/test_14_truncated_pcap/` |

---

## 7. Kết quả Bài tập 2 — 14 Test Cases (T01–T14)

```bash
python3 tests/generate_bt2_test_pcaps.py   # sinh PCAP (timestamp cố định)
python3 tests/run_case.py all              # chạy và sinh report cho cả 14 case
```

| Case | Tên Test Case | Mục tiêu kiểm thử | Kết quả chính | Trạng thái | Thư mục |
|:---:|:---|:---|:---|:---:|:---|
| T01 | **HTTP URL Decode** | Percent-encoding trên URI | `uri_decoded = "/search?q=' OR 1=1&lang=en"`, URI gốc giữ nguyên, 1 flow | **PASS** | `TEST/BT2/bt2_t01_http_url_decode/` |
| T02 | **HTML Entity** | Giải mã entity trong body `text/html` | `body_decoded = "<p>Hello <script>alert(1)</script> & welcome</p>"`, charset `utf-8` | **PASS** | `TEST/BT2/bt2_t02_html_entity/` |
| T03 | **SMTP MIME** | base64, quoted-printable, RFC 2047 | `"Hello World! This is a base64 message."`, `"Hệ thống IDS đang hoạt động."`, `Subject = "Tái khoan"`, 1 flow SMTP | **PASS** | `TEST/BT2/bt2_t03_smtp_mime/` |
| T04 | **Invalid Bytes** | Byte không hợp lệ UTF-8 | `decode_status = "partial"`, warning `invalid_utf8_sequence`, payload lạ `UNKNOWN` | **PASS** | `TEST/BT2/bt2_t04_invalid_bytes/` |
| T05 | **Normalization** | Header, Host, URI path, domain | `Content-Type`, `Host = "ids.security.lab:8080"`, `uri_normalized = "/admin/secret?q=/"`, `portal.uit.edu.vn`, 2 flow | **PASS** | `TEST/BT2/bt2_t05_normalization/` |
| T06 | **Missing Field** | Thiếu tầng mạng / protocol lạ | ARP ⇒ `invalid/missing_network_layer`, `flow = null`; UDP lạ ⇒ `partial/unsupported_protocol`, 1 flow | **PASS** | `TEST/BT2/bt2_t06_missing_field/` |
| T07 | **TCP Handshake** | Flow qua 3 bước bắt tay | 1 flow `HANDSHAKE → ESTABLISHED`, `syn_count = 2`, `ack_count = 2`, fwd/bwd `2/1` | **PASS** | `TEST/BT2/bt2_t07_tcp_handshake/` |
| T08 | **Bidirectional** | Request/response hai chiều | 1 flow, `direction` `forward`/`backward`, mỗi chiều 1 packet, app `HTTP` | **PASS** | `TEST/BT2/bt2_t08_bidirectional/` |
| T09 | **TCP Close** | Đóng bằng FIN hai chiều và RST | Flow 1 `CLOSED`/`fin` (`fin_count = 2`), flow 2 `RESET`/`rst` | **PASS** | `TEST/BT2/bt2_t09_tcp_close/` |
| T10 | **UDP DNS Flow** | Flow UDP cho DNS query/response | 1 flow `UDP` `ESTABLISHED`, 2 packet / 159 byte, app `DNS`, `syn_count = 0` | **PASS** | `TEST/BT2/bt2_t10_udp_dns/` |
| T11 | **Concurrent Flows** | Ba flow xen kẽ | 3 flow record riêng biệt, mỗi flow 2 packet | **PASS** | `TEST/BT2/bt2_t11_concurrent_flows/` |
| T12 | **Idle Timeout** | Timeout cấu hình được (`--tcp-timeout 5`) | Flow im lặng 29.99s ⇒ `close_reason = "timeout"`; flow mới ⇒ `end_of_capture` | **PASS** | `TEST/BT2/bt2_t12_idle_timeout/` |
| T13 | **Flow Statistics** | Thống kê chi tiết một flow | 8 packet, 392 byte (192 xuôi + 200 ngược), `duration = 0.7`, `syn/ack/fin = 2/7/2`, `CLOSED`/`fin` | **PASS** | `TEST/BT2/bt2_t13_statistics/` |
| T14 | **Malformed Event** | Event lỗi + PCAP cắt cụt | TCP không payload ⇒ `partial/no_application_layer`; IP `PROTO_0` ⇒ `partial/missing_transport_layer` | **PASS** | `TEST/BT2/bt2_t14_malformed_event/` |

---

## 8. Kết quả Bài tập 3 — 14 Test Cases (Core Engine)

```bash
python3 tests/generate_bt3_test_pcaps.py   # sinh rules + PCAP (t01–t04, t06: rules-only)
python3 tests/run_case.py all bt3          # chạy và sinh report cho cả 14 case
```

**Deviation có chủ đích so với Snort gốc** (đã nêu ở mục 5.6): với UDP, tracker đánh dấu flow `ESTABLISHED` ngay từ packet đầu tiên (UDP không có handshake để quan sát), nên điều kiện `flow:established` với rule UDP có hiệu lực ngay packet thứ nhất. Snort gốc yêu cầu đã thấy lưu lượng hai chiều trước khi coi flow là established — trong bối cảnh module này chỉ có state của Flow Tracker, quy ước trên là nhất quán và tất định khi replay PCAP.

| Case | Tên Test Case | Mục tiêu kiểm thử | Kết quả chính | Trạng thái | Thư mục |
|:---:|:---|:---|:---|:---:|:---|
| T01 | **Rule Loader** | Nạp nhiều file, comment/dòng trống, lỗi từng rule | 3`valid` (1100001–1100003); 1`invalid` (thiếu `sid`) + 1`unsupported` (`pcre`) kèm số dòng; 2 file nạp cùng lúc | **PASS** | `TEST/BT3/t01_rule_loader/` |
| T02 | **Invalid Rule** | Rule sai cú pháp | 3`invalid`: thiếu `sid`, thiếu `;`/`msg`, port `abc`; 0 rule hợp lệ | **PASS** | `TEST/BT3/t02_invalid_rule/` |
| T03 | **Unsupported Keyword** | Ngoài phạm vi hỗ trợ | 4`unsupported`: `pcre`, action `drop`, protocol `icmp`, địa chỉ phủ định `!` — kèm lý do, không crash | **PASS** | `TEST/BT3/t03_unsupported_keyword/` |
| T04 | **Header Parse** | CIDR, port range, chiều `<>` | Parse đúng `10.0.0.0/24`, `1024:2048`, rule hai chiều 1100023 | **PASS** | `TEST/BT3/t04_header_parse/` |
| T05 | **Direction** | `to_server` / `to_client` | Payload forward ⇒ chỉ rule `to_server` (1100041) nổ; backward ⇒ chỉ `to_client` (1100042) | **PASS** | `TEST/BT3/t05_direction/` |
| T06 | **Indexer Candidates** | Candidate rules theo index | 6 probe: chỉ rule giao IP/port/protocol đúng chiều là candidate (1100031–1100034) | **PASS** | `TEST/BT3/t06_indexer_candidates/` |
| T07 | **Header Prefilter** | Cùng content, khác header | 3 packet cùng chứa `EVIL`: chỉ rule có header/port khớp nổ (1100051, 1100052), UDP port 53 ⇒ 1100053 | **PASS** | `TEST/BT3/t07_header_prefilter/` |
| T08 | **Flow State** | `established` / `not_established` | SYN đầu tiên (`HANDSHAKE`) ⇒ rule `not_established` (1100062); sau handshake ⇒ rule `established` (1100061) nổ trên packet `HELLO` | **PASS** | `TEST/BT3/t08_flow_state/` |
| T09 | **Content Nocase** | `nocase` | `AdMiN` ⇒ chỉ rule nocase (1100071); `ADMIN` ⇒ cả hai rule (1100071 + 1100072) nổ | **PASS** | `TEST/BT3/t09_content_nocase/` |
| T10 | **Offset/Depth** | Cửa sổ tìm tuyệt đối | `MALWARE` tại offset 28 khớp rule `offset:28; depth:7` (1100081); cùng content ngoài cửa sổ ⇒ không nổ | **PASS** | `TEST/BT3/t10_offset_depth/` |
| T11 | **Distance/Within** | Cửa sổ tương đối | Hai chuỗi cách nhau đúng 1 byte khớp `distance:1; within:1` (1100091); khoảng cách khác ⇒ không nổ | **PASS** | `TEST/BT3/t11_distance_within/` |
| T12 | **Flags/Dsize** | `flags` + `dsize` | Packet `PA` với dsize > 10 ⇒ 1100101; packet `F` dsize 0 ⇒ 1100103; packet dsize < 10 không thỏa ⇒ không nổ | **PASS** | `TEST/BT3/t12_flags_dsize/` |
| T13 | **Multi-Rule Match** | Nhiều rule cùng khớp 1 packet | Packet 4 khớp cả 3 rule (1100111, 1100112, 1100113) ⇒ 3 detection event cho cùng packet | **PASS** | `TEST/BT3/t13_multi_rule_match/` |
| T14 | **Detection Event** | Event đầy đủ trường | Event: `sid 1100121`, `classtype attempted-admin`, `flow_state ESTABLISHED`, `matched.contents` offset 7/length 11, `matched.fields` flow+flags+dsize, `rule_file` chính xác | **PASS** | `TEST/BT3/t14_detection_event/` |

---

## 9. AI Disclosure

- **Công cụ AI sử dụng**: Antigravity (Gemini 3.8 flash)
- **Mục đích sử dụng**:
  - Hỗ trợ xây dựng kế hoạch phân rã tính năng (task breakdown) theo phương pháp luận kỹ thuật phần mềm.
  - Hỗ trợ thiết kế kiến trúc pipeline 9 tầng (`capture/`, `parsers/`, `decoder/`, `preprocessor/`, `flow/`, `core/`, `pipeline/`, `storage/`, `config.py`).
  - Hỗ trợ tạo bộ dữ liệu test case mẫu chuẩn bằng Scapy cho 14 kịch bản Bài tập 1, 14 kịch bản Bài tập 2 (timestamp cố định để kiểm thử timeout/thống kê tất định) và 14 kịch bản Bài tập 3 (rules + PCAP, timestamp cố định `1700000000.0`).
  - Hỗ trợ rà soát (review) logic máy trạng thái TCP, quy tắc chuẩn hóa URI/header và các literal `decode_status`/`reason`/`close_reason` cho khớp đặc tả đề bài; rà soát ngữ nghĩa matching của Snort (offset/depth, distance/within trên raw payload) và các deviation có chủ đích cho Bài tập 3.
- **Phần mã nguồn có sự hỗ trợ của AI**:
  - Cấu trúc dataclass trong `parsers/models.py`, `flow/models.py` và module cấu hình `config.py`.
  - Biểu thức chính quy (Regex) và logic bóc tách trong `parsers/detector.py`, `parsers/application/http.py`, `parsers/application/dns.py`, `parsers/application/smtp.py`.
  - Logic giải mã trong `decoder/decoder.py` và logic kiểm tra/chuẩn hóa trong `preprocessor/preprocessor.py`.
  - Máy trạng thái TCP, timeout và thống kê trong `flow/tracker.py`.
  - Phần tích hợp `pipeline/engine.py`, các tham số CLI mới trong `main.py` và script sinh dữ liệu `tests/generate_bt2_test_pcaps.py`.
  - Core Engine Bài tập 3: toàn bộ `core/models.py`, `core/parser.py`, `core/loader.py`, `core/indexer.py`, `core/matcher.py`, `core/detection.py`, `core/evaluator.py`; mục `rules` trong `config.py`; tích hợp rule evaluation + logger detection trong `pipeline/engine.py` và `main.py`; script `tests/generate_bt3_test_pcaps.py`, `tests/rule_case.py` và phần mở rộng Bài tập 3 của `tests/run_case.py`.
