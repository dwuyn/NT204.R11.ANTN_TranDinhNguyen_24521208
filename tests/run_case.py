"""Runner to execute a test case, generate output.jsonl, and generate report.md.

Each test case has a registered set of assertions (EXPECTATIONS). A case only
reports PASS when every expected JSON subset matches at least one parsed event,
the minimum event count is reached, and (when configured) the minimum number of
flow records is reached and every flow assertion matches.

Registered keys per case:
  min_events   minimum number of parsed events.
  checks       list of JSON subsets; each subset must match at least one event.
  pcap         optional pcap filename (default test.pcap).
  min_flows    optional minimum number of flow records.
  flow_checks  optional list of JSON subsets matched against flow records.
  args         optional extra CLI arguments passed to main.py.
  description  test objective (required to be included in `run_case.py all`).
  criteria     verification criteria (required for `run_case.py all`).

Assignment 3 (rules-only) keys:
  kind                   "rules" runs tests/rule_case.py instead of main.py and
                         asserts `checks` against its result.json.
  rules                  rule filename (default test.rules).
  probes                 candidate queries passed to the rule indexer.
  loader                 optional disabled_sids/disabled_files for RuleLoader.
  min_detections         optional minimum number of detection records.
  detection_checks       optional list of JSON subsets matched against detections.
  forbidden_detections   optional list of JSON subsets that must match nothing.

Usage:
  python tests/run_case.py <case_name> "<description>" "<criteria>"
  python tests/run_case.py all [case_prefix]
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

# Expected result per test case directory.
#   min_events: minimum number of parsed events.
#   checks: list of JSON subsets; each subset must match at least one event.
#   pcap: optional pcap filename (default test.pcap).
#   min_flows / flow_checks: optional flow record assertions.
#   args: optional extra CLI arguments for main.py.
#   description / criteria: required for `run_case.py all`.
EXPECTATIONS = {
    "test_01_tcp_handshake": {
        "min_events": 3,
        "checks": [
            {"transport": {"handshake": "SYN"}},
            {"transport": {"handshake": "SYN-ACK"}},
            {"transport": {"handshake": "ACK"}},
        ],
        "description": "TCP 3-way Handshake",
        "criteria": "Nhận diện đúng SYN, SYN/ACK, ACK",
    },
    "test_02_tcp_data": {
        "min_events": 1,
        "checks": [
            {"transport": {"layer": "TCP", "payload_len": 44}},
            {"application": {"protocol": "UNKNOWN"}},
        ],
        "description": "TCP Data Packet",
        "criteria": "Parse TCP packet có payload và kiểm tra độ dài payload",
    },
    "test_03_udp": {
        "min_events": 1,
        "checks": [{"transport": {"layer": "UDP", "payload_len": 47}}],
        "description": "UDP Datagram",
        "criteria": "Parse UDP packet, trích xuất port và payload",
    },
    "test_04_http_get": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "type": "request",
                    "details": {
                        "method": "GET",
                        "uri": "/api/v1/network/stats",
                        "version": "HTTP/1.1",
                    },
                }
            }
        ],
        "description": "HTTP GET Request",
        "criteria": "Parse method, URI, version, headers",
    },
    "test_05_http_post": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "type": "request",
                    "details": {
                        "method": "POST",
                        "uri": "/api/login",
                        "body": "username=admin&password=secretPassword123",
                    },
                }
            }
        ],
        "description": "HTTP POST Request",
        "criteria": "Parse method, headers và trích xuất request body",
    },
    "test_06_http_response": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "type": "response",
                    "details": {"status_code": 200, "reason": "OK"},
                }
            }
        ],
        "description": "HTTP Response",
        "criteria": "Parse HTTP version, status code, reason phrase, headers, body",
    },
    "test_07_dns_query": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "DNS",
                    "type": "query",
                    "details": {"queries": [{"name": "portal.uit.edu.vn", "type": "A"}]},
                }
            }
        ],
        "description": "DNS Query",
        "criteria": "Parse domain và query type",
    },
    "test_08_dns_response": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "DNS",
                    "type": "response",
                    "details": {
                        "answers": [
                            {
                                "name": "portal.uit.edu.vn",
                                "type": "A",
                                "rdata": "118.69.123.45",
                            }
                        ]
                    },
                }
            }
        ],
        "description": "DNS Response",
        "criteria": "Parse ít nhất một answer record gồm name, type, rdata, ttl",
    },
    "test_09_smtp_command": {
        "min_events": 3,
        "checks": [
            {"application": {"protocol": "SMTP", "details": {"command": "EHLO"}}},
            {"application": {"protocol": "SMTP", "details": {"command": "MAIL FROM"}}},
            {"application": {"protocol": "SMTP", "details": {"command": "RCPT TO"}}},
        ],
        "description": "SMTP Commands",
        "criteria": "Parse HELO/EHLO, MAIL FROM và RCPT TO kèm tham số",
    },
    "test_10_smtp_response": {
        "min_events": 3,
        "checks": [
            {"application": {"protocol": "SMTP", "details": {"status_code": 220}}},
            {"application": {"protocol": "SMTP", "details": {"status_code": 250}}},
            {"application": {"protocol": "SMTP", "details": {"status_code": 354}}},
        ],
        "description": "SMTP Responses",
        "criteria": "Parse SMTP status codes (220, 250, 354)",
    },
    "test_11_unknown_protocol": {
        "min_events": 2,
        "checks": [
            {"application": {"protocol": "UNKNOWN"}},
            {"errors": []},
        ],
        "description": "Unknown Protocol",
        "criteria": "Xử lý an toàn không crash khi gặp giao thức không hỗ trợ",
    },
    "test_12_malformed_packet": {
        "min_events": 2,
        "checks": [
            {"transport": {"handshake": "SYN"}},
            {"application": {"protocol": "UNKNOWN"}},
        ],
        "description": "Malformed Packet",
        "criteria": "Xử lý an toàn không crash khi gặp packet hỏng/cắt cụt",
    },
    "test_13_non_standard_port": {
        "min_events": 3,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "details": {"method": "GET", "detection_method": "payload_signature"},
                }
            },
            {
                "application": {
                    "protocol": "SMTP",
                    "details": {"command": "EHLO", "detection_method": "payload_signature"},
                }
            },
            {
                "application": {
                    "protocol": "DNS",
                    "details": {"detection_method": "payload_signature"},
                }
            },
        ],
        "description": "Non-standard Port Detection",
        "criteria": "Nhận diện HTTP/SMTP/DNS trên port phi tiêu chuẩn bằng payload",
    },
    "test_14_truncated_pcap": {
        "pcap": "truncated.pcap",
        "min_events": 1,
        "checks": [
            {"application": {"protocol": "HTTP", "details": {"method": "GET"}}},
        ],
        "description": "Truncated PCAP",
        "criteria": "Không crash khi file PCAP bị cắt cụt, vẫn parse gói đầy đủ đầu tiên",
    },
    # ------------------------------------------------------------------
    # Assignment 2 cases (decoder, preprocessor, flow tracker)
    # ------------------------------------------------------------------
    "bt2_t01_http_url_decode": {
        "min_events": 1,
        "checks": [
            {"application": {"details": {"uri": "/search?q=%27%20OR%201%3D1&lang=en"}}},
            {
                "decode": {
                    "decode_status": "decoded",
                    "fields": {"uri_decoded": "/search?q=' OR 1=1&lang=en"},
                }
            },
            {
                "preprocess": {"preprocess_status": "valid", "processing_action": "forward"},
            },
        ],
        "min_flows": 1,
        "description": "Giải mã percent-encoding trên URI của HTTP request",
        "criteria": (
            "Event HTTP request giữ nguyên URI gốc đã mã hóa, decode.fields.uri_decoded "
            "chứa chuỗi %27%20OR%201%3D1 đã giải mã, event hợp lệ (forward) và có 1 flow TCP."
        ),
    },
    "bt2_t02_html_entity": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "details": {
                        "body": "<p>Hello &lt;script&gt;alert(1)&lt;/script&gt; &amp; welcome</p>"
                    }
                }
            },
            {
                "decode": {
                    "decoders": ["html_entities"],
                    "fields": {
                        "body_decoded": "<p>Hello <script>alert(1)</script> & welcome</p>",
                        "body_charset": "utf-8",
                        "body_decode_status": "ok",
                    },
                }
            },
        ],
        "description": "Giải mã HTML entity trong body của HTTP response text/html",
        "criteria": (
            "Body gốc vẫn giữ nguyên entity, decode.fields.body_decoded đã unescape "
            "&lt;script&gt; thành <script>, charset là utf-8 và body_decode_status là ok."
        ),
    },
    "bt2_t03_smtp_mime": {
        "min_events": 2,
        "checks": [
            {"application": {"protocol": "SMTP", "type": "data"}},
            {
                "decode": {
                    "fields": {
                        "mime_body_decoded": "Hello World! This is a base64 message.",
                        "content_transfer_encoding": "base64",
                    },
                    "decoders": ["base64"],
                }
            },
            {
                "decode": {
                    "fields": {
                        "mime_body_decoded": "Hệ thống IDS đang hoạt động.",
                        "content_transfer_encoding": "quoted-printable",
                    },
                    "decoders": ["quoted_printable"],
                }
            },
            {"decode": {"fields": {"headers_decoded": {"Subject": "Tái khoan"}}}},
        ],
        "min_flows": 1,
        "flow_checks": [{"application_protocol": "SMTP", "packet_count": 2}],
        "description": "Giải mã MIME base64, quoted-printable và header RFC 2047 trong SMTP DATA",
        "criteria": (
            "Hai packet MIME được nhận là SMTP data, body base64 giải mã thành "
            "'Hello World! This is a base64 message.', body quoted-printable giải mã thành "
            "'Hệ thống IDS đang hoạt động.', header Subject RFC 2047 giải mã thành 'Tái khoan', "
            "và cả hai packet thuộc cùng một flow SMTP."
        ),
    },
    "bt2_t04_invalid_bytes": {
        "min_events": 2,
        "checks": [
            {"decode": {"decode_status": "partial", "warnings": ["invalid_utf8_sequence"]}},
            {"application": {"protocol": "UNKNOWN"}, "decode": {"decode_status": "partial"}},
            {"preprocess": {"preprocess_status": "partial", "reason": "unsupported_protocol"}},
        ],
        "description": "Xử lý byte không hợp lệ UTF-8 và payload giao thức không hỗ trợ",
        "criteria": (
            "Body chứa byte lỗi UTF-8 được giải mã thay thế và gắn trạng thái partial với "
            "warning invalid_utf8_sequence, payload nhị phân lạ được nhận là UNKNOWN và "
            "preprocessor trả về partial/unsupported_protocol."
        ),
    },
    "bt2_t05_normalization": {
        "min_events": 2,
        "checks": [
            {
                "application": {
                    "details": {
                        "headers": {
                            "Content-Type": "text/plain",
                            "Host": "ids.security.lab:8080",
                        }
                    }
                }
            },
            {
                "application": {
                    "details": {
                        "uri_normalized": "/admin/secret?q=/",
                        "uri": "//admin//./stats/%2e%2e/secret?q=%2f",
                    }
                }
            },
            {"preprocess": {"normalizations": ["http_header_names", "uri_path"]}},
            {
                "application": {"details": {"queries": [{"name": "portal.uit.edu.vn"}]}},
                "preprocess": {"normalizations": ["domain_lowercase"]},
            },
        ],
        "min_flows": 2,
        "description": "Chuẩn hóa HTTP header, Host, URI path và tên miền DNS",
        "criteria": (
            "Header 'content-TYPE' thành 'Content-Type', 'hOSt' thành 'Host' với host viết "
            "thường, URI '//admin//./stats/%2e%2e/secret?q=%2f' chuẩn hóa thành "
            "'/admin/secret?q=/', QNAME 'PORTAL.UIT.EDU.VN' thành 'portal.uit.edu.vn' và "
            "preprocess.normalizations ghi nhận đúng các loại đã thay đổi."
        ),
    },
    "bt2_t06_missing_field": {
        "min_events": 2,
        "checks": [
            {
                "network": None,
                "transport": None,
                "flow": None,
                "preprocess": {
                    "preprocess_status": "invalid",
                    "reason": "missing_network_layer",
                },
            },
            {
                "application": {"protocol": "UNKNOWN"},
                "preprocess": {"preprocess_status": "partial", "reason": "unsupported_protocol"},
            },
        ],
        "min_flows": 1,
        "description": "Xử lý event thiếu tầng mạng và thiếu giao thức ứng dụng hỗ trợ",
        "criteria": (
            "Packet ARP không có network/transport layer được đánh invalid với reason "
            "missing_network_layer và không gắn flow; payload UDP lạ được đánh partial với "
            "reason unsupported_protocol nhưng vẫn được theo dõi 1 flow UDP."
        ),
    },
    "bt2_t07_tcp_handshake": {
        "min_events": 3,
        "checks": [
            {
                "transport": {"handshake": "SYN"},
                "flow": {"direction": "forward", "is_new_flow": True, "state": "HANDSHAKE"},
            },
            {"transport": {"handshake": "SYN-ACK"}, "flow": {"direction": "backward"}},
            {
                "transport": {"handshake": "ACK"},
                "flow": {
                    "state": "ESTABLISHED",
                    "flow_id": "TCP-10.0.0.10:51234-10.0.0.1:80",
                },
            },
        ],
        "min_flows": 1,
        "flow_checks": [
            {
                "state": "ESTABLISHED",
                "packet_count": 3,
                "forward": {"packet_count": 2},
                "backward": {"packet_count": 1},
                "syn_count": 2,
                "ack_count": 2,
                "fin_count": 0,
                "rst_count": 0,
                "close_reason": "end_of_capture",
            }
        ],
        "description": "Theo dõi flow TCP qua ba bước bắt tay SYN, SYN-ACK, ACK",
        "criteria": (
            "Ba packet cùng 5-tuple tạo đúng 1 flow, state chuyển HANDSHAKE -> ESTABLISHED, "
            "hướng forward/backward chính xác, đếm đủ 2 SYN (SYN-ACK tính vào cả SYN và ACK) "
            "và 2 ACK, flow được flush khi hết capture với close_reason end_of_capture."
        ),
    },
    "bt2_t08_bidirectional": {
        "min_events": 2,
        "checks": [
            {
                "flow": {
                    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
                    "direction": "forward",
                }
            },
            {
                "flow": {
                    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
                    "direction": "backward",
                }
            },
        ],
        "min_flows": 1,
        "flow_checks": [
            {
                "packet_count": 2,
                "application_protocol": "HTTP",
                "forward": {"packet_count": 1},
                "backward": {"packet_count": 1},
            }
        ],
        "description": "Gộp request/response hai chiều vào cùng một flow",
        "criteria": (
            "Request và response ngược chiều cùng 5-tuple thuộc một flow duy nhất với "
            "flow_id ổn định, direction lần lượt là forward/backward, mỗi chiều 1 packet "
            "và application_protocol được nhận là HTTP."
        ),
    },
    "bt2_t09_tcp_close": {
        "min_events": 6,
        "checks": [
            {
                "flow": {
                    "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
                    "state": "CLOSED",
                }
            },
            {
                "flow": {
                    "flow_id": "TCP-10.0.0.10:51002-10.0.0.30:8080",
                    "state": "RESET",
                }
            },
        ],
        "min_flows": 2,
        "flow_checks": [
            {
                "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
                "state": "CLOSED",
                "close_reason": "fin",
                "fin_count": 2,
                "packet_count": 6,
            },
            {
                "flow_id": "TCP-10.0.0.10:51002-10.0.0.30:8080",
                "state": "RESET",
                "close_reason": "rst",
                "rst_count": 1,
            },
        ],
        "description": "Đóng flow TCP bằng FIN hai chiều và bằng RST",
        "criteria": (
            "Flow thứ nhất qua chuỗi SYN, SYN-ACK, ACK, FIN, ACK, FIN chuyển sang CLOSED "
            "với close_reason fin và 2 FIN; flow thứ hai SYN rồi RST chuyển sang RESET với "
            "close_reason rst; cả hai flow record đều được ghi."
        ),
    },
    "bt2_t10_udp_dns": {
        "min_events": 2,
        "checks": [
            {
                "application": {"type": "query"},
                "flow": {"flow_id": "UDP-192.168.1.100:53000-8.8.8.8:53"},
            },
            {"application": {"type": "response"}},
        ],
        "min_flows": 1,
        "flow_checks": [
            {
                "protocol": "UDP",
                "state": "ESTABLISHED",
                "packet_count": 2,
                "byte_count": 159,
                "forward": {"packet_count": 1},
                "backward": {"packet_count": 1},
                "application_protocol": "DNS",
                "syn_count": 0,
            }
        ],
        "description": "Theo dõi flow UDP cho cặp DNS query/response",
        "criteria": (
            "Query và response DNS cùng 5-tuple tạo đúng 1 flow UDP ở trạng thái ESTABLISHED "
            "ngay từ packet đầu, đếm 2 packet (159 byte) chia đều hai chiều, "
            "application_protocol là DNS và không có cờ TCP nào được đếm."
        ),
    },
    "bt2_t11_concurrent_flows": {
        "min_events": 6,
        "checks": [
            {"flow": {"direction": "forward"}},
        ],
        "min_flows": 3,
        "flow_checks": [
            {"flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80", "packet_count": 2},
            {"flow_id": "TCP-10.0.0.11:52001-10.0.0.20:80", "packet_count": 2},
            {"flow_id": "TCP-10.0.0.10:52002-10.0.0.30:443", "packet_count": 2},
        ],
        "description": "Theo dõi đồng thời ba flow xen kẽ nhau",
        "criteria": (
            "Sáu packet thuộc ba 5-tuple xen kẽ theo thời gian tạo đúng 3 flow record riêng "
            "biệt, mỗi flow nhận đúng 2 packet và flow_id tương ứng từng kết nối."
        ),
    },
    "bt2_t12_idle_timeout": {
        "min_events": 3,
        "checks": [
            {
                "flow": {
                    "flow_id": "TCP-10.0.0.11:53000-10.0.0.20:8080",
                    "is_new_flow": True,
                }
            },
        ],
        "min_flows": 2,
        "flow_checks": [
            {
                "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
                "close_reason": "timeout",
                "state": "ESTABLISHED",
                "packet_count": 2,
            },
            {
                "flow_id": "TCP-10.0.0.11:53000-10.0.0.20:8080",
                "close_reason": "end_of_capture",
            },
        ],
        "args": ["--tcp-timeout", "5"],
        "description": "Đóng flow TCP khi vượt idle timeout cấu hình được",
        "criteria": (
            "Với --tcp-timeout 5, flow thứ nhất im lặng 29.99s bị đóng với close_reason "
            "timeout sau khi packet của flow thứ hai xuất hiện, flow thứ hai vẫn active và "
            "được flush khi hết capture với close_reason end_of_capture."
        ),
    },
    "bt2_t13_statistics": {
        "min_events": 8,
        "checks": [
            {"decode": {"fields": {"body_decoded": "OK"}}},
        ],
        "min_flows": 1,
        "flow_checks": [
            {
                "packet_count": 8,
                "byte_count": 392,
                "start_time": 1700000000.0,
                "last_seen": 1700000000.7,
                "duration": 0.7,
                "forward": {"packet_count": 4, "byte_count": 192},
                "backward": {"packet_count": 4, "byte_count": 200},
                "syn_count": 2,
                "ack_count": 7,
                "fin_count": 2,
                "rst_count": 0,
                "state": "CLOSED",
                "close_reason": "fin",
            }
        ],
        "description": "Thống kê chi tiết một flow TCP đầy đủ vòng đời",
        "criteria": (
            "Flow 8 packet từ bắt tay đến khi đóng ghi đúng start_time/last_seen/duration "
            "(0.7s) và byte_count (392 = 192 xuôi + 200 ngược), đếm đúng 2 SYN, 7 ACK, "
            "2 FIN, 0 RST và đóng với close_reason fin."
        ),
    },
    "bt2_t14_malformed_event": {
        "pcap": "truncated.pcap",
        "min_events": 2,
        "checks": [
            {
                "transport": {"layer": "TCP"},
                "preprocess": {
                    "preprocess_status": "partial",
                    "reason": "no_application_layer",
                },
            },
            {
                "network": {"proto": "PROTO_0"},
                "preprocess": {
                    "preprocess_status": "partial",
                    "reason": "missing_transport_layer",
                },
            },
        ],
        "min_flows": 1,
        "description": "Xử lý event lỗi và file PCAP bị cắt cụt",
        "criteria": (
            "PCAP cắt cụt vẫn đọc được, packet IP/TCP không payload được đánh partial với "
            "reason no_application_layer và vẫn tạo flow TCP; packet IP proto 0 không có "
            "transport layer được đánh partial với reason missing_transport_layer."
        ),
    },
    # ------------------------------------------------------------------
    # Assignment 3 cases (core engine: loader, parser, indexer, matcher,
    # evaluator, detection events)
    # ------------------------------------------------------------------
    "bt3_t01_rule_loader": {
        "kind": "rules",
        "checks": [
            {
                "stats": {
                    "files_loaded": 1,
                    "valid": 3,
                    "invalid": 1,
                    "unsupported": 1,
                    "disabled_rules": 0,
                    "disabled_files": 0,
                }
            },
            {
                "valid": [
                    {"sid": 1100001, "rev": 2, "msg": "HTTP GET"},
                    {"sid": 1100002, "rev": 1, "msg": "TLS hello"},
                    {"sid": 1100003, "rev": 1, "msg": "DNS query"},
                ]
            },
            {
                "valid": [
                    {
                        "sid": 1100001,
                        "contents": [{"content": "GET", "nocase": True}, {"content": "/index"}],
                    }
                ]
            },
            {
                "invalid": [
                    {"status": "invalid", "line_no": 6, "reason": "missing required option: msg"}
                ]
            },
            {
                "unsupported": [
                    {"status": "unsupported", "line_no": 7, "reason": "unsupported keyword: pcre"}
                ]
            },
            {
                "warnings": [
                    "invalid rule at TEST/BT3/t01_rule_loader/test.rules:6: "
                    "missing required option: msg",
                    "unsupported rule at TEST/BT3/t01_rule_loader/test.rules:7: "
                    "unsupported keyword: pcre",
                ]
            },
        ],
        "description": "Nạp rule từ file: dòng hợp lệ, dòng invalid và dòng unsupported",
        "criteria": (
            "Rule loader nạp file test.rules, bỏ qua comment/dòng trống, nhận đúng 3 rule hợp lệ "
            "với sid/rev/content (nocase) chính xác, ghi nhận 1 rule invalid (thiếu msg) tại "
            "dòng 6 và 1 rule unsupported (pcre) tại dòng 7 kèm warning tương ứng."
        ),
    },
    "bt3_t02_invalid_rule": {
        "kind": "rules",
        "checks": [
            {"stats": {"files_loaded": 1, "valid": 0, "invalid": 3, "unsupported": 0}},
            {"invalid": [{"status": "invalid", "line_no": 1, "reason": "missing required option: sid"}]},
            {"invalid": [{"status": "invalid", "line_no": 2, "reason": "invalid rule syntax"}]},
            {"invalid": [{"status": "invalid", "line_no": 3, "reason": "invalid port: abc"}]},
            {
                "warnings": [
                    "invalid rule at TEST/BT3/t02_invalid_rule/test.rules:1: missing required option: sid",
                    "invalid rule at TEST/BT3/t02_invalid_rule/test.rules:2: invalid rule syntax",
                    "invalid rule at TEST/BT3/t02_invalid_rule/test.rules:3: invalid port: abc",
                ]
            },
        ],
        "description": "Rule sai cú pháp bị đánh invalid kèm lý do, loader không dừng",
        "criteria": (
            "Ba rule thiếu sid, sai toán tử chiều (=>) và cổng không hợp lệ (abc) đều bị đánh "
            "invalid với reason tương ứng theo từng dòng, không rule nào bị crash và cả ba "
            "warning đều được ghi lại."
        ),
    },
    "bt3_t03_unsupported_keyword": {
        "kind": "rules",
        "checks": [
            {"stats": {"files_loaded": 1, "valid": 0, "invalid": 0, "unsupported": 4}},
            {"unsupported": [{"status": "unsupported", "line_no": 1, "reason": "unsupported keyword: pcre"}]},
            {"unsupported": [{"status": "unsupported", "line_no": 2, "reason": "unsupported action: drop"}]},
            {"unsupported": [{"status": "unsupported", "line_no": 3, "reason": "unsupported protocol: icmp"}]},
            {
                "unsupported": [
                    {"status": "unsupported", "line_no": 4, "reason": "unsupported negated address: !192.168.1.1"}
                ]
            },
        ],
        "description": "Cấu trúc ngoài phạm vi bị đánh unsupported kèm lý do, không crash",
        "criteria": (
            "Bốn rule dùng pcre, action drop, protocol icmp và địa chỉ phủ định đều được phân "
            "loại unsupported với reason cụ thể từng dòng; loader vẫn kết thúc bình thường với "
            "0 rule hợp lệ."
        ),
    },
    "bt3_t04_header_parse": {
        "kind": "rules",
        "checks": [
            {"stats": {"files_loaded": 1, "valid": 3}},
            {
                "valid": [
                    {
                        "sid": 1100021,
                        "header": {
                            "action": "alert",
                            "protocol": "tcp",
                            "direction": "->",
                            "src_ip": {"any": False, "network": "192.168.1.0/24", "text": "192.168.1.0/24"},
                            "src_port": {"lo": 1024, "hi": 2048, "text": "1024:2048"},
                            "dst_ip": {"any": False, "network": "10.0.0.5/32", "text": "10.0.0.5"},
                            "dst_port": {"lo": 80, "hi": 80, "text": "80"},
                        },
                    }
                ]
            },
            {
                "valid": [
                    {
                        "sid": 1100022,
                        "header": {
                            "protocol": "udp",
                            "direction": "<>",
                            "src_ip": {"any": True, "network": None, "text": "any"},
                            "src_port": {"lo": None, "hi": None, "text": "any"},
                            "dst_ip": {"any": False, "network": "8.8.8.8/32"},
                            "dst_port": {"lo": 53, "hi": 53, "text": "53"},
                        },
                    }
                ]
            },
            {
                "valid": [
                    {
                        "sid": 1100023,
                        "header": {
                            "src_ip": {"any": False, "network": "172.16.0.0/12"},
                            "src_port": {"lo": None, "hi": 1024, "text": ":1024"},
                            "dst_ip": {"any": True},
                            "dst_port": {"lo": 8080, "hi": 8080},
                        },
                    }
                ]
            },
        ],
        "description": "Parse rule header: CIDR, dải cổng, cận mở và toán tử hai chiều",
        "criteria": (
            "Header CIDR 192.168.1.0/24 với dải cổng 1024:2048, header UDP hai chiều <> tới "
            "8.8.8.8:53 và header với cận dưới mở :1024 đều được parse thành IPSpec/PortSpec "
            "chính xác (any/network/lo/hi/text)."
        ),
    },
    "bt3_t05_direction": {
        "min_events": 5,
        "min_flows": 1,
        "checks": [{"transport": {"layer": "TCP", "payload_len": 45}}],
        "min_detections": 2,
        "detection_checks": [
            {
                "sid": 1100041,
                "packet_id": 4,
                "direction": "forward",
                "flow_state": "ESTABLISHED",
                "action": "alert",
                "src_port": 52000,
                "dst_port": 80,
            },
            {
                "sid": 1100042,
                "packet_id": 5,
                "direction": "backward",
                "flow_state": "ESTABLISHED",
                "src_port": 80,
                "dst_port": 52000,
            },
        ],
        "forbidden_detections": [
            {"sid": 1100041, "direction": "backward"},
            {"sid": 1100042, "direction": "forward"},
        ],
        "description": "Hướng flow: to_server chỉ khớp chiều đi, to_client chỉ khớp chiều về",
        "criteria": (
            "Rule flow:to_server,established chỉ alert packet request (forward, packet 4) chứa "
            "'SECRET', rule flow:to_client,established chỉ alert packet response (backward, "
            "packet 5) chứa 'TOKEN'; không có detection nào sai chiều."
        ),
    },
    "bt3_t06_indexer_candidates": {
        "kind": "rules",
        "probes": [
            {"protocol": "TCP", "src_ip": "10.0.0.10", "src_port": 50000, "dst_ip": "10.0.0.20", "dst_port": 80},
            {"protocol": "TCP", "src_ip": "10.0.0.10", "src_port": 50000, "dst_ip": "10.0.0.20", "dst_port": 443},
            {"protocol": "UDP", "src_ip": "10.0.0.10", "src_port": 50000, "dst_ip": "8.8.8.8", "dst_port": 53},
            {"protocol": "TCP", "src_ip": "192.168.1.5", "src_port": 50000, "dst_ip": "10.0.0.20", "dst_port": 80},
            {"protocol": "TCP", "src_ip": "10.0.0.10", "src_port": 50000, "dst_ip": "172.16.0.1", "dst_port": 9999},
            {"protocol": "TCP", "src_ip": "10.0.0.10", "src_port": 50000, "dst_ip": "10.0.0.20", "dst_port": 90},
        ],
        "checks": [
            {"stats": {"valid": 4}},
            {
                "candidates": [
                    {
                        "query": {"protocol": "TCP", "src_ip": "10.0.0.10", "src_port": 50000, "dst_ip": "10.0.0.20", "dst_port": 80},
                        "sids_str": "1100031,1100034",
                    },
                    {
                        "query": {"protocol": "TCP", "src_ip": "10.0.0.10", "src_port": 50000, "dst_ip": "10.0.0.20", "dst_port": 443},
                        "sids_str": "1100032",
                    },
                    {
                        "query": {"protocol": "UDP", "src_ip": "10.0.0.10", "src_port": 50000, "dst_ip": "8.8.8.8", "dst_port": 53},
                        "sids_str": "1100033",
                    },
                    {
                        "query": {"protocol": "TCP", "src_ip": "192.168.1.5", "src_port": 50000, "dst_ip": "10.0.0.20", "dst_port": 80},
                        "sids_str": "1100031,1100034",
                    },
                    {
                        "query": {"protocol": "TCP", "src_ip": "10.0.0.10", "src_port": 50000, "dst_ip": "172.16.0.1", "dst_port": 9999},
                        "sids_str": "",
                    },
                    {
                        "query": {"protocol": "TCP", "src_ip": "10.0.0.10", "src_port": 50000, "dst_ip": "10.0.0.20", "dst_port": 90},
                        "sids_str": "1100034",
                    },
                ]
            },
        ],
        "description": "Indexer lọc candidate rule theo protocol, IP và cổng chính xác",
        "criteria": (
            "Với 4 rule đã nạp, truy vấn candidate cho các 5-tuple mẫu trả đúng tập sid đã sắp "
            "xếp: dst 80 khớp rule 'any' và rule dải 80:90, dst 443 chỉ khớp rule subnet TLS, "
            "UDP/53 khớp rule DNS, dst 90 chỉ khớp rule dải 80:90 và trả rỗng khi không rule "
            "nào phù hợp."
        ),
    },
    "bt3_t07_header_prefilter": {
        "min_events": 4,
        "min_detections": 3,
        "checks": [{"transport": {"layer": "UDP", "payload_len": 12}}],
        "detection_checks": [
            {"sid": 1100052, "packet_id": 1, "dst_ip": "10.0.0.50", "dst_port": 80},
            {"sid": 1100051, "packet_id": 2, "dst_ip": "10.0.0.100", "dst_port": 4444},
            {
                "sid": 1100053,
                "packet_id": 4,
                "protocol": "UDP",
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "matched": {"contents": [{"content": "version.bind", "nocase": True}]},
            },
        ],
        "forbidden_detections": [
            {"sid": 1100051, "packet_id": 1},
            {"sid": 1100052, "packet_id": 2},
            {"dst_port": 9999},
        ],
        "description": "Header rule quyết định: cùng content 'EVIL' nhưng chỉ đúng đích mới alert",
        "criteria": (
            "Ba packet TCP đều chứa 'EVIL' nhưng chỉ packet tới 10.0.0.50:80 khớp rule "
            "1100052 và packet tới 10.0.0.100:4444 khớp rule 1100051; packet tới "
            "10.0.0.60:9999 không khớp rule nào; packet UDP chứa 'version.bind' khớp rule DNS "
            "1100053."
        ),
    },
    "bt3_t08_flow_state": {
        "min_events": 4,
        "min_detections": 2,
        "checks": [
            {"transport": {"handshake": "SYN"}, "flow": {"state": "HANDSHAKE"}},
            {"transport": {"layer": "TCP"}},
        ],
        "detection_checks": [
            {
                "sid": 1100062,
                "packet_id": 1,
                "direction": "forward",
                "flow_state": "HANDSHAKE",
                "msg": "connection not established yet",
            },
            {
                "sid": 1100061,
                "packet_id": 4,
                "flow_state": "ESTABLISHED",
                "matched": {"contents": [{"content": "HELLO", "offset": 0, "length": 5}]},
            },
        ],
        "forbidden_detections": [
            {"sid": 1100061, "packet_id": 1},
            {"sid": 1100062, "packet_id": 4},
        ],
        "description": "Trạng thái flow: not_established khớp SYN, established chỉ khớp sau bắt tay",
        "criteria": (
            "Rule flow:not_established alert đúng packet SYN đầu tiên (flow_state HANDSHAKE) "
            "và không alert các packet sau; rule flow:to_server,established chứa 'HELLO' chỉ "
            "alert packet 4 khi flow đã ESTABLISHED qua bắt tay ba bước."
        ),
    },
    "bt3_t09_content_nocase": {
        "min_events": 2,
        "min_detections": 3,
        "checks": [{"application": {"protocol": "HTTP"}}],
        "detection_checks": [
            {
                "sid": 1100071,
                "packet_id": 1,
                "matched": {"contents": [{"content": "admin", "nocase": True, "offset": 11, "length": 5}]},
            },
            {
                "sid": 1100072,
                "packet_id": 2,
                "matched": {"contents": [{"content": "ADMIN", "nocase": False, "offset": 11}]},
            },
        ],
        "forbidden_detections": [{"sid": 1100072, "packet_id": 1}],
        "description": "nocase khớp không phân biệt hoa thường, content thường phải khớp đúng byte",
        "criteria": (
            "Payload chứa 'AdMiN' chỉ khớp rule nocase 1100071; payload chứa 'ADMIN' khớp cả "
            "rule nocase 1100071 lẫn rule phân biệt hoa thường 1100072; rule 1100072 không "
            "được alert trên packet 1 (vị trí match offset 11, length 5)."
        ),
    },
    "bt3_t10_offset_depth": {
        "min_events": 1,
        "min_detections": 1,
        "checks": [{"transport": {"layer": "TCP", "payload_len": 35}}],
        "detection_checks": [
            {
                "sid": 1100081,
                "matched": {"contents": [{"content": "MALWARE", "offset": 28, "length": 7, "nocase": False}]},
            }
        ],
        "forbidden_detections": [{"sid": 1100082}],
        "description": "Cửa sổ tuyệt đối offset/depth giới hạn phạm vi tìm content",
        "criteria": (
            "Rule offset:28 depth:7 khớp 'MALWARE' đúng vị trí 28 trong payload 35 byte; rule "
            "offset:0 depth:10 không khớp vì cửa sổ [0,10) không chứa 'MALWARE'."
        ),
    },
    "bt3_t11_distance_within": {
        "min_events": 1,
        "min_detections": 1,
        "checks": [{"transport": {"layer": "TCP", "payload_len": 10}}],
        "detection_checks": [
            {
                "sid": 1100091,
                "matched": {"contents": [{"content": "aa", "offset": 2}, {"content": "bb", "offset": 6}]},
            }
        ],
        "forbidden_detections": [{"sid": 1100092}],
        "description": "Cửa sổ tương đối distance/within tính từ match trước đó",
        "criteria": (
            "Payload 'XXaaYYbbZZ': rule content 'aa' rồi 'bb' với distance:2 within:2 khớp "
            "(aa tại offset 2, bb tại offset 6); rule with within:1 chỉ mở cửa sổ 1 byte sau "
            "distance nên không khớp."
        ),
    },
    "bt3_t12_flags_dsize": {
        "min_events": 2,
        "min_detections": 2,
        "checks": [
            {"transport": {"layer": "TCP", "flags": ["PSH", "ACK"], "payload_len": 20}},
            {"transport": {"layer": "TCP", "flags": ["FIN"], "payload_len": 0}},
        ],
        "detection_checks": [
            {"sid": 1100101, "packet_id": 1, "matched": {"fields": ["flags:PA", "dsize:>10"]}},
            {"sid": 1100103, "packet_id": 2, "matched": {"fields": ["flags:F", "dsize:0"]}},
        ],
        "forbidden_detections": [{"sid": 1100102}],
        "description": "flags (tập chữ cái) và dsize (so sánh kích thước payload)",
        "criteria": (
            "Packet PSH-ACK payload 20 byte khớp rule flags:PA dsize:>10 nhưng không khớp rule "
            "dsize:<10; packet FIN không payload khớp rule flags:F dsize:0."
        ),
    },
    "bt3_t13_multi_rule_match": {
        "min_events": 4,
        "min_detections": 3,
        "checks": [{"application": {"protocol": "HTTP", "type": "request"}}],
        "detection_checks": [
            {"sid": 1100111, "packet_id": 4, "msg": "http post seen"},
            {
                "sid": 1100112,
                "packet_id": 4,
                "matched": {"fields": ["flow:to_server,established", "flags:PA", "dsize:>0"]},
            },
            {"sid": 1100113, "packet_id": 4, "matched": {"contents": [{"content": "/login"}]}},
        ],
        "forbidden_detections": [
            {"sid": 1100111, "packet_id": 1},
            {"sid": 1100112, "packet_id": 1},
            {"sid": 1100113, "packet_id": 1},
        ],
        "description": "Mặc định không dừng ở match đầu: một packet khớp cả ba rule",
        "criteria": (
            "Packet POST /login khớp đồng thời ba rule (content 'POST', POST+flow+flags+dsize "
            "và '/login') và cả ba detection đều được sinh cho packet 4; các packet bắt tay "
            "không sinh detection nào."
        ),
    },
    "bt3_t14_detection_event": {
        "min_events": 4,
        "min_flows": 1,
        "min_detections": 1,
        "checks": [{"application": {"protocol": "HTTP", "type": "request"}}],
        "flow_checks": [
            {
                "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
                "application_protocol": "HTTP",
                "state": "ESTABLISHED",
                "packet_count": 4,
            }
        ],
        "detection_checks": [
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
                    "contents": [{"content": "/etc/passwd", "offset": 7, "length": 11, "nocase": True}],
                    "fields": ["flow:to_server,established", "flags:PA", "dsize:>0"],
                },
                "rule_file": "TEST/BT3/t14_detection_event/test.rules",
            }
        ],
        "forbidden_detections": [
            {"sid": 1100121, "direction": "backward"},
            {"sid": 1100121, "packet_id": 1},
        ],
        "description": "Detection Event đầy đủ trường theo mục 5 của đề bài",
        "criteria": (
            "Detection cho packet 4 chứa đủ thông tin: timestamp (1700000000.3), sid/rev/msg, "
            "classtype attempted-admin, priority 1, 5-tuple, protocol TCP/HTTP, direction "
            "forward, flow_id/flow_state, thông tin match (content /etc/passwd offset 7 kèm "
            "các field flow/flags/dsize) và file rule nguồn."
        ),
    },
}


def _subset_match(actual, expected) -> bool:
    """Return True when expected is contained in actual.

    Dict: every expected key must match recursively.
    List: each expected element must match at least one actual element;
    an empty expected list means the actual list must also be empty.
    """
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return all(
            key in actual and _subset_match(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return False
        if not expected:
            return actual == []
        return all(any(_subset_match(item, exp) for item in actual) for exp in expected)
    return actual == expected


def _matches_any(events, expected) -> bool:
    return any(_subset_match(event, expected) for event in events)


def _read_jsonl(path: str) -> list:
    """Read a JSON Lines file into a list of records (empty when missing)."""
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _case_dir(case_name: str) -> str:
    """Directory holding a case's artifacts.

    Cases are grouped per assignment: ``test_*`` under ``TEST/BT1/``,
    ``bt2_*`` under ``TEST/BT2/`` and ``bt3_*`` under ``TEST/BT3/`` with the
    ``bt3_`` prefix stripped from the directory name
    (``bt3_t01_rule_loader`` -> ``TEST/BT3/t01_rule_loader``).
    """
    if case_name.startswith("bt3_"):
        return os.path.join("TEST", "BT3", case_name[len("bt3_"):])
    if case_name.startswith("bt2_"):
        return os.path.join("TEST", "BT2", case_name)
    return os.path.join("TEST", "BT1", case_name)


def _resolve_paths(case_name: str, spec: dict):
    """Return (case_dir, pcap, output, flows, detections, result, temp_dir).

    Assignment 1 cases keep their artifacts untouched: their flow records are
    written to a temporary directory because those cases do not assert flows.
    """
    case_dir = _case_dir(case_name)
    pcap_path = os.path.join(case_dir, spec.get("pcap", "test.pcap"))
    output_path = os.path.join(case_dir, "output.jsonl")
    if case_name.startswith(("bt2_", "bt3_")):
        return (
            case_dir,
            pcap_path,
            output_path,
            os.path.join(case_dir, "flows.jsonl"),
            os.path.join(case_dir, "detections.jsonl"),
            os.path.join(case_dir, "result.json"),
            None,
        )
    temp_dir = tempfile.mkdtemp(prefix="ids_flows_")
    return (
        case_dir,
        pcap_path,
        output_path,
        os.path.join(temp_dir, "flows.jsonl"),
        os.path.join(temp_dir, "detections.jsonl"),
        os.path.join(temp_dir, "result.json"),
        temp_dir,
    )


def _run_rules_case(case_name: str, spec: dict, case_dir: str, result_path: str) -> int:
    """Run a rules-only BT3 case through tests/rule_case.py and write report.md."""
    rules_path = os.path.join(case_dir, spec.get("rules", "test.rules"))
    report_path = os.path.join(case_dir, "report.md")

    if not os.path.isfile(rules_path):
        print(f"[!] Error: {rules_path} not found.")
        return 1

    cmd = [
        sys.executable,
        "-m",
        "tests.rule_case",
        rules_path,
        result_path,
        json.dumps(spec.get("probes", [])),
        json.dumps(spec.get("loader", {})),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] rule_case.py failed on {case_name}:\n{res.stderr}")
        return res.returncode

    with open(result_path, "r", encoding="utf-8") as handle:
        result = json.load(handle)

    checks = spec["checks"]
    failures = [
        f"Không kết quả nào khớp kỳ vọng #{idx}: {json.dumps(check, ensure_ascii=False)}"
        for idx, check in enumerate(checks, start=1)
        if not _matches_any([result], check)
    ]

    status = "PASS (Thành công)" if not failures else "FAIL (Thất bại)"
    result_lines = (
        "\n".join(f"- {line}" for line in failures)
        if failures
        else "- Tất cả kỳ vọng kiểm thử đều khớp với kết quả thực tế."
    )
    stats = result.get("stats", {})

    report_content = f"""# Test Case Report: {case_name}

- **Mục tiêu**: {spec["description"]}
- **Yêu cầu kiểm thử**: {spec["criteria"]}
- **File Rules**: `{rules_path}`
- **File Kết quả**: `{result_path}`
- **Thống kê nạp rule**: files={stats.get("files_loaded", 0)} valid={stats.get("valid", 0)} invalid={stats.get("invalid", 0)} unsupported={stats.get("unsupported", 0)}
- **Trạng thái**: **{status}**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
{res.stdout.strip()}
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Danh sách JSON subset bắt buộc phải khớp:
```json
{json.dumps(checks, indent=2, ensure_ascii=False)}
```

## 3. Đánh giá tính đúng đắn
{result_lines}
- Chương trình kết thúc bình thường (exit code 0), không crash.
- Kết quả nạp rule tuân thủ đúng mô hình valid / invalid / unsupported của đề bài.

## 4. Kết quả nạp rule (result.json)
```json
{json.dumps(result, ensure_ascii=False, indent=2)}
```
"""
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"[+] Case {case_name}: {status}. Report written to {report_path}")
    return 0 if not failures else 1


def run_case(case_name: str, description: str, verification_criteria: str) -> int:
    spec = EXPECTATIONS.get(case_name)
    kind = (spec or {}).get("kind", "engine")
    (
        case_dir,
        pcap_path,
        output_path,
        flows_path,
        detections_path,
        result_path,
        temp_dir,
    ) = _resolve_paths(case_name, spec or {})
    report_path = os.path.join(case_dir, "report.md")

    if kind == "rules":
        return _run_rules_case(case_name, spec, case_dir, result_path)

    if not os.path.isfile(pcap_path):
        print(f"[!] Error: {pcap_path} not found.")
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return 1

    try:
        # BT3 engine cases always carry a rules file (default name test.rules).
        rules_file = spec.get("rules", "test.rules") if case_name.startswith("bt3_") and spec else None

        # Run main.py on the pcap
        cmd = [
            sys.executable,
            "main.py",
            "--pcap",
            pcap_path,
            "--output",
            output_path,
            "--flows-output",
            flows_path,
        ]
        if rules_file:
            cmd += [
                "--rules",
                os.path.join(case_dir, rules_file),
                "--detections-output",
                detections_path,
            ]
        cmd += list(spec.get("args", []) if spec else [])
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[!] main.py failed on {case_name}:\n{res.stderr}")
            return res.returncode

        events = _read_jsonl(output_path)
        flows = _read_jsonl(flows_path)
        detections = _read_jsonl(detections_path) if rules_file else []

        # Verify registered assertions
        failures = []
        min_flows = None
        flow_checks = []
        if spec is None:
            failures.append(f"Chưa đăng ký kỳ vọng kiểm thử cho case '{case_name}'.")
            checks = []
            min_events = 0
        else:
            checks = spec["checks"]
            min_events = spec["min_events"]
            if len(events) < min_events:
                failures.append(f"Cần tối thiểu {min_events} event, thực tế {len(events)}.")
            for idx, check in enumerate(checks, start=1):
                if not _matches_any(events, check):
                    failures.append(
                        f"Không event nào khớp kỳ vọng #{idx}: "
                        f"{json.dumps(check, ensure_ascii=False)}"
                    )

            min_flows = spec.get("min_flows")
            if min_flows is not None and len(flows) < min_flows:
                failures.append(f"Cần tối thiểu {min_flows} flow record, thực tế {len(flows)}.")
            flow_checks = spec.get("flow_checks", [])
            for idx, check in enumerate(flow_checks, start=1):
                if not _matches_any(flows, check):
                    failures.append(
                        f"Không flow nào khớp kỳ vọng #{idx}: "
                        f"{json.dumps(check, ensure_ascii=False)}"
                    )

            min_detections = spec.get("min_detections")
            if min_detections is not None and len(detections) < min_detections:
                failures.append(
                    f"Cần tối thiểu {min_detections} detection, thực tế {len(detections)}."
                )
            detection_checks = spec.get("detection_checks", [])
            for idx, check in enumerate(detection_checks, start=1):
                if not _matches_any(detections, check):
                    failures.append(
                        f"Không detection nào khớp kỳ vọng #{idx}: "
                        f"{json.dumps(check, ensure_ascii=False)}"
                    )
            forbidden_detections = spec.get("forbidden_detections", [])
            for idx, check in enumerate(forbidden_detections, start=1):
                if _matches_any(detections, check):
                    failures.append(
                        f"Detection vi phạm kỳ vọng cấm #{idx}: "
                        f"{json.dumps(check, ensure_ascii=False)}"
                    )

        status = "PASS (Thành công)" if not failures else "FAIL (Thất bại)"
        result_lines = (
            "\n".join(f"- {line}" for line in failures)
            if failures
            else "- Tất cả kỳ vọng kiểm thử đều khớp với output thực tế."
        )

        flow_header = ""
        flow_assertions = ""
        flow_section = ""
        is_bt2 = case_name.startswith("bt2_")
        is_bt3 = case_name.startswith("bt3_")
        if is_bt2 or (is_bt3 and flow_checks):
            flow_header = (
                f"- **File Flow Records**: `{flows_path}`\n"
                f"- **Số flow record**: {len(flows)}"
            )
            if is_bt3:
                flow_header += "\n"
            flow_assertions = f"""- Số flow tối thiểu: **{min_flows if min_flows is not None else 0}**
- Danh sách flow subset bắt buộc phải khớp:
```json
{json.dumps(flow_checks, indent=2, ensure_ascii=False)}
```"""
            flow_section = f"""
## 5. Flow Records (flows.jsonl)
- **Số flow record**: {len(flows)}
- **Số flow tối thiểu**: {min_flows if min_flows is not None else 0}
- **Kỳ vọng flow (JSON subset)**:
```json
{json.dumps(flow_checks, indent=2, ensure_ascii=False)}
```
- **Chi tiết flow records**:
```json
{json.dumps(flows, indent=2, ensure_ascii=False)}
```
"""

        detection_header = ""
        detection_assertions = ""
        detection_section = ""
        if rules_file:
            detection_header = (
                f"- **File Detections**: `{detections_path}`\n"
                f"- **Số detection**: {len(detections)}\n"
            )
            detection_assertions = f"""- Số detection tối thiểu: **{min_detections if min_detections is not None else 0}**
- Danh sách detection subset bắt buộc phải khớp:
```json
{json.dumps(detection_checks, indent=2, ensure_ascii=False)}
```
- Danh sách detection bị cấm (không được xuất hiện):
```json
{json.dumps(forbidden_detections, indent=2, ensure_ascii=False)}
```"""
            detection_section = f"""
## 6. Detection Events (detections.jsonl)
- **Số detection**: {len(detections)}
- **Số detection tối thiểu**: {min_detections if min_detections is not None else 0}
- **Kỳ vọng detection (JSON subset bắt buộc khớp)**:
```json
{json.dumps(detection_checks, indent=2, ensure_ascii=False)}
```
- **Kỳ vọng detection bị cấm**:
```json
{json.dumps(forbidden_detections, indent=2, ensure_ascii=False)}
```
- **Chi tiết detection records**:
```json
{json.dumps(detections, indent=2, ensure_ascii=False)}
```
"""

        # Write report.md
        report_content = f"""# Test Case Report: {case_name}

- **Mục tiêu**: {description}
- **Yêu cầu kiểm thử**: {verification_criteria}
- **File PCAP**: `{pcap_path}`
- **File Output JSONL**: `{output_path}`
{flow_header}{detection_header}- **Số gói tin đã xử lý**: {len(events)}
- **Trạng thái**: **{status}**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
{res.stdout.strip()}
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **{min_events}**
- Danh sách JSON subset bắt buộc phải khớp:
```json
{json.dumps(checks, indent=2, ensure_ascii=False)}
```
{flow_assertions}
{detection_assertions}

## 3. Đánh giá tính đúng đắn
{result_lines}
- Chương trình kết thúc bình thường (exit code 0), không crash.
- Cấu trúc dữ liệu đầu ra tuân thủ đúng định dạng JSON chuẩn hóa của đề bài.

## 4. Chi tiết Normalized Events (JSON)
```json
{json.dumps(events, indent=2, ensure_ascii=False)}
```
{flow_section}{detection_section}"""
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        print(f"[+] Case {case_name}: {status}. Report written to {report_path}")
        return 0 if not failures else 1
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def run_all(prefix: str = None) -> int:
    """Run every case that registers a description and criteria.

    ``prefix`` optionally restricts the run to cases whose name starts with it
    (e.g. ``bt3`` for the core engine assignment).
    """
    selected = [
        case
        for case, spec in EXPECTATIONS.items()
        if spec.get("description") and spec.get("criteria")
        and (not prefix or case.startswith(prefix))
    ]
    if not selected:
        print("No cases registered.")
        return 0

    failed = []
    for case in selected:
        spec = EXPECTATIONS[case]
        if run_case(case, spec["description"], spec["criteria"]) != 0:
            failed.append(case)

    print("-" * 60)
    print(f"[+] {len(selected) - len(failed)}/{len(selected)} cases PASS")
    if failed:
        print(f"[!] FAILED cases: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "all":
        sys.exit(run_all(prefix=sys.argv[2] if len(sys.argv) > 2 else None))
    if len(sys.argv) < 4:
        print("Usage: python run_case.py <case_name> <description> <criteria>")
        print("       python run_case.py all [case_prefix]")
        sys.exit(1)
    sys.exit(run_case(sys.argv[1], sys.argv[2], sys.argv[3]))
