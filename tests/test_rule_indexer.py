"""Unit tests cho Rule Repository / Indexer (core.indexer)."""

import unittest

from core.indexer import RuleRepository
from core.parser import RuleParser


def build_repo(*rules_text: str) -> RuleRepository:
    repo = RuleRepository()
    for text in rules_text:
        outcome = RuleParser.parse(text, "test.rules", 1)
        assert outcome.ok, outcome.reason
        repo.add(outcome.rule)
    return repo


def sids(rules) -> list:
    return sorted(rule.sid for rule in rules)


class TestExactPortIndex(unittest.TestCase):
    def setUp(self):
        self.repo = build_repo(
            'alert tcp any any -> any 80 (msg:"http"; sid:1;)',
            'alert tcp any 53 -> any any (msg:"dns-src"; sid:2;)',
            'alert udp any any -> any 53 (msg:"dns-dst"; sid:3;)',
        )

    def test_dst_port_uni_rule(self):
        found = self.repo.candidates("TCP", "10.0.0.1", 50000, "10.0.0.2", 80)
        self.assertEqual(sids(found), [1])

    def test_src_port_uni_rule(self):
        found = self.repo.candidates("TCP", "10.0.0.1", 53, "10.0.0.2", 50000)
        self.assertEqual(sids(found), [2])

    def test_reversed_uni_rule_is_not_candidate(self):
        # Rule "any 53 -> any any" là một chiều: packet đi ngược lại không khớp.
        found = self.repo.candidates("TCP", "10.0.0.1", 50000, "10.0.0.2", 53)
        self.assertEqual(found, [])

    def test_protocol_separation(self):
        found = self.repo.candidates("UDP", "10.0.0.1", 50000, "10.0.0.2", 53)
        self.assertEqual(sids(found), [3])

    def test_unrelated_event_returns_empty(self):
        found = self.repo.candidates("TCP", "10.0.0.1", 50000, "10.0.0.2", 8080)
        self.assertEqual(found, [])


class TestAnyAndRangeIndex(unittest.TestCase):
    def test_any_port_rule(self):
        repo = build_repo('alert tcp any any -> any any (msg:"all"; sid:4;)')
        self.assertEqual(sids(repo.candidates("TCP", "10.0.0.1", 1, "10.0.0.2", 2)), [4])
        self.assertEqual(repo.candidates("UDP", "10.0.0.1", 1, "10.0.0.2", 2), [])

    def test_closed_range(self):
        repo = build_repo('alert tcp any any -> any 1024:2048 (msg:"range"; sid:5;)')
        self.assertEqual(sids(repo.candidates("TCP", "10.0.0.1", 50000, "10.0.0.2", 1500)), [5])
        self.assertEqual(repo.candidates("TCP", "10.0.0.1", 50000, "10.0.0.2", 80), [])

    def test_open_ended_range(self):
        repo = build_repo('alert tcp any any -> any 1024: (msg:"high"; sid:6;)')
        self.assertEqual(sids(repo.candidates("TCP", "10.0.0.1", 1, "10.0.0.2", 50000)), [6])
        self.assertEqual(repo.candidates("TCP", "10.0.0.1", 1, "10.0.0.2", 80), [])

    def test_bidirectional_rule_matches_both_orientations(self):
        repo = build_repo('alert tcp any any <> any 80 (msg:"bidi"; sid:7;)')
        forward = repo.candidates("TCP", "10.0.0.1", 50000, "10.0.0.2", 80)
        backward = repo.candidates("TCP", "10.0.0.2", 80, "10.0.0.1", 50000)
        self.assertEqual(sids(forward), [7])
        self.assertEqual(sids(backward), [7])


class TestIPFilter(unittest.TestCase):
    def test_cidr_and_single_ip(self):
        repo = build_repo(
            'alert tcp 10.0.0.0/8 any -> 192.168.1.0/24 80 (msg:"cidr"; sid:8;)',
            'alert tcp any any -> 203.0.113.5 any (msg:"single"; sid:9;)',
        )
        found = repo.candidates("TCP", "10.1.2.3", 50000, "192.168.1.20", 80)
        self.assertEqual(sids(found), [8])

        found = repo.candidates("TCP", "172.16.0.1", 50000, "203.0.113.5", 443)
        self.assertEqual(sids(found), [9])

    def test_ip_mismatch_excluded(self):
        repo = build_repo(
            'alert tcp 10.0.0.0/8 any -> any 80 (msg:"cidr"; sid:10;)',
        )
        found = repo.candidates("TCP", "172.16.0.1", 50000, "10.0.0.2", 80)
        self.assertEqual(found, [])


class TestRepositoryBehavior(unittest.TestCase):
    def test_candidates_sorted_by_sid(self):
        repo = build_repo(
            'alert tcp any any -> any 80 (msg:"b"; sid:200;)',
            'alert tcp any any -> any 80 (msg:"a"; sid:100;)',
        )
        found = repo.candidates("TCP", "10.0.0.1", 50000, "10.0.0.2", 80)
        self.assertEqual([rule.sid for rule in found], [100, 200])

    def test_no_duplicate_candidates(self):
        # Rule hai chiều với cùng port đơn ở cả hai vế có thể rơi vào nhiều bucket.
        repo = build_repo('alert tcp any 80 <> any 80 (msg:"dup"; sid:11;)')
        found = repo.candidates("TCP", "10.0.0.1", 80, "10.0.0.2", 80)
        self.assertEqual(len(found), 1)

    def test_get_len_and_stats(self):
        repo = build_repo(
            'alert tcp any any -> any 80 (msg:"a"; sid:1;)',
            'alert udp any any -> any 53 (msg:"b"; sid:2;)',
            'alert tcp any any -> any 1024:2048 (msg:"c"; sid:3;)',
        )
        self.assertEqual(len(repo), 3)
        self.assertEqual(repo.get(2).sid, 2)
        self.assertIsNone(repo.get(999))
        stats = repo.stats()
        self.assertEqual(stats["rules"], 3)
        self.assertEqual(stats["protocols"], {"tcp": 2, "udp": 1})
        self.assertEqual(stats["range_buckets"], {"tcp": 1})


if __name__ == "__main__":
    unittest.main()
