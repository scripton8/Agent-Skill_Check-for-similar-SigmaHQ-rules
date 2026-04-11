#!/usr/bin/env python3
"""
Unit tests for check_similar_rules.py
"""

import sys
from pathlib import Path

import pytest

# Make the scripts directory importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from check_similar_rules import (  # noqa: E402
    MIN_SIMILARITY_SCORE,
    MAX_RESULTS,
    calculate_similarity,
    extract_keywords,
    extract_rule_text,
    find_similar_rules,
    format_comment,
    _file_url,
)

# ---------------------------------------------------------------------------
# Sample Sigma rules used across multiple tests
# ---------------------------------------------------------------------------

RULE_WMI = {
    "title": "Suspicious Process Creation via WMI",
    "id": "a1b2c3d4-0001-0001-0001-000000000001",
    "description": "Detects suspicious process creation via Windows Management Instrumentation (WMI)",
    "tags": ["attack.execution", "attack.t1047"],
    "detection": {
        "selection": {
            "EventID": 4688,
            "ParentImage|endswith": "WmiPrvSE.exe",
        },
        "condition": "selection",
    },
    "logsource": {"category": "process_creation", "product": "windows"},
    "author": "Test Author",
    "references": [],
    "falsepositives": [],
    "file_path": "rules/windows/process_creation/proc_creation_win_wmi.yml",
}

RULE_MIMIKATZ = {
    "title": "Mimikatz Credential Dumping",
    "id": "a1b2c3d4-0002-0002-0002-000000000002",
    "description": "Detects usage of Mimikatz credential dumping tool by process name",
    "tags": ["attack.credential_access", "attack.t1003"],
    "detection": {
        "selection": {"Image|endswith": "mimikatz.exe"},
        "condition": "selection",
    },
    "logsource": {"category": "process_creation", "product": "windows"},
    "author": "Test Author",
    "references": [],
    "falsepositives": [],
    "file_path": "rules/windows/process_creation/proc_creation_win_mimikatz.yml",
}

RULE_TUNNEL = {
    "title": "Network Tunnelling Tool Usage - Chisel",
    "id": "a1b2c3d4-0003-0003-0003-000000000003",
    "description": "Detects usage of Chisel network tunnelling tool for port forwarding and pivoting",
    "tags": ["attack.command_and_control", "attack.t1572"],
    "detection": {
        "selection": {"Image|endswith": ["chisel.exe", "chisel"]},
        "condition": "selection",
    },
    "logsource": {"category": "process_creation", "product": "windows"},
    "author": "Test Author",
    "references": [],
    "falsepositives": [],
    "file_path": "rules/windows/process_creation/proc_creation_win_chisel.yml",
}

ALL_RULES = [RULE_WMI, RULE_MIMIKATZ, RULE_TUNNEL]


# ---------------------------------------------------------------------------
# extract_keywords
# ---------------------------------------------------------------------------


class TestExtractKeywords:
    def test_returns_dict(self):
        result = extract_keywords("process creation windows")
        assert isinstance(result, dict)

    def test_empty_string_returns_empty(self):
        assert extract_keywords("") == {}

    def test_none_returns_empty(self):
        assert extract_keywords(None) == {}  # type: ignore[arg-type]

    def test_stop_words_filtered(self):
        result = extract_keywords("the and for are this that")
        assert result == {}

    def test_meaningful_keywords_present(self):
        result = extract_keywords("Detects suspicious process creation via WMI Windows")
        assert "suspicious" in result
        assert "process" in result
        assert "creation" in result
        assert "windows" in result
        assert "wmi" in result

    def test_frequency_counted(self):
        result = extract_keywords("mimikatz mimikatz mimikatz")
        assert result.get("mimikatz", 0) >= 3

    def test_hyphenated_token_split(self):
        result = extract_keywords("command-and-control network")
        assert "command" in result or "control" in result

    def test_underscore_token_split(self):
        result = extract_keywords("process_creation event_id")
        assert "process" in result
        assert "event" in result


# ---------------------------------------------------------------------------
# extract_rule_text
# ---------------------------------------------------------------------------


class TestExtractRuleText:
    def test_includes_title(self):
        text = extract_rule_text(RULE_WMI)
        assert "WMI" in text or "wmi" in text.lower()

    def test_includes_description(self):
        text = extract_rule_text(RULE_MIMIKATZ)
        assert "Mimikatz" in text or "mimikatz" in text.lower()

    def test_includes_tags(self):
        text = extract_rule_text(RULE_TUNNEL)
        assert "attack.command_and_control" in text or "command_and_control" in text

    def test_includes_detection_values(self):
        text = extract_rule_text(RULE_TUNNEL)
        assert "chisel" in text.lower()

    def test_includes_logsource(self):
        text = extract_rule_text(RULE_WMI)
        assert "windows" in text.lower()

    def test_empty_rule(self):
        text = extract_rule_text({})
        assert text == ""


# ---------------------------------------------------------------------------
# calculate_similarity
# ---------------------------------------------------------------------------


class TestCalculateSimilarity:
    def test_matching_content_yields_positive_score(self):
        query = extract_keywords("WMI process creation detection windows management")
        score = calculate_similarity(query, RULE_WMI)
        assert score > MIN_SIMILARITY_SCORE

    def test_unrelated_content_yields_low_score(self):
        query = extract_keywords("cooking pasta bolognese recipe ingredients")
        score = calculate_similarity(query, RULE_WMI)
        assert score < 0.15

    def test_empty_query_returns_zero(self):
        assert calculate_similarity({}, RULE_WMI) == 0.0

    def test_score_is_float(self):
        query = extract_keywords("mimikatz credential dumping")
        score = calculate_similarity(query, RULE_MIMIKATZ)
        assert isinstance(score, float)

    def test_title_match_boosts_score(self):
        # Query specifically matches the title words – should be higher than a generic match
        title_query = extract_keywords("Mimikatz Credential Dumping")
        generic_query = extract_keywords("credential access windows")
        title_score = calculate_similarity(title_query, RULE_MIMIKATZ)
        generic_score = calculate_similarity(generic_query, RULE_MIMIKATZ)
        assert title_score >= generic_score


# ---------------------------------------------------------------------------
# find_similar_rules
# ---------------------------------------------------------------------------


class TestFindSimilarRules:
    def test_finds_mimikatz_rule(self):
        results = find_similar_rules("Detect mimikatz credential dumping tool", ALL_RULES)
        titles = [r[0]["title"] for r in results]
        assert any("Mimikatz" in t for t in titles)

    def test_finds_tunnel_rule_for_new_tool(self):
        query = "Detect ligolo-ng tunnelling tool used for network pivoting and port forwarding"
        results = find_similar_rules(query, ALL_RULES)
        titles = [r[0]["title"] for r in results]
        assert any("Tunnel" in t or "tunnel" in t.lower() for t in titles)

    def test_irrelevant_query_returns_empty_or_few(self):
        results = find_similar_rules("chocolate cake baking recipe", ALL_RULES)
        assert len(results) <= 1

    def test_returns_list_of_tuples(self):
        results = find_similar_rules("WMI process creation", ALL_RULES)
        for rule, score in results:
            assert isinstance(rule, dict)
            assert isinstance(score, float)

    def test_results_sorted_descending(self):
        results = find_similar_rules("mimikatz WMI process chisel tunnel", ALL_RULES)
        scores = [s for _, s in results]
        assert scores == sorted(scores, reverse=True)

    def test_max_results_capped(self):
        # Duplicate rules to exceed MAX_RESULTS
        many_rules = ALL_RULES * (MAX_RESULTS + 5)
        results = find_similar_rules("mimikatz WMI chisel tunnelling credential", many_rules)
        assert len(results) <= MAX_RESULTS

    def test_empty_rules_list(self):
        results = find_similar_rules("mimikatz detection", [])
        assert results == []

    def test_each_result_has_score_above_threshold(self):
        results = find_similar_rules("process creation windows", ALL_RULES)
        for _, score in results:
            assert score >= MIN_SIMILARITY_SCORE


# ---------------------------------------------------------------------------
# format_comment
# ---------------------------------------------------------------------------


class TestFormatComment:
    REPO = "owner/test-repo"
    SERVER = "https://github.com"

    def test_no_results_message(self):
        comment = format_comment([], self.REPO, self.SERVER)
        assert "No similar Sigma rules were found" in comment

    def test_results_table_present(self):
        results = [(RULE_WMI, 0.45), (RULE_MIMIKATZ, 0.32)]
        comment = format_comment(results, self.REPO, self.SERVER)
        assert "| Rule Name |" in comment
        assert "| Rule ID |" in comment
        assert "| Description |" in comment
        assert "| Link |" in comment

    def test_rule_titles_in_comment(self):
        results = [(RULE_WMI, 0.45)]
        comment = format_comment(results, self.REPO, self.SERVER)
        assert "Suspicious Process Creation via WMI" in comment

    def test_rule_ids_in_comment(self):
        results = [(RULE_WMI, 0.45)]
        comment = format_comment(results, self.REPO, self.SERVER)
        assert "a1b2c3d4-0001-0001-0001-000000000001" in comment

    def test_view_rule_link_present(self):
        results = [(RULE_WMI, 0.45)]
        comment = format_comment(results, self.REPO, self.SERVER)
        assert "View Rule" in comment
        assert self.REPO in comment

    def test_long_description_truncated(self):
        long_rule = {**RULE_WMI, "description": "A" * 200}
        results = [(long_rule, 0.4)]
        comment = format_comment(results, self.REPO, self.SERVER)
        assert "…" in comment

    def test_header_present(self):
        comment = format_comment([], self.REPO, self.SERVER)
        assert "Similar Sigma Rules Check" in comment

    def test_footer_present(self):
        comment = format_comment([], self.REPO, self.SERVER)
        assert "agent skill" in comment.lower() or "SKILL.md" in comment

    def test_multiple_results_all_in_table(self):
        results = [(r, 0.5 - i * 0.1) for i, r in enumerate(ALL_RULES)]
        comment = format_comment(results, self.REPO, self.SERVER)
        for rule in ALL_RULES:
            assert rule["title"] in comment


# ---------------------------------------------------------------------------
# _file_url helper
# ---------------------------------------------------------------------------


class TestFileUrl:
    def test_basic_url(self):
        url = _file_url("rules/win/test.yml", "owner/repo", "https://github.com")
        assert url == "https://github.com/owner/repo/blob/main/rules/win/test.yml"

    def test_backslash_normalised(self):
        url = _file_url("rules\\win\\test.yml", "owner/repo", "https://github.com")
        assert "rules/win/test.yml" in url
