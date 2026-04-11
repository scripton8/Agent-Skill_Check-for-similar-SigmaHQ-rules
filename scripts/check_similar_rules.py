#!/usr/bin/env python3
"""
Check for Similar SigmaHQ Rules
================================
Scans the repository's Sigma detection rules and compares them against a new
detection idea described in a GitHub issue or pull request. Posts the results
as a comment on the issue/PR.

Usage (GitHub Actions):
    The script reads event data from $GITHUB_EVENT_PATH and posts a comment
    using the $GITHUB_TOKEN.  The following environment variables must be set:
        GITHUB_TOKEN   - GitHub personal access token or Actions token
        EVENT_NAME     - GitHub event name (issues / pull_request)
        REPO           - Repository in "owner/name" format
        SERVER_URL     - GitHub server URL (e.g. https://github.com)
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    print("PyYAML is required. Install it with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Directories searched for Sigma rules (in order of preference)
RULES_DIRECTORIES: List[str] = [
    "rules",
    "detections",
    "detection",
    "sigma",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting",
]

# Minimum similarity score for a rule to be included in results (0–1)
MIN_SIMILARITY_SCORE: float = 0.05

# Maximum number of results to show
MAX_RESULTS: int = 10

# Words that carry no discriminating meaning and are ignored during matching
STOP_WORDS: frozenset = frozenset(
    {
        "the", "and", "for", "are", "this", "that", "with", "from", "have",
        "has", "not", "will", "can", "all", "any", "but", "was", "been",
        "being", "its", "our", "your", "their", "into", "then", "than",
        "when", "where", "what", "which", "who", "how", "use", "used",
        "using", "should", "could", "would", "may", "might", "must",
        "shall", "also", "such", "more", "some", "other", "new", "each",
        "both", "only", "very", "just", "even", "most", "over", "after",
        "before", "about", "above", "below", "between", "through", "upon",
        "these", "those", "they", "them", "there", "here", "via", "per",
        "type", "value", "true", "false", "null", "none", "rule", "rules",
        "detect", "detects", "detection", "sigma", "log", "logs",
    }
)

# ---------------------------------------------------------------------------
# Keyword extraction
# ---------------------------------------------------------------------------


def extract_keywords(text: str) -> Dict[str, int]:
    """Return a frequency map of meaningful keywords extracted from *text*."""
    if not text:
        return {}

    text = text.lower()

    # Tokenise: keep alphanumeric runs including underscores and hyphens
    tokens = re.findall(r"[a-z][a-z0-9_\-]{2,}", text)

    freq: Dict[str, int] = {}
    for token in tokens:
        # Also record individual parts split on _ and -
        parts = [p for p in re.split(r"[_\-]", token) if len(p) > 2]
        candidates = [token] + parts
        for word in candidates:
            if word not in STOP_WORDS:
                freq[word] = freq.get(word, 0) + 1

    return freq


# ---------------------------------------------------------------------------
# Sigma rule parsing
# ---------------------------------------------------------------------------


def _collect_strings(obj, accumulator: List[str]) -> None:
    """Recursively collect all string values from a nested dict/list."""
    if isinstance(obj, dict):
        for value in obj.values():
            _collect_strings(value, accumulator)
    elif isinstance(obj, list):
        for item in obj:
            _collect_strings(item, accumulator)
    elif obj is not None:
        accumulator.append(str(obj))


def extract_rule_text(rule: Dict) -> str:
    """Return a single string containing all searchable text for *rule*."""
    parts: List[str] = []

    for field in ("title", "description", "author"):
        val = rule.get(field)
        if val:
            parts.append(str(val))

    tags = rule.get("tags") or []
    parts.extend(str(t) for t in tags)

    logsource = rule.get("logsource") or {}
    _collect_strings(logsource, parts)

    detection = rule.get("detection") or {}
    _collect_strings(detection, parts)

    refs = rule.get("references") or []
    parts.extend(str(r) for r in refs)

    fps = rule.get("falsepositives") or []
    parts.extend(str(f) for f in fps)

    return " ".join(parts)


def parse_sigma_rule(file_path: Path, repo_root: Path) -> Optional[Dict]:
    """Parse a YAML file and return a rule dict if it looks like a Sigma rule."""
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as fh:
            content = yaml.safe_load(fh)
    except Exception:
        return None

    if not isinstance(content, dict):
        return None

    # A Sigma rule must have at least a title or a detection block
    if not content.get("title") and "detection" not in content:
        return None

    try:
        relative_path = str(file_path.relative_to(repo_root))
    except ValueError:
        relative_path = str(file_path)

    return {
        "title": content.get("title") or "Unknown Rule",
        "id": content.get("id") or "",
        "description": content.get("description") or "",
        "status": content.get("status") or "",
        "tags": content.get("tags") or [],
        "detection": content.get("detection") or {},
        "logsource": content.get("logsource") or {},
        "author": content.get("author") or "",
        "references": content.get("references") or [],
        "falsepositives": content.get("falsepositives") or [],
        "file_path": relative_path,
    }


def find_sigma_rules(repo_root: Path) -> List[Path]:
    """Return paths to all Sigma rule YAML files in the repository."""
    found: List[Path] = []

    # Prefer dedicated rule directories
    for directory in RULES_DIRECTORIES:
        rules_dir = repo_root / directory
        if rules_dir.is_dir():
            for ext in ("*.yml", "*.yaml"):
                found.extend(rules_dir.rglob(ext))

    # Fall back: scan the whole repository, skipping .github
    if not found:
        for ext in ("*.yml", "*.yaml"):
            for candidate in repo_root.rglob(ext):
                rel = candidate.relative_to(repo_root)
                if ".github" not in rel.parts:
                    found.append(candidate)

    # Deduplicate while preserving order
    seen = set()
    unique: List[Path] = []
    for p in found:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def load_all_rules(repo_root: Path) -> List[Dict]:
    """Find and parse all Sigma rules in *repo_root*."""
    rule_files = find_sigma_rules(repo_root)
    rules: List[Dict] = []
    for path in rule_files:
        rule = parse_sigma_rule(path, repo_root)
        if rule:
            rules.append(rule)
    return rules


# ---------------------------------------------------------------------------
# Similarity scoring
# ---------------------------------------------------------------------------


def calculate_similarity(query_keywords: Dict[str, int], rule: Dict) -> float:
    """
    Return a similarity score in [0, 1] between *query_keywords* and *rule*.

    The score is a Jaccard index over keyword sets, with additional boosts
    when query keywords appear in the rule's title or description.
    """
    if not query_keywords:
        return 0.0

    rule_text = extract_rule_text(rule)
    rule_keywords = extract_keywords(rule_text)

    if not rule_keywords:
        return 0.0

    query_set = set(query_keywords)
    rule_set = set(rule_keywords)

    intersection = query_set & rule_set
    union = query_set | rule_set

    if not union:
        return 0.0

    score = len(intersection) / len(union)

    # Boost: query terms that appear in the title are a stronger signal
    title_keywords = extract_keywords(rule.get("title") or "")
    title_overlap = query_set & set(title_keywords)
    if title_overlap:
        score += (len(title_overlap) / max(len(query_set), 1)) * 0.3

    # Smaller boost for description overlap
    desc_keywords = extract_keywords(rule.get("description") or "")
    desc_overlap = query_set & set(desc_keywords)
    if desc_overlap:
        score += (len(desc_overlap) / max(len(query_set), 1)) * 0.1

    return score


def find_similar_rules(
    query_text: str, rules: List[Dict]
) -> List[Tuple[Dict, float]]:
    """Return up to MAX_RESULTS rules from *rules* most similar to *query_text*."""
    query_keywords = extract_keywords(query_text)
    scored: List[Tuple[Dict, float]] = []

    for rule in rules:
        score = calculate_similarity(query_keywords, rule)
        if score >= MIN_SIMILARITY_SCORE:
            scored.append((rule, score))

    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:MAX_RESULTS]


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _file_url(file_path: str, repo: str, server_url: str) -> str:
    """Return a browser URL pointing to *file_path* on GitHub."""
    normalized = file_path.replace("\\", "/")
    return f"{server_url}/{repo}/blob/main/{normalized}"


def format_comment(
    similar_rules: List[Tuple[Dict, float]],
    repo: str,
    server_url: str,
) -> str:
    """Build the Markdown body for the GitHub comment."""
    lines = [
        "## 🔍 Similar Sigma Rules Check",
        "",
        "_This automated check scans the repository's Sigma detection rules for "
        "matches related to the content of this issue/PR._",
        "",
    ]

    if not similar_rules:
        lines += [
            "**No similar Sigma rules were found** in this repository that match "
            "the described detection idea.",
            "",
            "This may mean:",
            "- The detection idea covers a new, unique threat scenario not yet detected",
            "- The described technique or tool has no existing coverage in the current ruleset",
            "",
            "> 💡 This is a great opportunity to create a new Sigma rule covering this gap!",
        ]
    else:
        lines += [
            f"Found **{len(similar_rules)}** potentially related rule(s) in this repository:",
            "",
            "| Rule Name | Rule ID | Description | Link |",
            "|-----------|---------|-------------|------|",
        ]

        for rule, _score in similar_rules:
            title = (rule.get("title") or "Unknown").replace("|", "\\|")
            rule_id = rule.get("id") or "N/A"
            description = (rule.get("description") or "No description available").replace(
                "\n", " "
            )
            if len(description) > 150:
                description = description[:147] + "…"
            description = description.replace("|", "\\|")

            url = _file_url(rule["file_path"], repo, server_url)
            lines.append(f"| {title} | `{rule_id}` | {description} | [View Rule]({url}) |")

        lines += [
            "",
            "> 💡 **Review these rules** to determine if any fully cover the described "
            "detection, or if any could be **extended** to include it.",
        ]

    lines += [
        "",
        "---",
        "<sub>🤖 Generated by the "
        "[Check for Similar Sigma Rules]"
        "(.github/skills/check-similar-sigma-rules/SKILL.md) agent skill</sub>",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# GitHub API interaction
# ---------------------------------------------------------------------------


def post_comment(
    body: str, issue_number: int, repo: str, token: str
) -> None:
    """Post *body* as a comment on issue/PR *issue_number* in *repo*."""
    if not token:
        print("GITHUB_TOKEN not set – printing comment to stdout instead.")
        print(body)
        return

    api_url = f"https://api.github.com/repos/{repo}/issues/{issue_number}/comments"
    payload = json.dumps({"body": body}).encode()

    req = urllib.request.Request(
        api_url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read().decode())
            print(f"Comment posted: {result.get('html_url', '(no URL)')}")
    except urllib.error.HTTPError as exc:
        print(
            f"Failed to post comment: HTTP {exc.code}: {exc.read().decode()}",
            file=sys.stderr,
        )
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"Failed to post comment: {exc}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _read_event() -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """
    Read issue/PR data from the GitHub Actions event payload file.

    Returns (title, body, number).
    """
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path or not os.path.isfile(event_path):
        return None, None, None

    with open(event_path, encoding="utf-8") as fh:
        event = json.load(fh)

    for key in ("issue", "pull_request"):
        obj = event.get(key)
        if obj:
            return (
                obj.get("title") or "",
                obj.get("body") or "",
                int(obj["number"]),
            )

    return None, None, None


def main() -> None:
    repo = os.environ.get("REPO", "")
    server_url = os.environ.get("SERVER_URL", "https://github.com")
    token = os.environ.get("GITHUB_TOKEN", "")
    repo_root = Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve()

    title, body, issue_number = _read_event()

    if not title and not body:
        print("No issue/PR content found – nothing to compare.", file=sys.stderr)
        sys.exit(0)

    query_text = f"{title}\n\n{body}"
    print(f"Query preview: {query_text[:300]!r}")

    print("Loading Sigma rules…")
    rules = load_all_rules(repo_root)
    print(f"  Parsed {len(rules)} rule(s)")

    print("Scoring rules…")
    similar = find_similar_rules(query_text, rules)
    print(f"  {len(similar)} rule(s) above threshold {MIN_SIMILARITY_SCORE}")

    comment = format_comment(similar, repo, server_url)
    print("\n--- Comment preview ---")
    print(comment)
    print("--- End preview ---\n")

    if issue_number and repo:
        post_comment(comment, issue_number, repo, token)
    else:
        print("No issue number or repo available – skipping comment post.")


if __name__ == "__main__":
    main()
