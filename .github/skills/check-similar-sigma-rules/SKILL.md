---
name: check-similar-sigma-rules
description: >-
  Checks a repository's existing Sigma detection rules for rules that are similar to or could be
  extended by a new detection idea described in an issue or pull request. Use this skill when
  analyzing detection ideas, new Sigma rules, or security detection requests to find overlapping,
  duplicate, or extensible rules already present in the repository.
---

## Purpose

This skill scans the current repository's Sigma detection rules (`.yml`/`.yaml` files, typically
found in a `rules/` directory) and compares them against a new detection idea or rule described in
an issue or pull request. It helps maintainers avoid duplicating effort and identify rules that can
be extended rather than replaced by a new one.

## When to Use

Invoke this skill when:
- A new detection idea is submitted in an issue
- A new Sigma rule is proposed in a pull request
- You need to check whether an existing rule already covers a described threat scenario
- You need to find rules that could be extended to include a new detection condition (e.g., adding
  another tool to a rule that already detects similar tools)

## Procedure

1. **Extract the detection concept** from the issue or PR title and body, including:
   - Threat actor techniques, tactics, or procedures (TTPs)
   - Specific tools, processes, command-line patterns, or registry paths mentioned
   - Log sources referenced (e.g., Windows Event Log, Sysmon, network logs)
   - MITRE ATT&CK techniques if mentioned (e.g., T1059, T1547)

2. **Scan the repository** for Sigma rule files (`.yml`/`.yaml`) in common locations:
   - `rules/` and all subdirectories
   - `detections/`, `detection/`, `sigma/` if present
   - Root-level YAML files that match the Sigma rule schema

3. **For each Sigma rule found**, extract and compare:
   - Rule `title` and `description`
   - `detection` conditions (keywords, field values, selections)
   - `tags` (especially MITRE ATT&CK tags like `attack.t1059`)
   - `logsource` type, category, and product

4. **Score and rank** rules by relevance to the input using keyword similarity

5. **Output a table** with the top matching rules, including:
   - Rule name/title
   - Rule UUID (`id` field)
   - Description
   - A direct link to the rule file in the repository

## Output Format

If matching rules are found:

| Rule Name | Rule ID | Description | Link |
|-----------|---------|-------------|------|
| [Rule Title] | [UUID] | [Description] | [View Rule] |

> 💡 Review these rules to determine if any fully cover the described detection, or if any could
> be **extended** to include the new detection scenario.

If no matching rules are found:

> **No similar Sigma rules were found** in this repository that match the described detection idea.

## Notes

- Rules are scored using keyword similarity between the input text and rule metadata plus detection
  content
- A minimum similarity threshold is applied to avoid false positives
- Up to 10 of the most relevant rules are returned
- Rules that could be *extended* (e.g., adding a new tool to an existing tool-detection rule) are
  surfaced alongside rules that already fully cover the detection idea
