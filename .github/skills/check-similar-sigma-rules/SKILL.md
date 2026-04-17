---
name: check-similar-sigma-rules
description: >-
  Finds Sigma detections that either already cover a new detection idea or are directly extensible
  with small, concrete changes. Use this skill to avoid broad similarity matches and return only
  high-confidence coverage or extension candidates.
---

## Purpose

This skill scans the current repository's Sigma detection rules (`.yml`/`.yaml` files, typically
found in a `rules/` directory) and compares them against a new detection idea or rule described in
an issue or pull request.

When evaluating or proposing rule changes, always align with the latest SigmaHQ reference guide
and current Sigma rule schema/documentation.

It is intentionally strict: return only detections that either:
- already cover the requested idea, or
- can be extended to cover it with small, concrete, low-risk changes.

Broadly "similar" rules that do not materially help implementation should be excluded.

## When to Use

Invoke this skill when:
- A new detection idea is submitted in an issue
- A new Sigma rule is proposed in a pull request
- You need to check whether an existing rule already covers a described threat scenario
- You need to find rules that could be extended to include a new detection condition (e.g., adding
  another tool to a rule that already detects similar tools)

## Match Requirements

Evaluate each candidate rule across these critical dimensions:
- Detection logic: parent/child relationships, process-chain behavior, correlation, baseline/novelty
- Indicator set: binaries, command-line patterns, paths, registry keys, network indicators
- Field anchor compatibility: the fields needed for new indicators/regex already exist in the rule or are trivially available via existing pipeline mappings
- Telemetry semantics: same event intent (e.g., process creation vs proxy request)
- Logsource compatibility: product/service/category alignment, with tolerance for minor naming differences
- Purpose linkage: candidate rule intent must be logically related to the requested detection objective
- ATT&CK/tags relevance: candidate tags should be overlapping or adjacent in technique/tactic family

### Purpose Linkage Rules

Only keep candidates where the rule purpose is meaningfully related to the requested idea.

Required checks:
- Rule title/description intent overlaps with requested detection objective
- Detection behavior overlaps (not just shared fields)
- ATT&CK tags are overlapping or in a directly related family when available

Automatic rejection conditions:
- Match is based mostly on same logsource, same fields, or generic terms only
- Candidate has different detection objective despite similar data source
- Candidate would introduce unrelated detection branches into the rule

ATT&CK guidance:
- Prefer exact technique/sub-technique overlap (e.g., `attack.t1059.003` to `attack.t1059`)
- Allow closely related techniques only with explicit rationale
- If tags are missing, rely on title/description + detection behavior linkage
- If tags strongly conflict with requested purpose and no behavioral linkage exists, mark `Out of Scope`

### Logsource Compatibility Guidance

Allow slight `logsource` parameter differences when telemetry intent is equivalent.

Examples of acceptable differences:
- Same behavior and event type, but different product/service labels for a custom environment
- Equivalent endpoint process telemetry with renamed data source fields

Examples that are not acceptable:
- Different telemetry class (e.g., proxy/network rule suggested for endpoint process-chain request)
- Rule requires fields not available in the requested data source and would need major redesign

## Procedure

1. **Extract the detection concept** from the issue or PR title and body, including:
   - Threat actor techniques, tactics, or procedures (TTPs)
   - Specific tools, processes, command-line patterns, or registry paths mentioned
   - Log sources referenced (e.g., Windows Event Log, Sysmon, network logs)
   - MITRE ATT&CK techniques if mentioned (e.g., T1059, T1547)

   Before proposing patches or classifying edge cases, consult the latest SigmaHQ reference
   guidance/schema semantics for:
   - valid standard rule keys
   - `detection` syntax and `condition` semantics
   - current best practices for tags, logsource, and field usage

2. **Scan the repository** for Sigma rule files (`.yml`/`.yaml`) in common locations:
   - `rules/` and all subdirectories
   - `detections/`, `detection/`, `sigma/` if present
   - Root-level YAML files that match the Sigma rule schema

   Also scan for Sigma pipeline and backend conversion configuration that affects rule portability:
   - `pipelines/` directory and subdirectories
   - Repository docs/config that define field mappings or event normalization for Sigma conversion

3. **For each Sigma rule found**, extract and compare:
   - Rule `title` and `description`
   - `detection` conditions (keywords, field values, selections)
   - `tags` (especially MITRE ATT&CK tags like `attack.t1059`)
   - `logsource` type, category, and product
   - Pipeline compatibility notes (whether existing pipelines already support required field mapping)

4. **Classify each rule using strict gates**:
   - **Full Coverage**:
     - Core detection logic matches the requested idea
     - Indicator set substantially overlaps
     - Telemetry semantics match
     - Logsource is same or compatible with minor parameter adjustments
   - **Extensible**:
     - Rule purpose is logically related to the requested idea
     - Rule shares the same detection pattern and telemetry semantics
     - ATT&CK/tags are overlapping or reasonably adjacent (or strong behavioral linkage exists when tags are absent)
       - Exact requested regex/literal patterns do not need to already exist in the candidate rule
       - The fields those new regex/literal patterns will target already exist in the rule, or are available through minor existing pipeline field mappings
     - Missing pieces can be added with small edits (e.g., add tools, add one selection, tune filters)
     - Pipeline/backend updates are small and localized if needed
     - Existing detection functionality is preserved (no removal of current detections/filters/logic)
     - Does not require rewriting the rule from scratch
   - **Out of Scope**:
     - Only generic keyword overlap
     - Same logsource/fields but different detection objective
     - Different telemetry class
       - Required target fields for the requested regex/pattern logic are not present and cannot be provided by minor existing pipeline mappings
     - Requires major pipeline redesign or unsupported field transformations
     - Would require major redesign to fit the requested idea

### Extension Safety Rules

When proposing `Extensible` changes, the rule must be **extended, not reduced**:
- Do not remove or weaken existing detection selections, filters, or conditions
- Do not delete currently covered behaviors from the rule
- Prefer additive changes (new selections, additional values, extra filters, optional pipeline mappings)
- If any existing logic appears incompatible, mark the rule as `Out of Scope` instead of proposing destructive edits

Branch isolation requirements (mandatory):
- New logic must be added as a separate branch (`selection_new_*`, `filter_new_*`) or equivalent isolated block
- New filters must only apply to the new branch, not retroactively to old branches
- Do not broaden parent selectors in a way that changes old branch semantics unless old branch condition remains unchanged
- Final `condition` must preserve original branch behavior exactly and combine new behavior explicitly (e.g., `(original_condition) or (new_condition)`)

Sigma schema scope requirements (mandatory):
- Patch suggestions may modify only SigmaHQ-standard rule keys (for example: `title`, `id`, `status`, `description`, `references`, `author`, `date`, `modified`, `tags`, `logsource`, `detection`, `falsepositives`, `level`, `fields`)
- Do not modify custom backend-specific keys/sections
- If backend behavior changes are needed, describe them in prose under pipeline compatibility notes instead of editing custom backend keys

Rule validity requirements (mandatory):
- Every proposed patch must result in a syntactically valid Sigma rule
- Every identifier referenced in `condition` must exist in the patched `detection` block
- Do not reference undefined selections, filters, keywords, or branch prefixes
- If a patch introduces `selection_new_*` or `filter_new_*`, the final `condition` must reference those exact identifiers consistently
- Preserve valid operator usage (`all of`, `1 of`, explicit boolean expressions, parentheses) and do not produce ambiguous or incomplete conditions
- Do not output example diffs that would fail basic Sigma parsing or break rule semantics

Consistency checks before returning a patch:
- Verify all added `selection_*` / `filter_*` names are defined exactly once if referenced directly
- Verify wildcard references such as `all of selection_new_*` only refer to identifiers that actually exist in the patch
- Verify the original rule still parses after the additive branch is merged into the updated `condition`
- If a valid patch cannot be written confidently, do not emit a diff for that rule; mark it `Out of Scope` or state that no safe patch suggestion can be produced

Metadata updates are allowed when extending a rule:
- `title`
- `description`
- `tags`
- `date`
- `modified`

5. **Output only Full Coverage or Extensible results** with:
   - Rule name/title
   - Rule UUID (`id` field)
   - Description
   - A direct link to the rule file in the repository
   - Match type (`Full Coverage` or `Extensible`)
   - Required extension summary (if `Extensible`)
   - Logsource compatibility note
   - Pipeline compatibility note

6. **For each result row, add a patch suggestion** immediately below the table entry showing
   concrete changes as a unified diff:
   - Include a `Current` vs `Expected` delta in `diff` format
   - Keep the patch minimal and focused on required changes only
   - For `Extensible` results, patches must be additive and preserve existing detection behavior
   - Patch must show branch isolation (original condition preserved, new logic in separate branch)
   - Patch must edit only SigmaHQ-standard keys and must not include changes to custom backend-specific sections
   - Patch must be internally valid: no undefined identifiers in `condition`, no broken boolean expressions, no incomplete detection branches
   - If pipeline updates are needed, include a second diff block for the pipeline/config file
   - If no changes are required, state `No patch needed` for that rule

## Output Format

If qualifying rules are found:

| Rule Name | Rule ID | Description | Link | Match Type | Required Extension | Logsource Compatibility | Pipeline Compatibility |
|-----------|---------|-------------|------|------------|--------------------|-------------------------|------------------------|
| [Rule Title] | [UUID] | [Description] | [View Rule] | [Full Coverage/Extensible] | [None or concise delta] | [Compatible/Slight adjustments needed] | [Compatible/Minor pipeline update needed] |

Patch suggestion for `[Rule Title]`:

```diff
# File: path/to/rule.yml
-# current relevant lines
+# expected updated lines
```

If a pipeline/config change is required:

```diff
# File: pipelines/path/to/pipeline.yml
-# current mapping/transform
+# expected mapping/transform
```

Review these rules to determine whether an existing detection can be reused directly or extended
with minimal changes.

If no qualifying rules are found:

> **No qualifying Sigma rules were found** that either fully cover this detection idea or are directly extensible for it.

In the no-match case:
- Do not include rejected candidate tables or detailed rule-by-rule reasoning
- Do not list near matches unless the user explicitly asks for them
- Keep the output concise and limited to the no-match statement

## Notes

- Do not return weak analogs that only share generic terms (e.g., "powershell" only)
- Do not match rules solely because logsource and field names are similar
- Absence of the exact requested regex/pattern in an existing rule is acceptable for `Extensible` classification when purpose, telemetry semantics, and target field availability are satisfied
- Prefer precision over recall; missing a weak match is acceptable
- Up to 3 qualifying rules are returned
- Every `Extensible` result must include a concrete "Required Extension" description
- Every qualifying result must include a concrete patch suggestion or an explicit `No patch needed`
- Consider repository-defined Sigma pipelines when determining whether a rule is truly extensible
- Never propose extension diffs that remove existing detection functionality
- Metadata-only updates (`title`, `description`, `tags`, `date`, `modified`) are valid alongside additive logic changes
- Never edit custom backend keys; restrict rule diffs to SigmaHQ-standard keys
- Never emit a patch with undefined detection identifiers or an invalid `condition`
- Stay aligned with the latest SigmaHQ reference guide and schema semantics when evaluating rules or writing diffs