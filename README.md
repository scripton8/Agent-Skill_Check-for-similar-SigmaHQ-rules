# Check for Similar SigmaHQ Rules – Agent Skill

A GitHub Copilot agent skill and GitHub Actions workflow that automatically
scans a repository's existing Sigma detection rules whenever a new detection
idea or Sigma rule is submitted via an issue or pull request.

## What it does

When an **issue** or **pull request** is opened (or edited), the workflow:

1. Reads the title and body of the issue/PR
2. Extracts detection concepts (TTPs, tools, log sources, MITRE ATT&CK tags)
3. Searches the repository for Sigma rule files (`.yml` / `.yaml`) and
   pipeline/backend configuration files
4. Evaluates each rule against strict coverage and extensibility criteria
5. Posts a comment showing only **high-confidence** matches – rules that either
   fully cover the described detection or can be extended with small, safe,
   additive changes

If no qualifying rules are found, the comment says so and encourages creating a
new rule to fill the coverage gap.

### Match classification

Every candidate rule is classified into one of three categories:

| Classification | Meaning |
|---|---|
| **Full Coverage** | The rule's detection logic, indicator set, telemetry, and log source substantially match the requested idea — no changes needed |
| **Extensible** | The rule's purpose and telemetry are logically related; missing indicators can be added as isolated, additive branches without touching existing logic |
| **Out of Scope** | Only generic keyword overlap, different telemetry class, or a major rewrite would be needed — excluded from results |

Only **Full Coverage** and **Extensible** rules are included in the output.

### Patch suggestions

For every **Extensible** result the skill produces a concrete unified diff
showing exactly which lines to add, with branch isolation guarantees:

- New logic is added as a separate branch (e.g., `selection_new_*`)
- The original `condition` is preserved; the new branch is combined explicitly
- No existing detection selections, filters, or conditions are removed
- Only SigmaHQ-standard rule keys are modified

### Example agent comment

> | Rule Name | Rule ID | Description | Link | Match Type | Required Extension | Logsource Compatibility | Pipeline Compatibility |
> |-----------|---------|-------------|------|------------|--------------------|-------------------------|------------------------|
> | Network Tunnelling Tool Usage - Chisel | `abc123…` | Detects usage of Chisel… | [View Rule](…) | Extensible | Add `chisel.exe` to existing tool list | Compatible | Compatible |
> | Network Tunnelling via SSH | `def456…` | Detects SSH-based port forwarding… | [View Rule](…) | Full Coverage | None | Compatible | Compatible |
>
> Patch suggestion for `Network Tunnelling Tool Usage - Chisel`:
>
> ```diff
> # File: rules/network/net_tunnelling_chisel.yml
> -    tools|contains:
> +    tools|contains:
>          - 'plink.exe'
> +        - 'chisel.exe'
> ```

## Repository layout

```
.
├── .github/
│   ├── skills/
│   │   └── check-similar-sigma-rules/
│   │       └── SKILL.md          ← Agent skill definition
│   └── workflows/
│       └── check-similar-sigma-rules.yml  ← GitHub Actions workflow
├── scripts/
│   └── check_similar_rules.py    ← Core matching logic
├── tests/
│   └── test_check_similar_rules.py
└── requirements.txt
```

## How to use this skill in your own Sigma repository

1. **Copy the workflow** (`.github/workflows/check-similar-sigma-rules.yml`)
   into the target repository's `.github/workflows/` directory.
2. **Copy the script** (`scripts/check_similar_rules.py`) into a `scripts/`
   directory in the target repository.
3. *(Optional)* **Copy the skill definition**
   (`.github/skills/check-similar-sigma-rules/SKILL.md`) if you want Copilot
   to be able to invoke it as a named skill.
4. The `GITHUB_TOKEN` secret is available automatically in GitHub Actions – no
   extra configuration is required.

### Supported rule directories

The script looks for Sigma rule files in the following directories (in order):

- `rules/`
- `detections/`
- `detection/`
- `sigma/`
- `rules-emerging-threats/`
- `rules-placeholder/`
- `rules-threat-hunting/`

If none of these exist, every `.yml` / `.yaml` file in the repository
(excluding `.github/`) is scanned.

The agent skill also scans the `pipelines/` directory (and any
subdirectories) for Sigma pipeline and backend conversion configuration, which
is used to assess whether field mappings needed by a proposed extension are
already available without a major pipeline redesign.

## Running tests locally

```bash
pip install -r requirements.txt
pytest tests/
```

## Configuration

The following constants in `scripts/check_similar_rules.py` can be adjusted:

| Constant | Default | Description |
|---|---|---|
| `MIN_SIMILARITY_SCORE` | `0.05` | Minimum score for a rule to appear in results |
| `MAX_RESULTS` | `10` | Maximum number of rules shown in the comment |
| `RULES_DIRECTORIES` | see above | Directories searched for Sigma rules |

## How similarity and coverage are evaluated

### Automated workflow (GitHub Actions)

The `check_similar_rules.py` script performs a lightweight first pass for each
Sigma rule:

1. Collects all text from `title`, `description`, `tags`, `detection`,
   `logsource`, `author`, `references`, and `falsepositives`
2. Tokenises and filters stop-words
3. Computes a **Jaccard similarity** between the query keyword set and the rule
   keyword set
4. Adds a boost when query terms appear in the rule's `title` (+0.3) or
   `description` (+0.1)

Rules scoring ≥ `MIN_SIMILARITY_SCORE` are returned, sorted by score descending.

### Agent skill (Copilot / SKILL.md)

When invoked as a Copilot agent skill, the analysis goes deeper. Each rule is
evaluated across multiple dimensions:

| Dimension | What is checked |
|---|---|
| **Detection logic** | Parent/child relationships, process-chain behavior, correlation |
| **Indicator set** | Binaries, command-line patterns, paths, registry keys, network indicators |
| **Field anchor compatibility** | Fields needed for new indicators already exist in the rule or pipeline |
| **Telemetry semantics** | Same event intent (e.g., process creation vs. proxy request) |
| **Logsource compatibility** | Product/service/category alignment (minor naming differences allowed) |
| **Purpose linkage** | Rule intent is logically related to the requested detection objective |
| **ATT&CK / tags relevance** | Technique/tactic family overlap or adjacency |

Rules are automatically rejected when the match is based solely on shared
logsource/fields, generic terms, or a different detection objective.
