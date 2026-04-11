# Check for Similar SigmaHQ Rules – Agent Skill

A GitHub Copilot agent skill and GitHub Actions workflow that automatically
scans a repository's existing Sigma detection rules whenever a new detection
idea or Sigma rule is submitted via an issue or pull request.

## What it does

When an **issue** or **pull request** is opened (or edited), the workflow:

1. Reads the title and body of the issue/PR
2. Searches the repository for Sigma rule files (`.yml` / `.yaml`)
3. Scores each rule for relevance using keyword similarity
4. Posts a comment with a table of the most similar rules – including rule name,
   UUID, description, and a direct link to the file

If no similar rules are found, the comment says so and encourages creating a
new rule to fill the coverage gap.

### Example comment

> ## 🔍 Similar Sigma Rules Check
>
> Found **2** potentially related rule(s) in this repository:
>
> | Rule Name | Rule ID | Description | Link |
> |-----------|---------|-------------|------|
> | Network Tunnelling Tool Usage - Chisel | `` `abc123…` `` | Detects usage of Chisel… | [View Rule](…) |
> | Network Tunnelling via SSH | `` `def456…` `` | Detects SSH-based port forwarding… | [View Rule](…) |
>
> 💡 **Review these rules** to determine if any fully cover the described
> detection, or if any could be **extended** to include it.

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

## How similarity is calculated

For each Sigma rule the script:

1. Collects all text from `title`, `description`, `tags`, `detection`,
   `logsource`, `author`, `references`, and `falsepositives`
2. Tokenises and filters stop-words
3. Computes a **Jaccard similarity** between the query keyword set and the rule
   keyword set
4. Adds a boost when query terms appear in the rule's `title` (+0.3) or
   `description` (+0.1)

Rules scoring ≥ `MIN_SIMILARITY_SCORE` are returned, sorted by score descending.
