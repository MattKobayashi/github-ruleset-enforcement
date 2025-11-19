# GitHub Ruleset Enforcement Utility

Ensure a templated ruleset is applied to every active non-fork repository owned by a user or organisation. The script inspects each repository, determines the required workflow checks for the target branch, and then creates or updates the repository ruleset accordingly.

## Setup

Create a fine-grained personal access token (PAT) with the following permissions:

| Permission     | Level          |
| -------------- | -------------- |
| Actions        | Read-only      |
| Administration | Read and write |
| Contents       | Read-only      |
| Metadata       | Read-only      |

## Usage

For organisations:

```bash
uv run main.py --org my-org --token <token> --ruleset-path ruleset.json --target-branch main
```

For individuals:

```bash
uv run main.py --user my-user --token <token> --ruleset-path ruleset.json --target-branch main
```

### Dry Run

Pass `--dry-run` to see the proposed ruleset payloads for each repository without making any API changes. This is useful for validating the resulting configuration before enforcing it:

```bash
uv run main.py --user my-user --token <token> --dry-run
```
