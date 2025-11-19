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

```shell
uv run main.py --org my-org --token <token> --ruleset-path ruleset.json --target-branch main
```

For individuals:

```shell
uv run main.py --user my-user --token <token> --ruleset-path ruleset.json --target-branch main
```

Available options:

```shell
usage: main.py [-h] [--org ORG] [--user USER] --token TOKEN [--ruleset-path RULESET_PATH] [--target-branch TARGET_BRANCH] [--dry-run]
               [--skip-repository SKIP_REPOSITORIES]

Ensure a GitHub ruleset is enforced across an owner account.

options:
  -h, --help            show this help message and exit
  --org ORG             GitHub organisation name
  --user USER           GitHub user name
  --token TOKEN         GitHub token with admin:org scope
  --ruleset-path RULESET_PATH
                        Path to the ruleset template JSON file
  --target-branch TARGET_BRANCH
                        Branch to enforce pull request checks on
  --dry-run             Show proposed ruleset changes without applying them
  --skip-repository, --skip-repo SKIP_REPOSITORIES
                        Repository name to skip (can be specified multiple times)
```

### Dry Run

Pass `--dry-run` to see the proposed ruleset payloads for each repository without making any API changes. This is useful for validating the resulting configuration before enforcing it:

```shell
uv run main.py --user my-user --token <token> --dry-run
```

### Skipping repositories

Provide `--skip-repository repo-name` (repeatable) to exclude specific repositories from enforcement:

```shell
uv run main.py --org my-org --token <token> --skip-repository legacy-repo --skip-repository sandbox
```
