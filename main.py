#!/usr/bin/env python3
"""GitHub ruleset enforcement utility."""

from __future__ import annotations

import argparse
import base64
import copy
import fnmatch
import json
import logging
import os
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

import requests
import yaml


class GitHubWorkflowLoader(yaml.SafeLoader):
    """YAML loader that treats GitHub workflow keys literally."""


_STRICT_BOOL_RESOLVER = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")


def _configure_workflow_loader() -> None:
    # Remove the default boolean resolver so words like "on"/"off" remain strings.
    for first_char in list("oOyYnNtTfF"):
        resolvers = GitHubWorkflowLoader.yaml_implicit_resolvers.get(first_char)
        if not resolvers:
            continue
        GitHubWorkflowLoader.yaml_implicit_resolvers[first_char] = [
            (tag, regexp)
            for tag, regexp in resolvers
            if tag != "tag:yaml.org,2002:bool"
        ]
    GitHubWorkflowLoader.add_implicit_resolver(
        "tag:yaml.org,2002:bool",
        _STRICT_BOOL_RESOLVER,
        list("tTfF"),
    )


_configure_workflow_loader()


GITHUB_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
USER_AGENT = "github-ruleset-enforcement/0.1.0"


logger = logging.getLogger(__name__)


class GitHubAPIError(RuntimeError):
    """Raised when the GitHub API returns an error response."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"GitHub API error {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


READ_ONLY_RULESET_FIELDS: set[str] = {
    "id",
    "source",
    "source_type",
    "node_id",
    "_links",
    "created_at",
    "updated_at",
    "current_user_can_bypass",
}


def _normalize_for_comparison(
    obj: dict | list | str | int | bool | None,
) -> dict | list | str | int | bool | None:
    """Recursively normalize a structure for comparison by sorting lists and dicts."""
    if isinstance(obj, dict):
        return {k: _normalize_for_comparison(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        # Sort lists of dicts by their JSON representation for consistent comparison
        normalized = [_normalize_for_comparison(item) for item in obj]
        try:
            return sorted(normalized, key=lambda x: json.dumps(x, sort_keys=True))
        except TypeError:
            # If items aren't comparable, keep original order
            return normalized
    return obj


def rulesets_are_equal(existing: dict, new_payload: dict) -> bool:
    """Compare two rulesets for equality, ignoring read-only fields."""
    existing_filtered = {
        k: v for k, v in existing.items() if k not in READ_ONLY_RULESET_FIELDS
    }
    normalized_existing = _normalize_for_comparison(existing_filtered)
    normalized_new = _normalize_for_comparison(new_payload)
    are_equal = normalized_existing == normalized_new
    if not are_equal:
        logger.debug(
            "Ruleset comparison - existing keys: %s, new keys: %s",
            sorted(existing_filtered.keys()),
            sorted(new_payload.keys()),
        )
        for key in set(existing_filtered.keys()) | set(new_payload.keys()):
            existing_val = existing_filtered.get(key)
            new_val = new_payload.get(key)
            if _normalize_for_comparison(existing_val) != _normalize_for_comparison(
                new_val
            ):
                logger.debug(
                    "Ruleset difference in key '%s': existing=%s, new=%s",
                    key,
                    json.dumps(existing_val, indent=2),
                    json.dumps(new_val, indent=2),
                )
    return are_equal


@dataclass
class Repository:
    """Simple container for repository metadata."""

    name: str
    default_branch: str
    archived: bool = False
    fork: bool = False


class GitHubRulesetEnforcer:
    """Helper that wraps the GitHub API calls required for enforcement."""

    def __init__(
        self,
        owner: str,
        owner_type: str,
        token: str,
        *,
        excluded_required_checks: Sequence[str] | None = None,
    ) -> None:
        self.owner = owner
        self.owner_type = owner_type
        self.owner_prefix = (
            f"/orgs/{owner}" if owner_type == "org" else f"/users/{owner}"
        )
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": USER_AGENT,
            }
        )
        self.excluded_required_checks: set[str] = set(excluded_required_checks or [])
        logger.debug("Initialized GitHubRulesetEnforcer for %s '%s'", owner_type, owner)

    def list_repositories(self) -> list[Repository]:
        logger.debug("Fetching repositories for owner '%s'", self.owner)

        if self.owner_type == "org":
            repos_endpoint = f"{self.owner_prefix}/repos"
            params = {"per_page": 100, "type": "all"}
        else:
            repos_endpoint = "/user/repos"
            params = {"per_page": 100, "visibility": "all", "affiliation": "owner"}

        repos = [
            Repository(
                name=repo["name"],
                default_branch=repo.get("default_branch", "main"),
                archived=repo.get("archived", False),
                fork=repo.get("fork", False),
            )
            for repo in self._paginate(repos_endpoint, params=params)
            if self.owner_type == "org"
            or repo.get("owner", {}).get("login", "").lower() == self.owner.lower()
        ]

        logger.debug("Fetched %d repositories for owner '%s'", len(repos), self.owner)
        return repos

    def branch_exists(self, repository: str, branch: str) -> bool:
        logger.debug(
            "Checking if branch '%s' exists in repository '%s'", branch, repository
        )
        response = self.session.get(
            f"{GITHUB_API_URL}/repos/{self.owner}/{repository}/branches/{branch}",
            timeout=30,
        )
        if response.status_code == 404:
            logger.debug("Branch '%s' not found in repository '%s'", branch, repository)
            return False
        if response.status_code >= 400:
            raise GitHubAPIError(response.status_code, self._format_error(response))
        logger.debug("Branch '%s' exists in repository '%s'", branch, repository)
        return True

    def list_workflows(self, repository: str) -> list[dict]:
        logger.debug("Listing workflows for repository '%s'", repository)
        return list(
            self._paginate(
                f"/repos/{self.owner}/{repository}/actions/workflows",
                params={"per_page": 100},
                data_key="workflows",
            )
        )

    def fetch_workflow_definition(
        self, repository: str, path: str, ref: str
    ) -> dict | None:
        logger.debug(
            "Fetching workflow definition for repository '%s', path '%s', ref '%s'",
            repository,
            path,
            ref,
        )
        response = self.session.get(
            f"{GITHUB_API_URL}/repos/{self.owner}/{repository}/contents/{path}",
            params={"ref": ref},
            timeout=30,
        )
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise GitHubAPIError(response.status_code, self._format_error(response))
        payload = response.json()
        content = base64.b64decode(payload["content"]).decode("utf-8")
        logger.debug(
            "Workflow definition for repository '%s' at '%s' (ref '%s'):\n%s",
            repository,
            path,
            ref,
            content,
        )
        try:
            documents = list(yaml.load_all(content, Loader=GitHubWorkflowLoader))
        except yaml.YAMLError as exc:  # pragma: no cover - defensive logging
            raise RuntimeError(f"Failed to parse workflow {path}: {exc}") from exc
        return documents[0] if documents else None

    def collect_required_checks_for_repository(
        self, repository: Repository, branch: str
    ) -> set[str]:
        logger.debug(
            "Collecting required checks for repository '%s' on branch '%s'",
            repository.name,
            branch,
        )
        checks: set[str] = set()
        try:
            workflows = self.list_workflows(repository.name)
        except GitHubAPIError as exc:
            if exc.status_code == 403:
                logger.warning(
                    "Skipping workflow inspection for repository '%s': %s",
                    repository.name,
                    exc.detail,
                )
                logger.warning(
                    "Provide a token with the 'actions' scope to collect required status checks."
                )
                return checks
            raise
        for workflow in workflows:
            if workflow.get("state") != "active":
                continue
            definition = self.fetch_workflow_definition(
                repository.name, workflow["path"], branch
            )
            if not definition:
                continue
            if workflow_targets_branch(definition, branch):
                checks.update(
                    extract_job_names(definition, self.excluded_required_checks)
                )
        logger.debug(
            "Collected %d required checks for repository '%s'",
            len(checks),
            repository.name,
        )
        return checks

    def find_ruleset(self, repository: str, name: str) -> dict | None:
        logger.debug("Searching for ruleset '%s' in repository '%s'", name, repository)
        endpoint = f"/repos/{self.owner}/{repository}/rulesets"
        params = {"per_page": 100, "includes_parents": "false"}

        ruleset = next(
            (
                r
                for r in self._paginate(endpoint, params=params)
                if r.get("name") == name
            ),
            None,
        )

        if ruleset:
            logger.debug(
                "Found existing ruleset '%s' (id=%s) in repository '%s'",
                name,
                ruleset.get("id"),
                repository,
            )
        else:
            logger.debug("Ruleset '%s' not found in repository '%s'", name, repository)

        return ruleset

    def create_ruleset(self, repository: str, payload: dict) -> None:
        logger.info(
            "Creating ruleset '%s' in repository '%s'", payload.get("name"), repository
        )
        response = self.session.post(
            f"{GITHUB_API_URL}/repos/{self.owner}/{repository}/rulesets",
            json=payload,
            timeout=30,
        )
        if response.status_code >= 400:
            raise GitHubAPIError(response.status_code, self._format_error(response))

    def update_ruleset(self, repository: str, ruleset_id: int, payload: dict) -> None:
        logger.info(
            "Updating ruleset '%s' (id=%s) in repository '%s'",
            payload.get("name"),
            ruleset_id,
            repository,
        )
        response = self.session.put(
            f"{GITHUB_API_URL}/repos/{self.owner}/{repository}/rulesets/{ruleset_id}",
            json=payload,
            timeout=30,
        )
        if response.status_code >= 400:
            raise GitHubAPIError(response.status_code, self._format_error(response))

    def get_ruleset(self, repository: str, ruleset_id: int) -> dict:
        """Fetch the full ruleset definition by ID."""
        logger.debug(
            "Fetching ruleset id=%s from repository '%s'", ruleset_id, repository
        )
        response = self.session.get(
            f"{GITHUB_API_URL}/repos/{self.owner}/{repository}/rulesets/{ruleset_id}",
            timeout=30,
        )
        if response.status_code >= 400:
            raise GitHubAPIError(response.status_code, self._format_error(response))
        return response.json()

    def upsert_ruleset(
        self, repository: str, definition: dict, dry_run: bool = False
    ) -> str:
        payload = self._prepare_ruleset_payload(definition)
        existing_summary = self.find_ruleset(repository, definition.get("name", ""))

        if existing_summary:
            # Fetch the full ruleset to compare
            existing = self.get_ruleset(repository, existing_summary["id"])
            if rulesets_are_equal(existing, payload):
                logger.info(
                    "Ruleset '%s' (id=%s) in repository '%s' is already up-to-date",
                    payload.get("name"),
                    existing_summary["id"],
                    repository,
                )
                return "unchanged"

        match (bool(existing_summary), dry_run):
            case (True, True):
                logger.info(
                    "[dry-run] Would update ruleset '%s' (id=%s) in repository '%s'",
                    payload.get("name"),
                    existing_summary["id"],
                    repository,
                )
                action = "dry_run_update"
            case (True, False):
                self.update_ruleset(repository, existing_summary["id"], payload)
                action = "updated"
            case (False, True):
                logger.info(
                    "[dry-run] Would create ruleset '%s' in repository '%s'",
                    payload.get("name"),
                    repository,
                )
                action = "dry_run_create"
            case (False, False):
                self.create_ruleset(repository, payload)
                action = "created"

        if dry_run:
            logger.debug(
                "[dry-run] Ruleset payload for '%s': %s",
                repository,
                json.dumps(payload, indent=2),
            )
        else:
            logger.info(
                "Ruleset '%s' applied to repository '%s'",
                payload.get("name"),
                repository,
            )
        return action

    def _prepare_ruleset_payload(self, definition: dict) -> dict:
        return {
            key: copy.deepcopy(value)
            for key, value in definition.items()
            if key not in READ_ONLY_RULESET_FIELDS
        }

    def _paginate(
        self,
        endpoint: str,
        *,
        params: dict | None = None,
        data_key: str | None = None,
    ) -> Iterable:
        url = endpoint if endpoint.startswith("http") else f"{GITHUB_API_URL}{endpoint}"
        next_params = params
        while url:
            response = self.session.get(url, params=next_params, timeout=30)
            if response.status_code >= 400:
                raise GitHubAPIError(response.status_code, self._format_error(response))
            body = response.json()
            items = body.get(data_key, []) if data_key else body
            yield from items
            url = response.links.get("next", {}).get("url")
            next_params = None

    @staticmethod
    def _format_error(response: requests.Response) -> str:
        try:
            return json.dumps(response.json())
        except ValueError:
            return response.text


def workflow_targets_branch(workflow: dict, branch: str) -> bool:
    event_map = normalize_events(workflow.get("on"))
    return any(
        event_name in event_map and branch_matches(event_map[event_name], branch)
        for event_name in ("pull_request", "pull_request_target")
    )


def normalize_events(triggers) -> dict:
    match triggers:
        case None:
            return {}
        case str():
            return {triggers: None}
        case list():
            return {event: None for event in triggers}
        case dict():
            return triggers
        case _:
            return {}


def branch_matches(event_config, branch: str) -> bool:
    if not isinstance(event_config, dict):
        return True
    branches = to_list(event_config.get("branches"))
    if branches:
        return any(fnmatch.fnmatch(branch, pattern) for pattern in branches)
    branches_ignore = to_list(event_config.get("branches-ignore"))
    if branches_ignore:
        return not any(fnmatch.fnmatch(branch, pattern) for pattern in branches_ignore)
    return True


def extract_job_names(workflow: dict, excluded_checks: set[str]) -> set[str]:
    jobs = workflow.get("jobs") or {}
    names: set[str] = set()
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_name = job.get("name") or job_id
        if job_name in excluded_checks:
            logger.debug(
                "Skipping job '%s' from required status checks due to exclusion list",
                job_name,
            )
        else:
            names.add(job_name)
    return names


def to_list(value: Sequence[str] | str | None) -> list[str]:
    match value:
        case None:
            return []
        case str():
            return [value]
        case _:
            return list(value)


DEFAULT_TEMPLATE_SOURCE = "MattKobayashi/github-ruleset-enforcement"
DEFAULT_TEMPLATES_DIR = "templates"
DEFAULT_TEMPLATE_FILENAME = "default.json"


def load_default_template(templates_dir: str) -> dict:
    """Load the default ruleset template from the templates directory."""
    default_path = Path(templates_dir) / DEFAULT_TEMPLATE_FILENAME
    if not default_path.exists():
        raise FileNotFoundError(
            f"Default template not found at '{default_path}'. "
            f"Ensure '{DEFAULT_TEMPLATE_FILENAME}' exists in the templates directory."
        )
    return json.loads(default_path.read_text(encoding="utf-8"))


def load_all_templates(templates_dir: str) -> tuple[dict, dict[str, dict]]:
    """Load all templates from the templates directory.

    Returns a tuple of (default_template, repo_templates) where:
    - default_template: The default template (from default.json or matching DEFAULT_TEMPLATE_SOURCE)
    - repo_templates: A dict mapping repository names to their templates
    """
    templates_path = Path(templates_dir)
    repo_templates: dict[str, dict] = {}
    default_template: dict | None = None

    if not templates_path.exists():
        raise FileNotFoundError(f"Templates directory '{templates_dir}' does not exist")

    for template_file in templates_path.glob("*.json"):
        try:
            template = json.loads(template_file.read_text(encoding="utf-8"))
            source = template.get("source", "")

            # Check if this is the default template
            if source == DEFAULT_TEMPLATE_SOURCE:
                if default_template is None:
                    default_template = template
                    logger.debug(
                        "Loaded default template from '%s' (source: %s)",
                        template_file.name,
                        source,
                    )
                else:
                    logger.warning(
                        "Multiple default templates found. Ignoring '%s'",
                        template_file.name,
                    )
                continue

            # Extract repository name from source (format: "owner/repo")
            if "/" in source:
                repo_name = source.split("/", 1)[1]
                repo_templates[repo_name] = template
                logger.debug(
                    "Loaded repository-specific template for '%s' from '%s'",
                    repo_name,
                    template_file.name,
                )
            else:
                logger.warning(
                    "Template '%s' has invalid source format: '%s'",
                    template_file.name,
                    source,
                )
        except json.JSONDecodeError as exc:
            logger.warning(
                "Failed to parse template '%s': %s", template_file.name, exc
            )

    if default_template is None:
        raise FileNotFoundError(
            f"No default template found in '{templates_dir}'. "
            f"Ensure a template with source '{DEFAULT_TEMPLATE_SOURCE}' exists."
        )

    logger.info(
        "Loaded default template and %d repository-specific templates from '%s'",
        len(repo_templates),
        templates_dir,
    )
    return default_template, repo_templates


def get_template_for_repository(
    repo_name: str,
    repo_templates: dict[str, dict],
    default_template: dict,
) -> dict:
    """Get the appropriate template for a repository.

    Returns a repository-specific template if one exists, otherwise the default template.
    """
    if repo_name in repo_templates:
        logger.debug(
            "Using repository-specific template for '%s'",
            repo_name,
        )
        return repo_templates[repo_name]

    logger.debug(
        "Using default template for '%s'",
        repo_name,
    )
    return default_template


def ensure_required_status_rule(ruleset: dict, required_checks: set[str]) -> None:
    rules = ruleset.setdefault("rules", [])
    if not required_checks:
        before = len(rules)
        rules[:] = [
            rule for rule in rules if rule.get("type") != "required_status_checks"
        ]
        if before != len(rules):
            logger.debug(
                "Removed required_status_checks rule from ruleset '%s' due to missing checks",
                ruleset.get("name"),
            )
        return

    rule = next(
        (rule for rule in rules if rule.get("type") == "required_status_checks"), None
    )
    if not rule:
        logger.debug(
            "Adding new required_status_checks rule to ruleset '%s'",
            ruleset.get("name"),
        )
        rule = {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": True,
                "do_not_enforce_on_create": False,
                "required_status_checks": [],
            },
        }
        rules.append(rule)
    parameters = rule.setdefault("parameters", {})
    existing_checks = parameters.get("required_status_checks", []) or []
    checks_by_context: dict[str, dict] = {}
    for check in existing_checks:
        match check:
            case {"context": str() as context}:
                checks_by_context[context] = check
            case str() as context:
                checks_by_context[context] = {"context": context}

    for context in required_checks:
        checks_by_context.setdefault(context, {"context": context})

    parameters["required_status_checks"] = [
        checks_by_context[context] for context in sorted(checks_by_context)
    ]
    logger.debug(
        "Ruleset '%s' now enforces %d required checks",
        ruleset.get("name"),
        len(parameters["required_status_checks"]),
    )


def ensure_repository_condition(ruleset: dict) -> None:
    ruleset.setdefault("enforcement", "active")
    ruleset.setdefault("conditions", {})


def ensure_ruleset_enforcement(
    owner: str,
    owner_type: str,
    token: str,
    templates_dir: str = DEFAULT_TEMPLATES_DIR,
    target_branch: str = "main",
    dry_run: bool = False,
    skip_repositories: Sequence[str] | None = None,
    excluded_required_checks: Sequence[str] | None = None,
) -> None:
    logger.info(
        "Ensuring ruleset enforcement for %s '%s' targeting branch '%s'",
        owner_type,
        owner,
        target_branch,
    )
    enforcer = GitHubRulesetEnforcer(
        owner,
        owner_type,
        token,
        excluded_required_checks=excluded_required_checks,
    )

    # Load all templates (default + repository-specific)
    default_template, repo_templates = load_all_templates(templates_dir)

    summary: Counter = Counter()
    processed_repositories: list[str] = []
    skipped_repositories: list[str] = []
    skip_set: set[str] = {repo.lower() for repo in (skip_repositories or [])}
    repositories = enforcer.list_repositories()
    logger.info("Found %d repositories to evaluate", len(repositories))
    for repo in repositories:
        logger.info(
            "Processing repository '%s' (default branch '%s')",
            repo.name,
            repo.default_branch,
        )
        if repo.name.lower() in skip_set:
            logger.info(
                "Skipping repository '%s': repository listed in --skip-repo",
                repo.name,
            )
            skipped_repositories.append(repo.name)
            continue
        if repo.archived:
            logger.info("Skipping repository '%s': repository is archived", repo.name)
            skipped_repositories.append(repo.name)
            continue
        if repo.fork:
            logger.info("Skipping repository '%s': repository is a fork", repo.name)
            skipped_repositories.append(repo.name)
            continue
        processed_repositories.append(repo.name)

        # Get the appropriate template for this repository
        template = get_template_for_repository(repo.name, repo_templates, default_template)
        repo_ruleset = copy.deepcopy(template)
        ensure_repository_condition(repo_ruleset)

        # Always collect workflow-based required checks for PR-triggered jobs
        required_checks: set[str] = set()
        if enforcer.branch_exists(repo.name, target_branch):
            required_checks = enforcer.collect_required_checks_for_repository(
                repo, target_branch
            )
            logger.debug(
                "Repository '%s' required checks from workflows: %s",
                repo.name,
                sorted(required_checks),
            )
        else:
            logger.info(
                "Skipping required check collection: branch '%s' does not exist in repository '%s'",
                target_branch,
                repo.name,
            )

        # For repository-specific templates, merge workflow checks with existing checks
        if repo.name in repo_templates:
            # Get existing required_status_checks from the template
            existing_checks = _extract_existing_status_checks(repo_ruleset)
            # Combine with workflow-discovered checks
            all_checks = existing_checks | required_checks
            logger.debug(
                "Repository '%s' combined checks (template + workflow): %s",
                repo.name,
                sorted(all_checks),
            )
            ensure_required_status_rule(repo_ruleset, all_checks)
        else:
            ensure_required_status_rule(repo_ruleset, required_checks)

        action = enforcer.upsert_ruleset(repo.name, repo_ruleset, dry_run=dry_run)
        summary[action] += 1

    _print_summary(summary, processed_repositories, skipped_repositories, dry_run)


def _extract_existing_status_checks(ruleset: dict) -> set[str]:
    """Extract existing required status check contexts from a ruleset."""
    checks: set[str] = set()
    rules = ruleset.get("rules", [])
    for rule in rules:
        if rule.get("type") == "required_status_checks":
            params = rule.get("parameters", {})
            for check in params.get("required_status_checks", []):
                if isinstance(check, dict):
                    context = check.get("context")
                    if context:
                        checks.add(context)
                elif isinstance(check, str):
                    checks.add(check)
    return checks


def _print_summary(
    summary: Counter, processed: list[str], skipped: list[str], dry_run: bool
) -> None:
    mode = "dry-run" if dry_run else "execution"
    logger.info("\n===== Ruleset enforcement %s summary =====", mode)
    if processed:
        logger.info(
            "Processed repositories (%d): %s",
            len(processed),
            ", ".join(sorted(processed)),
        )
    else:
        logger.info("No repositories processed")
    if skipped:
        logger.info(
            "Skipped repositories (%d): %s", len(skipped), ", ".join(sorted(skipped))
        )
    actions = {
        "created": "Rulesets created",
        "updated": "Rulesets updated",
        "unchanged": "Rulesets already up-to-date",
        "dry_run_create": "Rulesets to create",
        "dry_run_update": "Rulesets to update",
    }
    for key, label in actions.items():
        if summary.get(key):
            logger.info("%s: %d", label, summary[key])
    if not any(summary.values()):
        logger.info("No ruleset changes were required")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ensure a GitHub ruleset is enforced across an owner account."
    )
    parser.add_argument(
        "--org", default=os.environ.get("GITHUB_ORG"), help="GitHub organisation name"
    )
    parser.add_argument(
        "--user", default=os.environ.get("GITHUB_USER"), help="GitHub user name"
    )
    parser.add_argument(
        "--token", help="GitHub token with admin:org scope", required=True
    )
    parser.add_argument(
        "--templates-dir",
        default=DEFAULT_TEMPLATES_DIR,
        help=(
            "Directory containing ruleset templates. The default template must have "
            f"source '{DEFAULT_TEMPLATE_SOURCE}'. Repository-specific templates are "
            "identified by a different source field in 'owner/repo' format."
        ),
    )
    parser.add_argument(
        "--target-branch",
        default="main",
        help="Branch to enforce pull request checks on",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show proposed ruleset changes without applying them",
    )
    parser.add_argument(
        "--skip-repository",
        "--skip-repo",
        dest="skip_repositories",
        action="append",
        default=[],
        help="Repository name to skip (can be specified multiple times)",
    )
    parser.add_argument(
        "--exclude-required-check",
        dest="excluded_required_checks",
        action="append",
        default=[],
        help=(
            "Workflow job name to exclude from required status checks (can be"
            " specified multiple times)"
        ),
    )
    args = parser.parse_args()
    if not args.org and not args.user:
        parser.error("--org/--user or corresponding env vars are required")
    if args.org and args.user:
        parser.error("Please specify only one of --org or --user")
    if not args.token:
        parser.error("--token or GITHUB_TOKEN is required")
    return args


def main() -> None:
    log_level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    numeric_level = getattr(logging, log_level_name, logging.INFO)
    logging.basicConfig(
        level=numeric_level, format="%(asctime)s %(levelname)s %(name)s - %(message)s"
    )
    args = parse_args()
    owner = args.org or args.user
    owner_type = "org" if args.org else "user"
    ensure_ruleset_enforcement(
        owner,
        owner_type,
        args.token,
        templates_dir=args.templates_dir,
        target_branch=args.target_branch,
        dry_run=args.dry_run,
        skip_repositories=args.skip_repositories,
        excluded_required_checks=args.excluded_required_checks,
    )


if __name__ == "__main__":
    main()
