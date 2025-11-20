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
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set

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


READ_ONLY_RULESET_FIELDS: Set[str] = {
    "id",
    "source",
    "source_type",
    "node_id",
    "_links",
    "created_at",
    "updated_at",
}


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
        excluded_required_checks: Optional[Sequence[str]] | None = None,
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
        self.excluded_required_checks: Set[str] = set(excluded_required_checks or [])
        logger.debug("Initialized GitHubRulesetEnforcer for %s '%s'", owner_type, owner)

    def list_repositories(self) -> List[Repository]:
        logger.debug("Fetching repositories for owner '%s'", self.owner)
        repos: List[Repository] = []
        if self.owner_type == "org":
            repos_endpoint = f"{self.owner_prefix}/repos"
            params = {"per_page": 100, "type": "all"}
        else:
            repos_endpoint = "/user/repos"
            params = {"per_page": 100, "visibility": "all", "affiliation": "owner"}
        for repo in self._paginate(repos_endpoint, params=params):
            if (
                self.owner_type == "user"
                and repo.get("owner", {}).get("login", "").lower() != self.owner.lower()
            ):
                continue
            repos.append(
                Repository(
                    name=repo["name"],
                    default_branch=repo.get("default_branch", "main"),
                    archived=repo.get("archived", False),
                    fork=repo.get("fork", False),
                )
            )
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

    def list_workflows(self, repository: str) -> List[Dict]:
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
    ) -> Optional[Dict]:
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
    ) -> Set[str]:
        logger.debug(
            "Collecting required checks for repository '%s' on branch '%s'",
            repository.name,
            branch,
        )
        checks: Set[str] = set()
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

    def find_ruleset(self, repository: str, name: str) -> Optional[Dict]:
        logger.debug("Searching for ruleset '%s' in repository '%s'", name, repository)
        endpoint = f"/repos/{self.owner}/{repository}/rulesets"
        params = {"per_page": 100, "includes_parents": "false"}
        for ruleset in self._paginate(endpoint, params=params):
            if ruleset.get("name") == name:
                logger.debug(
                    "Found existing ruleset '%s' (id=%s) in repository '%s'",
                    name,
                    ruleset.get("id"),
                    repository,
                )
                return ruleset
        logger.debug("Ruleset '%s' not found in repository '%s'", name, repository)
        return None

    def create_ruleset(self, repository: str, payload: Dict) -> None:
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

    def update_ruleset(self, repository: str, ruleset_id: int, payload: Dict) -> None:
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

    def upsert_ruleset(
        self, repository: str, definition: Dict, dry_run: bool = False
    ) -> str:
        payload = self._prepare_ruleset_payload(definition)
        existing = self.find_ruleset(repository, definition.get("name", ""))
        action: str
        if existing:
            if dry_run:
                logger.info(
                    "[dry-run] Would update ruleset '%s' (id=%s) in repository '%s'",
                    payload.get("name"),
                    existing["id"],
                    repository,
                )
                action = "dry_run_update"
            else:
                self.update_ruleset(repository, existing["id"], payload)
                action = "updated"
        else:
            if dry_run:
                logger.info(
                    "[dry-run] Would create ruleset '%s' in repository '%s'",
                    payload.get("name"),
                    repository,
                )
                action = "dry_run_create"
            else:
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

    def _prepare_ruleset_payload(self, definition: Dict) -> Dict:
        payload: Dict = {}
        for key, value in definition.items():
            if key in READ_ONLY_RULESET_FIELDS:
                continue
            payload[key] = copy.deepcopy(value)
        return payload

    def _paginate(
        self,
        endpoint: str,
        *,
        params: Optional[Dict] = None,
        data_key: Optional[str] = None,
    ) -> Iterable:
        url = endpoint if endpoint.startswith("http") else f"{GITHUB_API_URL}{endpoint}"
        next_params = params
        while url:
            response = self.session.get(url, params=next_params, timeout=30)
            if response.status_code >= 400:
                raise GitHubAPIError(response.status_code, self._format_error(response))
            body = response.json()
            if data_key:
                items = body.get(data_key, [])
            elif isinstance(body, list):
                items = body
            else:
                items = body
            for item in items:
                yield item
            url = response.links.get("next", {}).get("url")
            next_params = None

    @staticmethod
    def _format_error(response: requests.Response) -> str:
        detail = response.text
        try:
            detail = json.dumps(response.json())
        except ValueError:
            pass
        return detail


def workflow_targets_branch(workflow: Dict, branch: str) -> bool:
    triggers = workflow.get("on")
    event_map = normalize_events(triggers)
    for event_name in ("pull_request", "pull_request_target"):
        if event_name not in event_map:
            continue
        if branch_matches(event_map[event_name], branch):
            return True
    return False


def normalize_events(triggers) -> Dict:
    if triggers is None:
        return {}
    if isinstance(triggers, str):
        return {triggers: None}
    if isinstance(triggers, list):
        return {event: None for event in triggers}
    if isinstance(triggers, dict):
        return triggers
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


def extract_job_names(workflow: Dict, excluded_checks: Set[str]) -> Set[str]:
    jobs = workflow.get("jobs") or {}
    names: Set[str] = set()
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_name = job.get("name") or job_id
        if job_name in excluded_checks:
            logger.debug(
                "Skipping job '%s' from required status checks due to exclusion list",
                job_name,
            )
            continue
        names.add(job_name)
    return names


def to_list(value: Optional[Sequence[str] | str]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def load_ruleset_template(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def ensure_required_status_rule(ruleset: Dict, required_checks: Set[str]) -> None:
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
    checks_by_context: Dict[str, Dict] = {}
    for check in existing_checks:
        if isinstance(check, dict):
            context = check.get("context")
            if context:
                checks_by_context[context] = check
        elif isinstance(check, str):
            checks_by_context[check] = {"context": check}

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


def ensure_repository_condition(ruleset: Dict) -> None:
    ruleset.setdefault("enforcement", "active")
    ruleset.setdefault("conditions", {})


def ensure_ruleset_enforcement(
    owner: str,
    owner_type: str,
    token: str,
    ruleset_path: str,
    target_branch: str = "main",
    dry_run: bool = False,
    skip_repositories: Optional[Sequence[str]] | None = None,
    excluded_required_checks: Optional[Sequence[str]] | None = None,
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
    template_ruleset = load_ruleset_template(ruleset_path)

    summary: Counter = Counter()
    processed_repositories: List[str] = []
    skipped_repositories: List[str] = []
    skip_set: Set[str] = {repo.lower() for repo in (skip_repositories or [])}
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
        repo_ruleset = copy.deepcopy(template_ruleset)
        ensure_repository_condition(repo_ruleset)

        required_checks: Set[str] = set()
        if enforcer.branch_exists(repo.name, target_branch):
            required_checks = enforcer.collect_required_checks_for_repository(
                repo, target_branch
            )
            logger.debug(
                "Repository '%s' required checks: %s",
                repo.name,
                sorted(required_checks),
            )
        else:
            logger.info(
                "Skipping required check collection: branch '%s' does not exist in repository '%s'",
                target_branch,
                repo.name,
            )

        ensure_required_status_rule(repo_ruleset, required_checks)
        action = enforcer.upsert_ruleset(repo.name, repo_ruleset, dry_run=dry_run)
        summary[action] += 1

    _print_summary(summary, processed_repositories, skipped_repositories, dry_run)


def _print_summary(
    summary: Counter, processed: List[str], skipped: List[str], dry_run: bool
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
        "--token",
        help="GitHub token with admin:org scope",
        required=True
    )
    parser.add_argument(
        "--ruleset-path",
        default="templates/ruleset.json",
        help="Path to the ruleset template JSON file",
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
        args.ruleset_path,
        args.target_branch,
        dry_run=args.dry_run,
        skip_repositories=args.skip_repositories,
        excluded_required_checks=args.excluded_required_checks,
    )


if __name__ == "__main__":
    main()
