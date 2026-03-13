import unittest

from main import GitHubRulesetEnforcer


class ReusableWorkflowResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.enforcer = GitHubRulesetEnforcer("repo-owner", "org", "token")

    def test_cross_owner_reusable_workflow_context(self) -> None:
        root_workflow = {
            "name": "CI",
            "jobs": {
                "test": {
                    "uses": "external-owner/actions-workflows/.github/workflows/test.yaml@main"
                }
            },
        }
        reusable_workflow = {
            "name": "Test",
            "on": {"workflow_call": {}},
            "jobs": {"image": {"name": "Image", "runs-on": "ubuntu-latest"}},
        }

        self.enforcer.fetch_workflow_definition = lambda owner, repo, path, ref: (  # type: ignore[method-assign]
            reusable_workflow
            if (owner, repo, path, ref)
            == (
                "external-owner",
                "actions-workflows",
                ".github/workflows/test.yaml",
                "main",
            )
            else None
        )

        checks = self.enforcer.extract_job_names_for_workflow(
            "repo-owner", "app", root_workflow
        )

        self.assertEqual(checks, {"Test / Image"})

    def test_repository_defined_workflow_uses_job_name_only(self) -> None:
        workflow = {
            "name": "CI",
            "jobs": {
                "lint": {"name": "Lint", "runs-on": "ubuntu-latest"},
                "test": {"runs-on": "ubuntu-latest"},
            },
        }

        checks = self.enforcer.extract_job_names_for_workflow(
            "repo-owner", "app", workflow, include_workflow_name=False
        )

        self.assertEqual(checks, {"Lint", "test"})

    def test_local_reusable_workflow_context_uses_default_branch(self) -> None:
        root_workflow = {
            "name": "CI",
            "jobs": {"test": {"uses": "./.github/workflows/test.yaml"}},
        }
        reusable_workflow = {
            "name": "Test",
            "on": {"workflow_call": {}},
            "jobs": {"image": {"name": "Image", "runs-on": "ubuntu-latest"}},
        }

        self.enforcer._default_branch_for_repository = lambda repository: "trunk"  # type: ignore[method-assign]
        self.enforcer.fetch_workflow_definition = lambda owner, repo, path, ref: (  # type: ignore[method-assign]
            reusable_workflow
            if (owner, repo, path, ref)
            == ("repo-owner", "app", ".github/workflows/test.yaml", "trunk")
            else None
        )

        checks = self.enforcer.extract_job_names_for_workflow(
            "repo-owner", "app", root_workflow
        )

        self.assertEqual(checks, {"Test / Image"})

    def test_local_reusable_workflow_uses_caller_ref_when_provided(self) -> None:
        root_workflow = {
            "name": "CI",
            "jobs": {"test": {"uses": "./.github/workflows/test.yaml"}},
        }
        reusable_workflow = {
            "name": "Test",
            "on": {"workflow_call": {}},
            "jobs": {"image": {"name": "Image", "runs-on": "ubuntu-latest"}},
        }

        self.enforcer._default_branch_for_repository = lambda repository: "trunk"  # type: ignore[method-assign]
        self.enforcer.fetch_workflow_definition = lambda owner, repo, path, ref: (  # type: ignore[method-assign]
            reusable_workflow
            if (owner, repo, path, ref)
            == ("repo-owner", "app", ".github/workflows/test.yaml", "feature/refactor")
            else None
        )

        checks = self.enforcer.extract_job_names_for_workflow(
            "repo-owner", "app", root_workflow, workflow_ref="feature/refactor"
        )

        self.assertEqual(checks, {"Test / Image"})

    def test_nested_reusable_workflow_contexts_are_resolved_transitively(self) -> None:
        root_workflow = {
            "name": "CI",
            "jobs": {
                "test": {
                    "uses": "external-owner/actions-workflows/.github/workflows/test.yaml@main"
                }
            },
        }
        reusable_workflow = {
            "name": "Test",
            "on": {"workflow_call": {}},
            "jobs": {
                "image": {
                    "uses": "external-owner/actions-workflows/.github/workflows/image.yaml@main"
                }
            },
        }
        nested_workflow = {
            "name": "Image",
            "on": {"workflow_call": {}},
            "jobs": {"build": {"name": "Build", "runs-on": "ubuntu-latest"}},
        }

        definitions = {
            (
                "external-owner",
                "actions-workflows",
                ".github/workflows/test.yaml",
                "main",
            ): reusable_workflow,
            (
                "external-owner",
                "actions-workflows",
                ".github/workflows/image.yaml",
                "main",
            ): nested_workflow,
        }
        self.enforcer.fetch_workflow_definition = lambda owner, repo, path, ref: (
            definitions.get(  # type: ignore[method-assign]
                (owner, repo, path, ref)
            )
        )

        checks = self.enforcer.extract_job_names_for_workflow(
            "repo-owner", "app", root_workflow
        )

        self.assertEqual(checks, {"Image / Build"})

    def test_reusable_workflow_cycles_do_not_recurse_forever(self) -> None:
        root_workflow = {
            "name": "CI",
            "jobs": {
                "test": {
                    "uses": "external-owner/actions-workflows/.github/workflows/test.yaml@main"
                }
            },
        }
        reusable_workflow = {
            "name": "Test",
            "on": {"workflow_call": {}},
            "jobs": {
                "again": {
                    "uses": "external-owner/actions-workflows/.github/workflows/test.yaml@main"
                },
                "image": {"name": "Image", "runs-on": "ubuntu-latest"},
            },
        }

        self.enforcer.fetch_workflow_definition = lambda owner, repo, path, ref: (  # type: ignore[method-assign]
            reusable_workflow
            if (owner, repo, path, ref)
            == (
                "external-owner",
                "actions-workflows",
                ".github/workflows/test.yaml",
                "main",
            )
            else None
        )

        checks = self.enforcer.extract_job_names_for_workflow(
            "repo-owner", "app", root_workflow
        )

        self.assertEqual(checks, {"Test / Image"})

    def test_excluded_checks_apply_within_reusable_workflows(self) -> None:
        enforcer = GitHubRulesetEnforcer(
            "repo-owner", "org", "token", excluded_required_checks=["Image"]
        )
        root_workflow = {
            "name": "CI",
            "jobs": {
                "test": {
                    "uses": "external-owner/actions-workflows/.github/workflows/test.yaml@main"
                }
            },
        }
        reusable_workflow = {
            "name": "Test",
            "on": {"workflow_call": {}},
            "jobs": {
                "image": {"name": "Image", "runs-on": "ubuntu-latest"},
                "lint": {"name": "Lint", "runs-on": "ubuntu-latest"},
            },
        }

        enforcer.fetch_workflow_definition = lambda owner, repo, path, ref: (  # type: ignore[method-assign]
            reusable_workflow
            if (owner, repo, path, ref)
            == (
                "external-owner",
                "actions-workflows",
                ".github/workflows/test.yaml",
                "main",
            )
            else None
        )

        checks = enforcer.extract_job_names_for_workflow(
            "repo-owner", "app", root_workflow
        )

        self.assertEqual(checks, {"Test / Lint"})

    def test_mixed_local_and_remote_nested_reusable_workflows(self) -> None:
        root_workflow = {
            "name": "CI",
            "jobs": {"local": {"uses": "./.github/workflows/local.yaml"}},
        }
        local_workflow = {
            "name": "Local",
            "on": {"workflow_call": {}},
            "jobs": {
                "remote": {
                    "uses": "external-owner/actions-workflows/.github/workflows/test.yaml@v1"
                }
            },
        }
        remote_workflow = {
            "name": "Test",
            "on": {"workflow_call": {}},
            "jobs": {"image": {"name": "Image", "runs-on": "ubuntu-latest"}},
        }

        definitions = {
            (
                "repo-owner",
                "app",
                ".github/workflows/local.yaml",
                "feature/refactor",
            ): local_workflow,
            (
                "external-owner",
                "actions-workflows",
                ".github/workflows/test.yaml",
                "v1",
            ): remote_workflow,
        }
        self.enforcer.fetch_workflow_definition = lambda owner, repo, path, ref: (  # type: ignore[method-assign]
            definitions.get((owner, repo, path, ref))
        )
        self.enforcer._default_branch_for_repository = lambda repository: "main"  # type: ignore[method-assign]

        checks = self.enforcer.extract_job_names_for_workflow(
            "repo-owner", "app", root_workflow, workflow_ref="feature/refactor"
        )

        self.assertEqual(checks, {"Test / Image"})


if __name__ == "__main__":
    unittest.main()
