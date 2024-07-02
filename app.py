"""GitHub application which applies the PSRT process for GitHub Security Advisories"""
import base64
import datetime
import os
import typing

from cvelib.cve_api import CveApi
from github.Auth import AppAuth
from github.GithubIntegration import GithubIntegration
from github.GithubObject import NotSet, Opt
from github.PaginatedList import PaginatedList
from github.Repository import Repository
from github.RepositoryAdvisory import RepositoryAdvisory


class RepositoryAdvisoryWithTeams(RepositoryAdvisory):
    """Patch for PyGithub to support the 'collaborating_teams' field"""

    @property
    def collaborating_teams(self) -> list[str]:
        return self._collaborating_teams.value

    def edit(
        self,
        cve_id: Opt[str] = NotSet,
        collaborating_teams: Opt[list[str]] = NotSet,
    ) -> "RepositoryAdvisoryWithTeams":
        """This is adapted from PyGithub's implementation, but only for the properties we need."""

        assert cve_id is NotSet or isinstance(cve_id, str), cve_id
        assert collaborating_teams is NotSet or (
            isinstance(collaborating_teams, typing.Iterable),
            collaborating_teams
            and all(isinstance(element, str) for element in collaborating_teams),
        )
        patch_parameters: dict[str, typing.Any] = {}
        if cve_id is not NotSet:
            patch_parameters["cve_id"] = cve_id
        if collaborating_teams is not NotSet:
            patch_parameters["collaborating_teams"] = collaborating_teams

        headers, data = self._requester.requestJsonAndCheck(
            "PATCH",
            self.url,
            input=patch_parameters,
        )
        self._useAttributes(data)
        return self

    def _initAttributes(self) -> None:
        self._collaborating_teams = NotSet
        super()._initAttributes()

    def _useAttributes(self, attributes: dict[str, typing.Any]) -> None:
        if "collaborating_teams" in attributes:
            self._collaborating_teams = attributes["collaborating_teams"]
        super()._useAttributes(attributes)


def get_repository_advisories(
    repo: Repository,
) -> typing.Iterable["RepositoryAdvisoryWithTeams"]:
    """Mimics get_repository_advisories(), except injects our own class."""

    return PaginatedList(
        RepositoryAdvisoryWithTeams,
        repo._requester,
        f"{repo.url}/security-advisories",
        None,
    )


def reserve_one_cve(cve_api: CveApi) -> str:
    """Reserves a single CVE ID"""
    resp = cve_api.reserve(count=1, random=True, year=str(datetime.date.today().year))
    cve_ids = [cve["cve_id"] for cve in resp["cve_ids"]]
    assert len(cve_ids) == 1
    return cve_ids[0]


def apply_to_repo(repo: Repository, cve_api: CveApi) -> None:
    """Applies the PSRT GitHub Security Advisory process to the repository."""

    security_advisories = get_repository_advisories(repo)
    for security_advisory in security_advisories:

        # We only operate on in-progress security advisories.
        if security_advisory.state not in ("triage", "draft"):
            continue

        # Maintain a list of updates to make and then submit them all at once.
        edit_kwargs = {}

        # Advisories that are in the 'draft' state without a CVE ID
        # should have one allocated by the PSF CVE Numbering Authority.
        if security_advisory.state == "draft" and security_advisory.cve_id is None:
            cve_id = reserve_one_cve(cve_api)
            edit_kwargs["cve_id"] = cve_id

        # If the PSRT GitHub team hasn't been added to the repository
        # we append it to the advisory.
        if "python/psrt" not in security_advisory.collaborating_teams:
            # Maintain all existing teams during the update.
            edit_kwargs["collaborating_teams"] = ["python/psrt"] + list(
                security_advisory.collaborating_teams
            )

        # Apply updates, if any, to the security advisory.
        if edit_kwargs:
            security_advisory.edit(**edit_kwargs)


def main() -> None:
    gh_client_private_key = base64.b64decode(os.environ["GH_CLIENT_PRIVATE_KEY"]).decode().strip()
    github_app = GithubIntegration(
        auth=AppAuth(os.environ["GH_CLIENT_ID"], gh_client_private_key)
    )
    cve_api = CveApi(
        org="PSF",
        username=os.environ["CVE_USERNAME"],
        api_key=os.environ["CVE_API_KEY"],
        env=os.environ.get("CVE_ENV", "prod"),
    )

    # Apply to all repositories for each installation.
    installations = github_app.get_installations()
    for installation in installations:
        repos = installation.get_repos()
        for repo in repos:
            apply_to_repo(repo, cve_api)


if __name__ == "__main__":
    main()
