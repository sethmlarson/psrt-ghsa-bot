import datetime

import mock
import pytest

import app


@pytest.fixture()
def year() -> str:
    return str(datetime.date.today().year)


@pytest.fixture
def cve_id(year):
    return f"CVE-{year}-0000"


@pytest.fixture
def cve_reserve_response(cve_id, year):
    # See: https://github.com/CVEProject/cve-services/blob/dev/schemas/cve-id/create-cve-ids-response.json
    return {
        "meta": {"remaining_quota": 1000},
        "cve_ids": [
            {
                "cve_id": cve_id,
                "cve_year": year,
                "owning_cna": "PSF",
                "state": "RESERVED",
                "requested_by": {"cna": "PSF", "user": "cna@python.org"},
                "requested": "2024-01-01T00:00:00Z",
            }
        ],
    }


@pytest.mark.parametrize("state", ["draft", "triage"])
def test_adds_psrt_github_team_to_security_advisories(state):
    security_advisory = mock.Mock()
    security_advisory.state = state
    security_advisory.cve_id = "CVE-0000-0000"
    security_advisory.collaborating_teams = []

    repo = mock.Mock()
    cve_api = mock.Mock()

    with mock.patch("app.get_repository_advisories") as get_repo_advs:
        get_repo_advs.return_value = [security_advisory]

        app.apply_to_repo(repo, cve_api)

    security_advisory.edit.assert_called_once_with(collaborating_teams=["python/psrt"])


@pytest.mark.parametrize("state", ["draft", "triage"])
def test_appends_psrt_github_team_to_security_advisories(state):
    security_advisory = mock.Mock()
    security_advisory.state = state
    security_advisory.cve_id = "CVE-0000-0000"
    security_advisory.collaborating_teams = ["python/other-team"]

    repo = mock.Mock()
    cve_api = mock.Mock()

    with mock.patch("app.get_repository_advisories") as get_repo_advs:
        get_repo_advs.return_value = [security_advisory]

        app.apply_to_repo(repo, cve_api)

    security_advisory.edit.assert_called_once_with(
        collaborating_teams=["python/psrt", "python/other-team"]
    )


@pytest.mark.parametrize("state", ["draft", "triage"])
def test_adds_psrt_github_team_to_security_advisories(state):
    security_advisory = mock.Mock()
    security_advisory.state = state
    security_advisory.cve_id = "CVE-0000-0000"
    security_advisory.collaborating_teams = []

    repo = mock.Mock()
    cve_api = mock.Mock()

    with mock.patch("app.get_repository_advisories") as get_repo_advs:
        get_repo_advs.return_value = [security_advisory]

        app.apply_to_repo(repo, cve_api)

    security_advisory.edit.assert_called_once_with(collaborating_teams=["python/psrt"])


@pytest.mark.parametrize("state", ["closed", "published"])
def test_does_not_modify_completed_security_advisories(state):
    security_advisory = mock.Mock()
    security_advisory.state = state
    security_advisory.cve_id = None
    security_advisory.collaborating_teams = []

    repo = mock.Mock()
    cve_api = mock.Mock()

    with mock.patch("app.get_repository_advisories") as get_repo_advs:
        get_repo_advs.return_value = [security_advisory]

        app.apply_to_repo(repo, cve_api)

    security_advisory.edit.assert_not_called()


def test_reserves_cve_id_for_draft_security_advisories(
    year, cve_id, cve_reserve_response
):
    security_advisory = mock.Mock()
    security_advisory.state = "draft"
    security_advisory.cve_id = None
    security_advisory.collaborating_teams = ["python/psrt"]

    repo = mock.Mock()
    cve_api = mock.Mock()
    cve_api.reserve.return_value = cve_reserve_response

    with mock.patch("app.get_repository_advisories") as get_repo_advs:
        get_repo_advs.return_value = [security_advisory]

        app.apply_to_repo(repo, cve_api)

    cve_api.reserve.assert_called_with(count=1, year=year, random=True)
    security_advisory.edit.assert_called_once_with(cve_id=cve_id)


@pytest.mark.parametrize("state", ["triage", "closed", "published"])
def test_does_not_reserve_cve_id_for_triage_security_advisories(state):
    security_advisory = mock.Mock()
    security_advisory.state = state
    security_advisory.cve_id = None
    security_advisory.collaborating_teams = ["python/psrt"]

    repo = mock.Mock()
    cve_api = mock.Mock()

    with mock.patch("app.get_repository_advisories") as get_repo_advs:
        get_repo_advs.return_value = [security_advisory]

        app.apply_to_repo(repo, cve_api)

    cve_api.reserve.assert_not_called()
    security_advisory.edit.assert_not_called()


def test_reserve_one_cve_id(cve_reserve_response, cve_id, year):
    cve_api = mock.Mock()
    cve_api.reserve.return_value = cve_reserve_response

    assert app.reserve_one_cve(cve_api) == cve_id

    cve_api.reserve.assert_called_with(count=1, year=year, random=True)
