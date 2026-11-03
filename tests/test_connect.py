"""Zero-config GitHub: repository from `git remote origin`, token from the GitHub CLI, `vitrix connect`."""

import shutil
import subprocess

import pytest

from vitrix import github as gh_mod
from vitrix import gitremote
from vitrix.cli import main
from vitrix.config import load_config

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@pytest.mark.parametrize("url, repo", [
    ("https://github.com/acme/detections.git", "acme/detections"),
    ("https://github.com/acme/detections", "acme/detections"),
    ("https://user@github.com/acme/det.ections.git", "acme/det.ections"),
    ("git@github.com:acme/detections.git", "acme/detections"),
    ("ssh://git@github.com/acme/detections.git", "acme/detections"),
    ("https://gitlab.com/acme/detections.git", None),
    ("https://github.com.evil.io/acme/detections.git", None),
    ("/local/path/repo.git", None),
])
def test_parse_remote(url, repo):
    assert gitremote.parse_remote(url) == repo


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


@pytest.fixture
def cloned(tmp_path):
    """A detections repo created by `vitrix init` with a GitHub origin, as after `git clone`."""
    repo = tmp_path / "det"
    assert main(["init", str(repo)]) == 0
    _git(repo, "init", "-b", "main")
    _git(repo, "remote", "add", "origin", "git@github.com:acme/detections.git")
    gitremote._cache.clear()
    return repo


@needs_git
def test_repository_is_detected_from_git_without_editing_vitrix_yml(cloned):
    cfg = load_config(cloned / "vitrix.yml")
    assert cfg.github_source == "git remote"
    assert (cfg.github.repo, cfg.github.base, cfg.github.path, cfg.github.workflow) == ("acme/detections", "main", "", "vitrix")


@needs_git
def test_explicit_section_wins_and_false_turns_it_off(cloned):
    yml = cloned / "vitrix.yml"
    text = yml.read_text(encoding="utf-8")
    yml.write_text(text + "\ngithub:\n  repo: other/repo\n", encoding="utf-8")
    cfg = load_config(yml)
    assert (cfg.github.repo, cfg.github_source) == ("other/repo", "vitrix.yml")
    yml.write_text(text + "\ngithub: false\n", encoding="utf-8")
    cfg = load_config(yml)
    assert cfg.github is None and cfg.github_source is None


def test_no_git_means_not_configured(user_repo):
    gitremote._cache.clear()
    assert load_config(user_repo).github is None


def test_token_prefers_environment_and_never_calls_gh_when_disabled(monkeypatch):
    monkeypatch.setenv("VITRIX_GITHUB_TOKEN", "t1")
    assert gitremote.token() == ("t1", "VITRIX_GITHUB_TOKEN")
    monkeypatch.delenv("VITRIX_GITHUB_TOKEN")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(gitremote, "_gh_token", lambda: pytest.fail("gh must not run"))
    assert gitremote.token() == (None, None)  # conftest sets VITRIX_GH_CLI=0


def test_token_from_github_cli(monkeypatch):
    monkeypatch.delenv("VITRIX_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("VITRIX_GH_CLI", "1")
    monkeypatch.setattr(gitremote, "_gh_cache", None)
    monkeypatch.setattr(gitremote, "_gh_token", lambda: "gho_x")
    assert gitremote.token() == ("gho_x", "gh CLI")


# --------------------------------------------------------------------------- vitrix connect

def _fake_github(monkeypatch, answers):
    calls = []

    def transport(_token):
        def send(method, url, body):
            calls.append(url)
            for suffix, reply in answers.items():
                if url.endswith(suffix):
                    return reply
            return 404, {"message": "Not Found"}
        return send

    monkeypatch.setattr(gh_mod, "_urllib_transport", transport)
    monkeypatch.setenv("VITRIX_GITHUB_TOKEN", "t")
    return calls


ALL_GOOD = {
    "/repos/acme/detections": (200, {"permissions": {"push": True}}),
    "/branches/main": (200, {}),
    "/contents/.github/workflows/vitrix.yml?ref=main": (200, {}),
    "/runs?per_page=1": (200, {"workflow_runs": [{"conclusion": "success", "html_url": "https://github.com/x"}]}),
}


@needs_git
def test_connect_all_green(cloned, monkeypatch, capsys):
    _fake_github(monkeypatch, ALL_GOOD)
    assert main(["-c", str(cloned / "vitrix.yml"), "connect"]) == 0
    out = capsys.readouterr().out
    assert "✗" not in out and "All set" in out and "detected from git" in out


@needs_git
def test_connect_says_exactly_what_to_push(cloned, monkeypatch, capsys):
    _fake_github(monkeypatch, {"/repos/acme/detections": (200, {"permissions": {"push": True}})})
    assert main(["-c", str(cloned / "vitrix.yml"), "connect"]) == 1
    out = capsys.readouterr().out
    assert "✗ Branch main is on GitHub" in out and "git push -u origin main" in out


@needs_git
def test_connect_without_token_points_to_gh_login(cloned, monkeypatch, capsys):
    monkeypatch.delenv("VITRIX_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert main(["-c", str(cloned / "vitrix.yml"), "connect"]) == 1
    assert "gh auth login" in capsys.readouterr().out


@needs_git
def test_connect_sets_up_git_and_origin_in_a_fresh_folder(user_repo, monkeypatch, capsys):
    _fake_github(monkeypatch, ALL_GOOD)
    root = user_repo.parent
    main(["-c", str(user_repo), "connect", "https://github.com/acme/detections"])
    assert gitremote.git(root, "remote", "get-url", "origin") == "https://github.com/acme/detections.git"


@needs_git
def test_connect_refuses_a_different_origin(cloned, capsys):
    assert main(["-c", str(cloned / "vitrix.yml"), "connect", "other/repo"]) == 1
    assert "git remote set-url origin" in capsys.readouterr().out


def test_connect_rejects_garbage(user_repo, capsys):
    assert main(["-c", str(user_repo), "connect", "not a repo"]) == 2
