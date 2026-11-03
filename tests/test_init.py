"""`vitrix init` and the project template: what a user gets on day one."""

from __future__ import annotations

import yaml
from test_engine import run

from vitrix.cli import TEMPLATE_DIR, main


def test_init_creates_a_complete_repository_with_dotfiles(tmp_path):
    repo = tmp_path / "detections"
    assert main(["init", str(repo)]) == 0
    files = {p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.is_file()}
    assert {"vitrix.yml", "README.md", ".gitignore", ".github/workflows/vitrix.yml", "rules/windows/powershell_encoded.yml",
            "cases/windows/powershell_encoded.yml", "datasets/windows_attack_simulation.jsonl"} <= files
    assert not any(part.startswith("_") for f in files for part in f.split("/"))  # `_github` became `.github`


def test_init_never_overwrites_without_force(tmp_path, capsys):
    repo = tmp_path / "detections"
    main(["init", str(repo)])
    (repo / "vitrix.yml").write_text("schema_version: 1\n# mine\n", encoding="utf-8")
    assert main(["init", str(repo)]) == 2
    assert "already has" in capsys.readouterr().err
    assert "# mine" in (repo / "vitrix.yml").read_text(encoding="utf-8")
    assert main(["init", str(repo), "--force"]) == 0
    assert "# mine" not in (repo / "vitrix.yml").read_text(encoding="utf-8")


def test_the_new_repository_passes_everything_out_of_the_box(user_repo):
    cfg = str(user_repo)
    assert run(cfg, "check", "--strict", "--gate") == 0
    assert run(cfg, "replay") == 0


def test_the_template_points_at_nobody_elses_repository():
    config = (TEMPLATE_DIR / "vitrix.yml").read_text(encoding="utf-8")
    assert "davivers" not in config  # the user's repository, never the project's
    assert not [line for line in config.splitlines() if line.startswith("github:")]  # GitHub is opt-in, as a commented example
    assert "your-org/your-detections" in config


def test_the_template_workflow_runs_on_the_branches_the_ui_pushes():
    wf = yaml.safe_load((TEMPLATE_DIR / "_github" / "workflows" / "vitrix.yml").read_text(encoding="utf-8"))
    assert wf["name"] == "vitrix"  # the `workflow:` name the config example refers to
    assert "vitrix/**" in wf[True]["push"]["branches"]  # `on` is parsed as the boolean True by YAML 1.1
    steps = " ".join(str(s.get("run", "")) for s in wf["jobs"]["validate"]["steps"])
    assert "vitrix check --strict --gate" in steps


def test_the_project_itself_has_no_example_detections_in_its_root():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    assert not (root / "rules").exists() and not (root / "vitrix.yml").exists()  # the product repo is not a detections repo


def test_init_next_steps_work_in_windows_powershell(tmp_path, capsys):
    """Windows PowerShell 5.1 rejects `&&`: the printed next steps must be one command per line."""
    main(["init", str(tmp_path / "repo")])
    out = capsys.readouterr().out
    assert "&&" not in out
    assert "git init\n" in out and "vitrix check --strict --gate" in out


def test_python_version_is_capped_where_dependencies_have_wheels():
    """pip must refuse clearly on an unsupported Python instead of compiling PyYAML (needs MSVC on Windows)."""
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.10,<3.15"' in text
