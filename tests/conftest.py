"""Configuração comum dos testes."""

import os

# O TestClient do Starlette manda `Host: testserver`. A API só aceita localhost e o que estiver
# em VITRIX_ALLOWED_HOSTS (defesa contra DNS rebinding), então liberamos esse nome nos testes.
os.environ.setdefault("VITRIX_ALLOWED_HOSTS", "testserver")
# Tests never pick up the developer's GitHub CLI login.
os.environ["VITRIX_GH_CLI"] = "0"


import pytest  # noqa: E402


@pytest.fixture
def user_repo(tmp_path):
    """A detections repository exactly as a user gets it: `vitrix init` into an empty folder."""
    from vitrix.cli import main

    repo = tmp_path / "my-detections"
    assert main(["init", str(repo)]) == 0
    with (repo / "vitrix.yml").open("a", encoding="utf-8") as fh:  # accounts are ON by default; API tests act as one local user
        fh.write("\nauth:\n  enabled: false\n")
    return repo / "vitrix.yml"
