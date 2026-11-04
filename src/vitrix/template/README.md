# My detections

Detection-as-Code with [Vitrix](https://github.com/davivers/vitrix): Sigma rules, test cases and replay logs in Git, validated by CI.

```
vitrix.yml        project configuration (targets, quality gate, GitHub, accounts)
mappings.yml      query mappings and final language defaults; written by the app (Editor / Settings), appears after the first change
rules/            Sigma rules (the source of truth)
cases/            test cases, same path as the rule
datasets/         logs for replay, with <name>.expect.yml expectations
.github/          the CI workflow that validates every change
```

## Work on it

```bash
vitrix check --strict --gate   # lint + conversion + tests + replay + quality gate
vitrix serve                   # the web UI on http://127.0.0.1:8000
```

## Connect it to GitHub (to publish from the UI)

Create an empty repository on GitHub, then in this folder (one command per line):

```
gh auth login                        # once, with the GitHub CLI: https://cli.github.com
vitrix connect your-org/your-repo    # links this folder and checks every step
vitrix serve
```

`vitrix connect` prints ✓ for each step that is ready and the exact command for the first one that is not (usually the first `git push`). Run it again until everything is ✓. Nothing to edit in `vitrix.yml`.

From then on, **Publish** in the Editor pushes a `vitrix/...` branch, waits for the real CI in `.github/workflows/vitrix.yml`, and only then opens the pull request.

The two example rules and their cases are only a starting point: edit or delete them.
