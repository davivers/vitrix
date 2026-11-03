# My detections

Detection-as-Code with [Vitrix](https://github.com/davivers/vitrix): Sigma rules, test cases and replay logs in Git, validated by CI.

```
vitrix.yml        project configuration (targets, quality gate, GitHub, accounts)
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

1. Push this folder to your own repository.
2. In `vitrix.yml` uncomment `github:` and set `repo: your-org/your-detections`.
3. Create a fine-grained token limited to that repository (Contents and Pull requests: read/write; Actions: read) and start the UI with it:

   ```bash
   export VITRIX_GITHUB_TOKEN=github_pat_...
   vitrix serve
   ```

From then on, **Publish** in the Editor pushes a `vitrix/...` branch, waits for the real CI in `.github/workflows/vitrix.yml`, and only then opens the pull request.

The two example rules and their cases are only a starting point: edit or delete them.
