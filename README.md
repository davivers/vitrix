<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="brand/vitrix-logo-on-dark.svg">
  <img src="brand/vitrix-logo-on-light.svg" alt="Vitrix" width="300">
</picture>

**Write once. Detect on any SIEM.**

Detection-as-Code for [Sigma](https://sigmahq.io) rules: validate, test, replay, gate and ship through your own CI.

[![CI](https://github.com/davivers/vitrix/actions/workflows/ci.yml/badge.svg)](https://github.com/davivers/vitrix/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10-3.14](https://img.shields.io/badge/python-3.10%E2%80%933.14-3776AB.svg)](pyproject.toml)
[![Status: alpha](https://img.shields.io/badge/status-alpha%200.1.0-orange.svg)](#limits-of-this-version)

<img src="docs/images/demo.gif" alt="Demo: edit a Sigma rule in the Vitrix editor, the Tests tab passes, Replay runs on local logs, and the quality gate shows Approved" width="860">

[Quickstart](#quickstart) · [Features](#features) · [Roles and security](#roles-and-security) · [CLI](#cli-cheat-sheet) · [Reference](#reference) · [Contributing](#contributing)

</div>

---

## What is Vitrix

Vitrix is a local tool for teams that keep detections as code. You write rules in Sigma; Vitrix checks them, converts them to the query language of each SIEM, runs your test cases and replays local logs against them. Nothing reaches your repository until a quality gate approves the rule and **your real CI passes for that exact commit**.

It needs no SIEM and sends nothing off your machine (GitHub is the only optional connection).

```mermaid
flowchart LR
    A[Write<br/>Sigma rule] --> B[Validate<br/>lint + convert]
    B --> C[Test<br/>typed cases]
    C --> D[Replay<br/>local logs]
    D --> E{Quality gate<br/>health score}
    E -- approved --> F[Publish<br/>push vitrix/* branch]
    F --> G[Real CI passes<br/>same commit]
    G --> H[Pull request]
    E -. blocked .-> A
```

Not ready to publish? **Save locally** keeps a private draft (stored in `.vitrix/`, never in `rules/`) that you can reopen later from the Editor.

## Quickstart

Vitrix runs **inside your own detections repository**. This repository is the product, not your rules. `vitrix init` creates a detections repo with example rules, test cases, replay logs and a CI workflow.

<details open>
<summary><b>Option 1 - Docker</b> (no Python needed)</summary>

```bash
git clone https://github.com/davivers/vitrix && cd vitrix
docker build -t vitrix .

# first time: create a detections repo in ./detections
mkdir detections
docker run --rm -v "$PWD/detections:/workspace" vitrix init .

# serve the UI at http://localhost:8000
docker run --rm -p 127.0.0.1:8000:8000 -v "$PWD/detections:/workspace" -e VITRIX_GITHUB_TOKEN vitrix
```

With Compose (mounts `./detections`, publishes `127.0.0.1:8000`):

```bash
docker compose run --rm vitrix init .
docker compose up
```

Other commands: `docker run --rm -v "$PWD/detections:/workspace" vitrix check --strict --gate` (also `replay`, `report`). On PowerShell use `${PWD}` instead of `$PWD`. Accounts and drafts live in `detections/.vitrix/`.

**First run.** The image turns accounts on (`VITRIX_AUTH=on`) and generates a one-time setup token (`VITRIX_BOOTSTRAP_TOKEN=auto`). Open the setup link printed in `docker compose logs` (or `docker logs <container>`) to create the workspace owner; Save locally (drafts) then works out of the box. The token is new on every start and only matters until the owner exists. Keep the port on `127.0.0.1`: anyone who holds the link can become the owner. Set `VITRIX_BOOTSTRAP_TOKEN` to your own value (16+ characters) to choose it, or `VITRIX_AUTH=off` to disable accounts (not recommended).

</details>

<details>
<summary><b>Option 2 - Python virtual environment</b> (install scripts)</summary>

Needs Python **3.10 to 3.14** (3.12 recommended) and Git. Python 3.15 is not supported yet (no PyYAML wheel).

```bash
# Linux / macOS
git clone https://github.com/davivers/vitrix && cd vitrix
scripts/install.sh
. .venv/bin/activate
vitrix init ../my-detections && cd ../my-detections
vitrix serve                         # http://127.0.0.1:8000
```

```powershell
# Windows (PowerShell 5.1 or 7; one command per line)
git clone https://github.com/davivers/vitrix; cd vitrix
powershell -File scripts\install.ps1
.\.venv\Scripts\Activate.ps1         # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
vitrix init ..\my-detections; cd ..\my-detections
vitrix serve                         # http://127.0.0.1:8000
```

PyPI (soon, not published yet): `pip install vitrix` will work once the first release is out.

Without cloning, install straight from GitHub: `scripts/install.sh "vitrix[api] @ git+https://github.com/davivers/vitrix"` (Windows: `scripts\install.ps1 -Target "vitrix[api] @ git+https://github.com/davivers/vitrix"`).
`vitrix: command not found` means the virtual environment is not active; activate it in each new terminal.

</details>

<details>
<summary><b>Option 3 - From source</b> (developing Vitrix)</summary>

```bash
git clone https://github.com/davivers/vitrix && cd vitrix
python -m venv .venv && . .venv/bin/activate     # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
vitrix init ../scratch-detections && cd ../scratch-detections    # this repo's root has no detections
vitrix check --strict --gate && vitrix serve
```

UI development: `cd web && npm install && npm run dev` (port 5173, proxies `/api` to :8000).

</details>

### Connect to GitHub (to publish)

Create `your-org/your-repo` empty on GitHub, then, inside your detections folder:

```bash
gh auth login                        # once; Vitrix uses the GitHub CLI token
vitrix connect your-org/your-repo    # git remote + token + push access + workflow, one check at a time
vitrix serve
```

`vitrix connect` prints the exact command for the first missing step; run it until everything is checked. Without the CLI, put a fine-grained token (Contents and Pull requests read/write, Actions read) in `VITRIX_GITHUB_TOKEN`. `vitrix.yml` has a `github:` section for overrides; `github: false` turns GitHub off.

## Features

| Feature | What it gives you |
|---|---|
| **Editor** | One rule, everything live: validation, queries per SIEM, test cases, quality gate, **Replay** on local datasets (matches vs expectations, matched events, timing) and impact vs the saved rule |
| **Quality gate** | Blocking checks plus a 0-100 health score; a rule is approved only with no blocker and a score at or above `min_score` (default 80) |
| **Test cases** | Typed cases (positive, negative, false positive, edge) run by a local evaluator; exclusions are proven |
| **Log replay** | Run rules on JSON/JSONL/YAML logs with `<dataset>.expect.yml` regression expectations |
| **MITRE ATT&CK coverage** | Matrix of tactics and techniques from your rule tags, drill-down to rules, ATT&CK Navigator export |
| **CI-first publishing** | Pushes a `vitrix/*` branch; the pull request opens only after the real CI passed for that exact commit (checked again server-side) |
| **Local drafts** | "Save locally" keeps work in progress in `.vitrix/drafts.db`; list, reopen, delete from the Editor |
| **Multi-SIEM output** | Splunk SPL, Microsoft KQL, Elastic EQL and more via pySigma; the final language is chosen per rule |
| **Regex Workbench** | Test regexes safely (subprocess + timeout); open to every role |
| **Dashboards and reports** | Operational and Executive views, Git-history trends, Markdown/JSON reports |
| **Team and audit** | Roles, invites, audit log; light and dark themes (choose in the user menu) |

### Screenshots

![Editor: live validation, quality gate and replay](docs/images/editor.png)

![MITRE ATT&CK coverage matrix](docs/images/coverage.png)

![Rules with gate status](docs/images/rules.png)

## Roles and security

Accounts are **on by default**: the first screen creates the owner. Opt out with `auth.enabled: false` in `vitrix.yml` or `VITRIX_AUTH=off` (single local user, no login). `VITRIX_AUTH` beats the file. When the server listens on a non-local address (`--host 0.0.0.0`) and no `VITRIX_BOOTSTRAP_TOKEN` is set, a one-time setup token is generated and its link printed in the log; on `127.0.0.1` the first account needs no token. One server is one workspace. The **first account becomes the owner**; after that registration is **by invitation only** (an invite is a single-use link bound to one email).

| Role | Can do |
|---|---|
| `viewer` | Read everything; use pure-compute tools (Regex Workbench, validate, replay, impact); open the Editor read-only (Save and Publish are disabled) |
| `editor` | Everything a viewer can, plus save local drafts and publish rules through CI |
| `admin` | Plus Settings, Connections and inviting people |
| `owner` | Plus managing admins and the workspace |

Role changes apply on the next request; people are not signed out.

> **Warning.** With accounts off (`auth.enabled: false` / `VITRIX_AUTH=off`) the API has **no authentication**: keep it on `127.0.0.1` (the default; the Docker examples publish `127.0.0.1:8000` only). Never expose it without auth. To go beyond localhost: keep accounts on, put TLS or a reverse proxy in front, and set `VITRIX_ALLOWED_HOSTS=<public hostname>` (plus `VITRIX_PUBLIC_URL` and `VITRIX_COOKIE_SECURE=1` where applicable). The GitHub token comes only from the environment, never from `vitrix.yml`.

Sessions are opaque tokens in an `HttpOnly`, `SameSite=Lax` cookie (only the hash is stored); passwords use salted scrypt; every action lands in the audit log. Regexes from users run in a subprocess with a timeout.

## CLI cheat sheet

| Command | What it does |
|---|---|
| `vitrix init [dir] [--force]` | Create a detections repository from the template (never overwrites without `--force`) |
| `vitrix connect [owner/repo]` | Link the folder to GitHub and CI; checks each step |
| `vitrix lint [--strict]` | Schema, modifiers, regex, condition, ATT&CK tags, duplicated logic |
| `vitrix convert [-t target] [--stdout]` | Convert to the configured SIEMs and write `dist/` |
| `vitrix test` | Run `cases/` with the local evaluator |
| `vitrix check [--strict] [--gate] [--markdown FILE]` | Lint + convert + test for CI; `--gate` adds replay and the quality gate |
| `vitrix gate` | Lifecycle and quality gate per rule, with health score |
| `vitrix replay [dataset] [-f file]` | Run rules on logs and check expected match counts |
| `vitrix report [--format md\|json] [-o file]` | Full report in one document |
| `vitrix targets` | List available SIEM targets |
| `vitrix serve [--host H] [--port N]` | Local API and web UI |

Exit codes: `0` ok, `1` rule failures, `2` usage or configuration error.

## Configuration

`vitrix init` writes a documented `vitrix.yml`. The essentials:

```yaml
schema_version: 1
rules_dir: rules
cases_dir: cases
datasets_dir: datasets
targets: [splunk, kql, elastic-eql]
default_target: splunk
quality_gate:
  min_positive: 1
  min_negative: 1
  min_score: 80
auth:
  enabled: true       # default; false = no accounts (localhost only)
```

## Project layout

Your detections repository (created by `vitrix init`):

```
vitrix.yml          configuration           rules/      Sigma rules (source of truth)
cases/              test cases (same path)  datasets/   replay logs + <name>.expect.yml
dist/               compiled queries (CI)   .github/    the CI workflow
.vitrix/            accounts and drafts (git-ignored)
```

This repository (the product): `src/vitrix/` engine, API, compiled UI and project template; `web/` UI source (React, TypeScript, Tailwind); `tests/`; `brand/`; `Dockerfile`, `docker-compose.yml`, `scripts/`.

## Contributing

```bash
pip install -e ".[dev]"
pytest
ruff check src tests && bandit -c pyproject.toml -r src -q
cd web && npm install && npm run typecheck && npm run build   # build goes to src/vitrix/ui/: commit it
```

Everything (code, UI, docs) is in English. Every behaviour change needs a test. CI runs tests, lint and security, checks the UI build is up to date, and installs a built wheel in a fresh venv (`init`, `check --gate`, `replay`, serve).

## License

MIT. See [LICENSE](LICENSE).

---

## Reference

Detailed reference for rules, targets and the API.

## Test cases

For `rules/windows/x.yml` the engine reads `cases/windows/x.yml`:

```yaml
cases:
  - name: Positive · powershell -enc
    expect: match            # or no_match
    event:
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell.exe -enc JABz'
```

With `require_cases: true` (default) every rule needs at least one `match` and one `no_match` case. Events use the field names of the Sigma rule itself, before any SIEM field mapping. Each case may say what it represents with `kind`:

| `kind` | What it is | `expect` |
|---|---|---|
| `positive` | the malicious behaviour (default for `match`) | `match` |
| `negative` | an ordinary event (default for `no_match`) | `no_match` |
| `false_positive` | legitimate activity that looks like the attack: admin, service account, IT tool | `no_match` |
| `edge` | edge case: missing or null field, casing, boundary value | either |

If the rule has an exclusion (`filter_*`, or a selection negated in the condition), the engine checks whether some `no_match` case **only avoided firing because of the exclusion**, i.e. whether the exception is tested.

## The lifecycle

| Stage | What it checks |
|---|---|
| Validate | YAML, schema and types, modifiers, invalid or catastrophic regex, complexity, ATT&CK tags, duplicated logic across rules, conversion to the final language |
| Test | positive, negative and edge cases; test data quality (repeated event, event without any field the rule uses) |
| Replay | logs in `datasets/` against every rule, with time per rule and expected counts (regression) |
| Analyze | false-positive case, exclusion tested, ATT&CK technique, documented `falsepositives`, periodic review (age from Git) |
| Quality gate | every blocking check passes: "is the rule ready to be published?" |
| Deploy | validated by the real CI and merged; the CI builds `dist/` (direct push to a SIEM does not exist yet) |

Each rule gets a **health score** (0–100): applicable checks that pass, blocking ones weigh 3, recommendations 1. A blocked rule never scores above 69. A rule is **approved** when nothing blocks it *and* its score reaches `min_score`; the Editor shows the score against the required minimum and only approved rules can be published.

```yaml
quality_gate:               # defaults shown
  min_positive: 1
  min_negative: 1
  false_positive_levels: [high, critical]   # these levels require a kind: false_positive case
  require_filter_test: true                 # a rule with filter_* needs a case proving the exclusion
  require_mitre: true
  allow_warnings: true                      # false: any lint warning blocks
  blocked_status: [deprecated, unsupported]
  require_replay: false                     # true: the rule needs an expectation in some dataset
  review_days: 180                          # recommend a review after N days without a change (0 = off)
  min_score: 80                             # health score a rule needs to be APPROVED (0 = no threshold)
```

### Log replay

A dataset is a file in `datasets/` (JSON, JSON Lines or YAML). Next to it, `<name>.expect.yml` says how many events each rule must match; if a change moves that number, replay and the gate report it:

```yaml
expect:
  windows/powershell_encoded.yml: 2       # exactly 2
  windows/schtasks_system.yml: {min: 1}   # at least 1
others: 0                                 # no other rule may fire
```

The example repository ships `datasets/windows_attack_simulation.jsonl`: an attack simulation (encoded PowerShell, persistence through a scheduled task, LSASS dump) mixed with legitimate activity.

### Regex Workbench

A lab to write and optimise regex with the same engine as the local tests: match highlighting, groups, time per sample, tips (nested quantifier, needless `.*`, unescaped Windows path backslash, when `contains` is enough) and the snippet ready for the Sigma rule. Every run is a separate process with a timeout.

## Final language of each rule

Each rule ships in one SIEM language. The engine decides, from the most specific to the most general:

1. **In the rule itself**, with `vitrix.target` (a name or a list):

   ```yaml
   vitrix:
     target: kql
   ```

2. **By route** in `vitrix.yml`: the first whose `match` fits the path inside `rules/` (`*` also crosses folders).

   ```yaml
   routes:
     - match: "azure/*"
       target: kql
   ```

3. **`default_target`** in `vitrix.yml`.
4. Otherwise the rule is converted for every active target.

`vitrix convert -t NAME` ignores all of this and forces one target. `dist/manifest.json` records, per rule, the targets and where the choice came from (`target_source`). The lint reports unknown targets and malformed `vitrix` blocks. A rule whose final-language conversion fails shows as failing; the preview in other SIEMs in the Editor never fails a rule.

## Built-in targets and plugins

`splunk` (SPL), `kql` (Defender/Sentinel), `elastic-eql`, `elastic-lucene`. For the field mapping of your environment, point to pySigma pipelines in `extra_pipelines` in `vitrix.yml`; they run before the SIEM's default mapping.

To add a SIEM without touching the engine, publish a package with an entry point:

```toml
[project.entry-points."vitrix.targets"]
my-siem = "my_package.target:target"
```

`target` is a `vitrix.backends.Target` (name, label, extension and a factory returning a pySigma backend).

## API

`vitrix serve` exposes an HTTP API on `127.0.0.1:8000` (interactive docs at `/docs`). It reuses the CLI engine, so UI numbers match `vitrix check`.

| Route | Returns |
|---|---|
| `GET /api/stats`, `/api/rules`, `/api/rules/{id}` | Dashboard numbers; every rule with its state; one rule with lint, queries per SIEM and tests. `id` is the path inside `rules/`. |
| `POST /api/validate` | Validates an unsaved rule (`{"rule", "cases", "path"}`), including its quality gate. |
| `POST /api/impact` | Impact analysis: saved rule vs. edited version on the datasets. |
| `GET /api/quality[/{id}]` | The lifecycle and quality gate, rule by rule. |
| `GET /api/tests`, `/api/coverage`, `/api/coverage/navigator` | Test suites by kind; ATT&CK matrix and data sources; an ATT&CK Navigator layer. |
| `GET /api/history[/{id}]` | Git history: coverage over time, activity, audit trail per rule. |
| `GET /api/datasets`, `/api/datasets/{name}/replay`, `POST /api/replay` | Replay of datasets or pasted events. |
| `POST /api/regex` | Regex Workbench. |
| `GET /api/report?format=md\|json` | Consolidated report. |
| `GET /api/config`, `POST /api/config/validate` | Effective configuration and validation of an edited `vitrix.yml`. |
| `GET /api/github`, `/api/github/activity` | Configuration and token status (never the token); open PRs, CI runs, time to merge (60 s cache). |
| `POST /api/ci/rules`, `POST /api/ci/config` | Step 1: push a branch so the real CI validates the change. |
| `GET /api/ci/status?commit=SHA` | State of the real CI for that exact commit (`none`, `pending`, `failure`, `success`). |
| `/api/auth/*`, `/api/workspace/*` | Accounts (register, login, logout, password, GitHub OAuth), members, roles, invites and the audit log. Public: `/api/auth/config`, `/api/auth/me`, login, register, the GitHub flow, `/api/health`. |
| `POST /api/pull-requests` | Step 2: `{"branch", "commit"}`. Refused with 409 unless CI passed for that commit. |

API limits:
- **Nothing is written to the local disk.** The only writes go to GitHub, with the token from the environment, always CI first and then the PR.
- **Authentication is on by default** (`auth.enabled`, off only by explicit opt-out), so the first visit creates the owner. With it off there is none and the API should only listen on localhost. With it on, every route except the public ones needs a session and a role (reads: viewer; computing and publishing rules: editor; anything else that writes: admin). Every request is checked (`Host` against DNS rebinding; `Origin` and JSON-only bodies against CSRF; `VITRIX_ALLOWED_HOSTS` allows other hosts). `vitrix serve --host` with another address prints a warning. Do not expose it without an authenticating proxy.
- CORS is off. For a UI on another origin set `VITRIX_CORS_ORIGINS=http://localhost:5173`.

## Limits of this version

- **Syntax validation per target:** pySigma conversion is the validation. The engine does not check the query with each SIEM's parser yet.
- **Local evaluator:** covers a subset of Sigma (see the header of `src/vitrix/evaluator.py`). Modifiers such as `windash`, `base64`, `cidr` and aggregation conditions **fail explicitly**, never silently. The lint warns when a rule is outside that subset.
- **ATT&CK validation** checks the format of tactics and techniques, not their existence in MITRE's data.
- **Deploy:** there are no adapters to push rules to a SIEM yet. The result is the `dist/` built by CI.

