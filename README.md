# Vitrix

Detection-as-Code without depending on a SIEM. You write rules in [Sigma](https://sigmahq.io); Vitrix **validates**, **converts** them for several SIEMs, **tests** each rule with sample events, **replays** local logs, applies a **quality gate** and ships changes through your **real CI** — all local and inside your own pipeline.

> Version 0.1.0, alpha. Chosen name: Vitrix (domain and trademark still to be checked).

**Write → Validate → Test → Replay → Analyze → Quality gate → Deploy**

## Getting started

**This repository is the Vitrix product, not your detections.** You install Vitrix and run it inside your own detections repository (a Git repo with your Sigma rules):

**Requirements:** Python **3.10 to 3.14** (3.12 recommended) and Git. Python 3.15 is not supported yet: PyYAML has no prebuilt wheel for it, so pip would try to compile it and ask for Microsoft Visual C++. Always install into a virtual environment.

**Windows (PowerShell)** — one command per line; Windows PowerShell 5.1 does not accept `&&`:

```powershell
# 1. a virtual environment with Python 3.12 (the `py` launcher ships with Python for Windows)
py install 3.12                 # only if `py -0` does not list 3.12 yet
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1    # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

# 2. install Vitrix (PyPI soon, for now straight from GitHub)
pip install "vitrix[api] @ git+https://github.com/davivers/vitrix.git"

# 3. create your detections repository: vitrix.yml, example rules, test cases, replay logs, CI workflow
vitrix init my-detections
cd my-detections

# 4. work on it
vitrix check --strict --gate    # lint + conversion + tests + replay + quality gate
vitrix serve                    # the web UI on http://127.0.0.1:8000

# 5. make it yours: commit, push to your own repository, then set github.repo in vitrix.yml
git init
git add -A
git commit -m "Initial detections"
```

**Linux / macOS (bash, zsh):**

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install "vitrix[api] @ git+https://github.com/davivers/vitrix.git"
vitrix init my-detections && cd my-detections
vitrix check --strict --gate && vitrix serve
git init && git add -A && git commit -m "Initial detections"
```

`vitrix: command not found` / `not recognized` means the install failed or the virtual environment is not active (activate it again in each new terminal).

`vitrix init` copies a small template: two example Sigma rules with typed test cases, an attack-simulation dataset with expectations, a `vitrix.yml` with every option documented, and `.github/workflows/vitrix.yml` (the CI that validates each change). Edit or delete the examples. To publish from the UI (CI first, then the pull request) see [Publishing](#publishing-real-ci-first-then-the-pull-request).

| Command | What it does |
|---|---|
| `vitrix init [dir] [--force]` | Creates a new detections repository from the template. Never overwrites without `--force`. |
| `vitrix lint [--strict]` | Schema, types, modifiers, regex, condition, metadata, ATT&CK tags and duplicated logic. `--strict` fails on warnings. |
| `vitrix convert [-t target] [--stdout]` | Converts to the targets in `vitrix.yml` and writes `dist/` (with `manifest.json`). |
| `vitrix test` | Runs `cases/` with the local evaluator. |
| `vitrix check [--strict] [--gate] [--markdown FILE]` | Lint + convert + test for CI; `--gate` adds replay and the quality gate; `--markdown "$GITHUB_STEP_SUMMARY"` publishes the summary. |
| `vitrix gate` | The lifecycle and the quality gate, rule by rule, with a health score. |
| `vitrix replay [dataset] [-f file]` | Runs the rules against logs in `datasets/` and checks the expected match counts. |
| `vitrix report [--format md\|json] [-o file]` | Quality gate, tests, coverage, data sources, replay and Git history in one document. |
| `vitrix targets` | Lists the available SIEMs. |
| `vitrix serve [--port N]` | Local API and web UI. |

Exit codes: `0` all good, `1` rule failures, `2` usage or configuration error.

## Web UI

`vitrix serve` opens the API and the UI at `http://127.0.0.1:8000`. The UI ships compiled inside the package: no Node needed to use it.

| Group | Screens |
|---|---|
| Overview | **Operational** (pipeline, path to publication, needs-attention list, coverage, CI, PRs, recent changes) and **Executive** (ATT&CK coverage over time, ready to publish, health, time to merge, contributors, data sources, gaps) |
| Detections | **Rules** (with health score and last change), **Editor** and **Regex Workbench** |
| Validation | **Test Suites** (rule list + case viewer), **Log Replay**, **MITRE Coverage** (column and pie charts, data sources, ATT&CK Navigator export), **Quality Gate** and **Reports** |
| System | **Team** (members, roles, invites, audit log), **Connections** (GitHub and SIEMs) and **Settings** (edits `vitrix.yml`, validates it and ships it through CI) |

CI and PR numbers only appear when GitHub is connected; otherwise the screen says what is missing instead of showing invented data. Charts use one violet series or a categorical palette validated for the dark background, always with the numbers written (never colour alone). The sidebar ends with the **account menu** (avatar, name, role; Team, Settings, Connections, Change password, Sign out).

### The Editor

Everything about one rule in one place: live validation, the **quality gate inside the editor**, the queries per SIEM, test cases by kind, **impact analysis** (the edited rule vs. the saved one on the same datasets) and the **audit trail** from Git history.

The gate **approves** a rule: no blocking check fails *and* its health score reaches `quality_gate.min_score` (default 80). The editor shows *Approved* or *Not approved*, the score against the required minimum on a 0–100 bar, the lifecycle track and every check. Only an approved rule can be published.

### Publishing: real CI first, then the pull request

A pull request can only be opened after the repository's **real CI (GitHub Actions) has passed for the exact commit**. Local tests are not enough.

1. **Local quality gate** must pass (the server refuses to send a blocked rule).
2. **Validate in CI**: Vitrix pushes a `vitrix/...` branch with one commit; your workflow runs on it.
3. **Open pull request**: unlocked only when every workflow run for that commit succeeded. The server checks this again right before opening the PR (and that the branch still points to the validated commit), so the UI cannot skip it.

Nothing is written to the local disk. The workflow must run on `vitrix/**` branches; the one `vitrix init` puts in your repository (`.github/workflows/vitrix.yml`) does.

```yaml
# vitrix.yml
github:
  repo: my-org/detections
  base: main       # default: main
  path: ""         # project folder inside the repository, if not the root
  workflow: vitrix # optional: only runs of this workflow count as CI validation
```

The token comes from the environment of `vitrix serve`, never from `vitrix.yml`:

```bash
export VITRIX_GITHUB_TOKEN=github_pat_...   # or GITHUB_TOKEN
vitrix serve
```

A fine-grained token limited to the repository is enough: **Contents** and **Pull requests** (read/write), **Actions** (read).

For development: `cd web && npm install && npm run dev` (proxy to the API on :8000); `npm run build` compiles into `src/vitrix/ui/` (commit the result).

## Workspace: several people, one tenant

By default Vitrix is a single local user. Turn on accounts to let a team work in the same workspace (one workspace = one detection repository):

```yaml
# vitrix.yml
auth:
  enabled: true
  allow_signup: false   # after the first account, registration is by invitation
  signup_role: viewer   # role of self-registered people, if allow_signup is true
  session_days: 14
```

- **Register and sign in** with email and password, or **with GitHub** (set `VITRIX_GITHUB_CLIENT_ID` and `VITRIX_GITHUB_CLIENT_SECRET` from a GitHub OAuth app whose callback is `<public url>/api/auth/github/callback`; behind a proxy also set `VITRIX_PUBLIC_URL`).
- The **first account becomes the owner**. Owners and admins invite people from **Team**; an invite is a link bound to one email, single use, valid 7 days (Vitrix does not send emails).
- **Roles**: `viewer` reads everything; `editor` adds the Editor tools, Regex Workbench, replay and publishing rules through CI; `admin` adds Settings changes, members, invites and the audit log; `owner` adds granting owners. The last owner can never be removed or demoted.
- Every action lands in the **audit log** (sign-ins, invites, role changes, rules sent to CI, pull requests). Commits pushed for CI carry a `Submitted-by:` trailer with the person who used the UI (plus `Co-authored-by` when their GitHub account is linked).
- The account menu at the bottom of the sidebar has Team, Settings, Connections, Change password and Sign out.

Security: passwords use salted scrypt; sessions are random opaque tokens in an `HttpOnly`, `SameSite=Lax` cookie (only their hash is stored, a new one on every login, revoked on logout and password change); 5 failed sign-ins lock an email+IP pair for 5 minutes; GitHub sign-in checks an OAuth `state` and links an existing account only through a **verified** GitHub email, and the GitHub token is discarded. Data lives in `.vitrix/vitrix.db` (git-ignored). Set `VITRIX_COOKIE_SECURE=1` (or serve over HTTPS) so the cookie is `Secure`, `VITRIX_ALLOWED_HOSTS` to the host name people use, and `VITRIX_TRUST_PROXY=1` only behind a proxy you control. Serve it over HTTPS (a reverse proxy) when it leaves localhost.

## Layout

Your detections repository (what `vitrix init` creates):

```
vitrix.yml              project configuration
rules/                  Sigma rules (source of truth)
cases/                  test cases, same path as the rule
datasets/               logs for replay, with <name>.expect.yml expectations
dist/                   compiled queries (generated by CI, do not edit)
.github/workflows/      the CI that validates every change (vitrix.yml)
.vitrix/                accounts database when auth is on (git-ignored)
```

This repository (the product):

```
src/vitrix/             the engine, the API, the compiled UI (ui/) and the project template (template/)
web/                    UI source code (React + TypeScript + Tailwind)
tests/                  tests of the engine, the API, auth and the user journey
brand/                  logo and palette
.github/workflows/ci.yml   tests, lint/security, UI build check and a fresh-install user journey
```
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
- **Authentication is opt-in** (`auth.enabled`). Without it there is none, so the API only listens on localhost. With it, every route except the public ones needs a session and a role (reads: viewer; computing and publishing rules: editor; anything else that writes: admin). Every request is checked (`Host` against DNS rebinding; `Origin` and JSON-only bodies against CSRF; `VITRIX_ALLOWED_HOSTS` allows other hosts). `vitrix serve --host` with another address prints a warning. Do not expose it without an authenticating proxy.
- CORS is off. For a UI on another origin set `VITRIX_CORS_ORIGINS=http://localhost:5173`.

## Limits of this version

- **Syntax validation per target:** pySigma conversion is the validation. The engine does not check the query with each SIEM's parser yet.
- **Local evaluator:** covers a subset of Sigma (see the header of `src/vitrix/evaluator.py`). Modifiers such as `windash`, `base64`, `cidr` and aggregation conditions **fail explicitly**, never silently. The lint warns when a rule is outside that subset.
- **ATT&CK validation** checks the format of tactics and techniques, not their existence in MITRE's data.
- **Deploy:** there are no adapters to push rules to a SIEM yet. The result is the `dist/` built by CI.

## Developing Vitrix itself

```bash
git clone https://github.com/davivers/vitrix && cd vitrix
pip install -e ".[dev]"                                   # engine + API + tests + lint (Python 3.10–3.14)
pytest
ruff check src tests && bandit -c pyproject.toml -r src -q

cd web && npm install
npm run dev          # UI on :5173, proxy to the API on :8000
npm run typecheck && npm run build   # compiles into src/vitrix/ui/: commit the result
```

**Try it as a user would.** The repository root has no detections, so run Vitrix on a scratch copy made by `vitrix init`, outside this folder:

```bash
vitrix init ../scratch-detections && cd ../scratch-detections
vitrix check --strict --gate && vitrix serve
```

The `user-journey` CI job does exactly this from a built wheel (install, `init`, `check --gate`, `replay`, serve). The example rules live in `src/vitrix/template/`; a leading `_` in a template file name becomes `.` when copied (`_github` → `.github`).
