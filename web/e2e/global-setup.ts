import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const VITRIX = path.join(ROOT, "venv", process.platform === "win32" ? "Scripts/vitrix.exe" : "bin/vitrix");

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as { port: number };
      srv.close(() => resolve(port));
    });
  });
}

async function waitHealth(url: string, proc: ChildProcess, log: () => string) {
  const end = Date.now() + 40_000;
  while (Date.now() < end) {
    if (proc.exitCode !== null) throw new Error(`vitrix exited early:\n${log()}`);
    try {
      if ((await fetch(`${url}/api/health`)).ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`vitrix did not become healthy at ${url}:\n${log()}`);
}

export const SETUP_TOKEN = "e2e-setup-token-0123456789";

/** A tiny SigmaHQ-shaped archive pre-seeded in the packs cache, so the Content packs screen never touches the network. */
function seedPacksCache(dir: string) {
  const py = path.join(ROOT, "venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
  const cache = path.join(dir, ".vitrix", "cache", "packs");
  mkdirSync(cache, { recursive: true });
  const code = `
import json, sys, time, zipfile, hashlib
cache = sys.argv[1]
def rule(i, title, tech):
    return f"""title: {title}
id: 00000000-0000-4000-8000-00000000000{i}
status: test
description: fixture rule {i}
author: e2e
date: 2026-01-01
tags:
  - attack.{tech[0]}
  - attack.{tech[1]}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '/tool{i}.exe'
  condition: selection
falsepositives:
  - none
level: medium
"""
zp = cache + "/sigmahq-master.zip"
with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("sigma-master/rules/windows/process_creation/proc_tool_one.yml", rule(1, "E2E fixture tool one", ("discovery", "t1082")))
    z.writestr("sigma-master/rules/windows/process_creation/proc_tool_two.yml", rule(2, "E2E fixture tool two", ("execution", "t1059")))
    z.writestr("sigma-master/rules/windows/process_creation/proc_tool_three.yml", rule(3, "E2E fixture tool three", ("persistence", "t1547")))
data = open(zp, "rb").read()
ts = time.time()
json.dump({"url": "fixture", "ref": "master", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
           "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)), "fetched_at_ts": ts + 86400 * 30},
          open(cache + "/sigmahq-master.json", "w"))
`;
  const r = spawnSync(py, ["-I", "-c", code, cache], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`seeding the packs cache failed: ${r.stderr}`);
}

function gitCommit(dir: string) {
  for (const args of [["init", "-q"], ["add", "-A"], ["-c", "user.email=e2e@example.com", "-c", "user.name=e2e", "commit", "-q", "-m", "Initial detections"]]) {
    const r = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
    if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${r.stderr}`);
  }
}

async function start(auth: boolean) {
  const dir = mkdtempSync(path.join(tmpdir(), auth ? "vitrix-e2e-auth-" : "vitrix-e2e-local-"));
  const init = spawnSync(VITRIX, ["init", dir], { encoding: "utf8" });
  if (init.status !== 0) throw new Error(`vitrix init failed: ${init.stderr}${init.stdout}`);
  const yml = path.join(dir, "vitrix.yml");
  if (auth) writeFileSync(yml, readFileSync(yml, "utf8") + "\nauth:\n  enabled: true\n  workspace_name: E2E workspace\n", "utf8");
  gitCommit(dir); // Drift and history need a repository with a commit
  seedPacksCache(dir);
  const port = await freePort();
  let out = "";
  const proc = spawn(VITRIX, ["-c", yml, "serve", "--port", String(port)], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, PYTHONUTF8: "1", ...(auth ? { VITRIX_AUTH: "on", VITRIX_BOOTSTRAP_TOKEN: SETUP_TOKEN } : { VITRIX_AUTH: "off", VITRIX_BOOTSTRAP_TOKEN: "" }) } });
  proc.stdout?.on("data", (d) => (out += d));
  proc.stderr?.on("data", (d) => (out += d));
  const url = `http://127.0.0.1:${port}`;
  await waitHealth(url, proc, () => out);
  return { url, proc };
}

function kill(proc: ChildProcess) {
  if (proc.pid === undefined || proc.exitCode !== null) return;
  if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(proc.pid), "/T", "/F"]);
  else proc.kill("SIGTERM");
}

/** Starts two isolated servers on temp repos: E2E_AUTH_URL (accounts on) and E2E_LOCAL_URL (accounts off). */
export default async function globalSetup() {
  const [auth, local] = await Promise.all([start(true), start(false)]);
  process.env.E2E_AUTH_URL = auth.url;
  process.env.E2E_LOCAL_URL = local.url;
  process.env.E2E_SETUP_TOKEN = SETUP_TOKEN;
  return async () => {
    kill(auth.proc);
    kill(local.proc);
  };
}
