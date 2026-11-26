import assert from "node:assert/strict";
import { test } from "node:test";
import { initializeSelector, selectTools } from "./fullsend-tools.js";

const native = (name = "cve", count = 1, path = "/vetted/cve/index.js") => ({ name, fullsendRegistrationCount: count, exposure: "direct", sourceInfo: { path } });
const manifest = (tools = ["cve"]) => ({ strictTools: true, tools, nativeTools: ["cve"], extensions: [{ path: "/vetted/cve" }] });

test("exact native tool selected without unrelated builtin or extension tools", () => {
  assert.deepEqual(selectTools(manifest(), [native(), native("unrelated"), { name: "bash" }]), ["cve"]);
});
test("empty is explicit and default selection is not an authority proof", () => {
  assert.deepEqual(selectTools(manifest([]), [native()]), []);
  assert.throws(() => selectTools({ tools: [] }, []), /strict tool declaration/);
});
test("missing, ambiguous and non-vetted registrations fail", () => {
  for (const registry of [[], [native(), native()], [native("cve", 1, "/vetted/cve-other/index.js")]]) {
    assert.throws(() => selectTools(manifest(), registry));
  }
  assert.throws(() => selectTools(manifest(), [{ ...native(), exposure: "hidden" }]), /hidden/);
});
test("activation and hook enforcement share canonical names", () => {
  const handlers = {}; let active = [];
  const pi = { on: (name, fn) => { handlers[name] = fn; }, getAllTools: () => [native(), { name: "read" }], setActiveTools: (names) => { active = names; }, getActiveTools: () => active };
  initializeSelector(pi, manifest(["cve", "read"]), { fatal: (message) => { throw new Error(message); } });
  handlers.session_start();
  assert.deepEqual(active, ["cve", "read"]);
  assert.equal(handlers.tool_call({ toolName: "cve" }), undefined);
  assert.equal(handlers.tool_call({ toolName: "bash" }).block, true);
  active.push("bash"); handlers.before_agent_start();
  assert.deepEqual(active, ["cve", "read"]);
});
test("a runtime ignoring exact activation fails", () => {
  const handlers = {};
  const pi = { on: (name, fn) => { handlers[name] = fn; }, getAllTools: () => [native()], setActiveTools: () => {}, getActiveTools: () => ["bash", "cve"] };
  initializeSelector(pi, manifest(), { fatal: (message) => { throw new Error(message); } });
  assert.throws(() => handlers.session_start(), /did not enforce/);
});

// Offline acceptance against the pinned Pi binary. Inspection exits
// on session_start, before any inference request or credential use.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const realPi = process.env.FULLSEND_TEST_PI_BIN;
const selectorPath = fileURLToPath(new URL("./fullsend-tools.js", import.meta.url));

async function actualSelection({ tools = ["cve"], duplicate = false, missing = false, wrongOrigin = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "fullsend-exact-pi-"));
  try {
    const home = join(dir, "home"); mkdirSync(home);
    const plugin = join(dir, "plugin"); mkdirSync(plugin);
    const tool = (name) => `pi.registerTool({name:${JSON.stringify(name)},label:'fixture',description:'offline fixture',parameters:{type:'object',properties:{}},execute:async()=>({content:[{type:'text',text:'fixture'}]})});`;
    writeFileSync(join(plugin, "index.js"), `export default function(pi){${tool(missing ? "other" : "cve")}${tool("unrelated")}${tool("bash")}}`);
    const paths = [plugin];
    if (duplicate) {
      const second = join(dir, "second"); mkdirSync(second);
      writeFileSync(join(second, "index.js"), `export default function(pi){${tool("cve")}}`);
      paths.push(second);
    }
    const inspector = join(dir, "inspector.js");
    writeFileSync(inspector, 'import {writeSync} from "node:fs"; export default function(pi){pi.on("session_start",()=>{writeSync(1,"FULLSEND_SELECTION="+JSON.stringify(pi.getActiveTools())+"\\n");process.exit(0);});}');
    const config = { strictTools: true, tools, nativeTools: tools.filter((name) => name === "cve"), extensions: paths.map((path) => ({ path: wrongOrigin ? join(dir, "different") : path })) };
    const manifestPath = join(dir, "manifest.json"); const bytes = JSON.stringify(config); writeFileSync(manifestPath, bytes);
    const args = ["--print", "--mode", "json", "--no-approve", "--no-extensions", "--no-prompt-templates", "--no-themes", "--no-session", "--model", "openai/gpt-5", "--api-key", "offline-not-a-key", "--tools", tools.join(","), ...paths.flatMap((path) => ["-e", path]), "-e", selectorPath, "-e", inspector];
    return await new Promise((resolveResult, reject) => {
      const child = spawn(resolve(realPi), args, { cwd: dir, env: { PATH: process.env.PATH, HOME: home, PI_CODING_AGENT_DIR: home, PI_OFFLINE: "1", PI_TELEMETRY: "0", FULLSEND_PI_MANIFEST: manifestPath, FULLSEND_PI_MANIFEST_SHA256: createHash("sha256").update(bytes).digest("hex") }, stdio: ["pipe", "pipe", "pipe"] });
      let stdout = "", stderr = "";
      child.stdout.on("data", (bytes) => { stdout += bytes; }); child.stderr.on("data", (bytes) => { stderr += bytes; });
      const timeout = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("offline Pi startup timed out")); }, 20000);
      child.on("error", reject); child.on("close", (code) => { clearTimeout(timeout); resolveResult({ code, stdout, stderr }); });
      child.stdin.end();
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test("real Pi exposes only the selected native tool", { skip: !realPi }, async () => {
  const result = await actualSelection();
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /FULLSEND_SELECTION=\["cve"\]/);
});
test("real Pi refuses missing, ambiguous and non-vetted selections before inference", { skip: !realPi }, async () => {
  for (const config of [{ missing: true }, { duplicate: true }, { wrongOrigin: true }]) {
    const result = await actualSelection(config);
    assert.notEqual(result.code, 0, result.stderr);
    assert.doesNotMatch(result.stdout, /FULLSEND_SELECTION=/);
    assert.match(result.stderr, /\[fullsend-tools\]|Failed to load extension/);
  }
});
test("real Pi explicit empty tool set exposes no builtins or unrelated extensions", { skip: !realPi }, async () => {
  const result = await actualSelection({ tools: [] });
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /FULLSEND_SELECTION=\[\]/);
});
