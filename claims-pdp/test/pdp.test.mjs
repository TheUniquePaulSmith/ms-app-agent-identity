// Decision matrix for the Cedar policies, run with: npm test
// Uses the real schema and policies, an in-memory stand-in for the PdpEntities
// table rows and in-memory PIPs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, mkdirSync, copyFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPolicyStore, createEvaluator, localGroupResolver, killKeys, entitiesFromRows, setEntities } from "../pdp-core.mjs";

const store = loadPolicyStore();
const BLUEPRINT = "b1b1b1b1-0000-4000-8000-000000000001";
// Test identities as in docs/test-identities.md (fake ids).
const GW_AGENT = "11111111-2222-3333-4444-555555555555"; // Agent2, autonomous limit 10,000
const SENIOR_AGENT = "33333333-0000-4000-8000-000000000003"; // Agent3, autonomous limit 50,000
const OLD_AGENT = "a9e7a9e7-0000-4000-8000-000000000002"; // Agent1 / Agent4: not registered
const HOST = "40570000-0000-4000-8000-000000000003";
const MCP = "3c903c90-0000-4000-8000-000000000004";
const USER1 = "05e10000-0000-4000-8000-000000000001";
const USER2 = "05e20000-0000-4000-8000-000000000002";
const USER3 = "05e30000-0000-4000-8000-000000000003"; // assigned to the agents, in no adjuster group
const STRANGER = "99999999-0000-0000-0000-000000000000";

// Rows as the Azure Table SDK returns them (PartitionKey = kind). OLD_AGENT is
// deliberately not registered.
const rows = [
  { partitionKey: "blueprint", rowKey: BLUEPRINT, displayName: "POC Claims Analysis Agent Blueprint" },
  { partitionKey: "agent", rowKey: GW_AGENT.toUpperCase(), displayName: "test gateway agent", blueprint: BLUEPRINT, autonomousLimit: 10000 },
  { partitionKey: "agent", rowKey: SENIOR_AGENT, displayName: "test senior agent", blueprint: BLUEPRINT, autonomousLimit: 50000 },
  { partitionKey: "application", rowKey: HOST, displayName: "POC Claims Web (host application)", isMcpServer: false },
  { partitionKey: "application", rowKey: MCP, displayName: "POC Claims MCP Server", isMcpServer: true },
  { partitionKey: "group", rowKey: "adjusters-eu", displayName: "POC Claims Adjusters EU", entraObjectId: "", region: "EU" },
  { partitionKey: "group", rowKey: "adjusters-us", displayName: "POC Claims Adjusters US", entraObjectId: "", region: "US" },
  { partitionKey: "group", rowKey: "senior-adjusters", displayName: "POC Claims Senior Adjusters", entraObjectId: "" },
  { partitionKey: "member", rowKey: USER1, groups: "adjusters-eu" },
  { partitionKey: "member", rowKey: "poc-claims-user1@contoso.onmicrosoft.com", groups: "adjusters-eu" },
  { partitionKey: "member", rowKey: USER2, groups: "adjusters-us, senior-adjusters" },
];
setEntities(store, entitiesFromRows(rows));

const seed = JSON.parse(readFileSync(new URL("../../claims-api-azure/seed-claims.json", import.meta.url), "utf8"));
const kills = new Map();
const pips = {
  killList: { get: async (keys) => new Map(keys.filter((k) => kills.has(k)).map((k) => [k, kills.get(k)])) },
  claims: { get: async (id) => seed.find((c) => c.claimId === id) || null },
  groups: localGroupResolver(store),
};
const pdp = createEvaluator(store, pips);

const agent = (permissions, id = GW_AGENT) => ({ type: "agent", id, properties: { blueprint: BLUEPRINT, permissions } });
const app = (id, permissions) => ({ type: "application", id, properties: { permissions } });
const claim = (id) => ({ type: "claim", id });
const mcpServer = { type: "mcp_server", id: "claims-mcp" };

async function decide(subject, action, resource, context = {}) {
  return pdp.evaluate({ subject, action: { name: action }, resource, context: { pep: "claims-mcp", ...context } });
}

async function expectDecision(expected, policy, ...args) {
  const r = await decide(...args);
  assert.equal(r.decision, expected, `${args[1]} ${args[2].id}: ${r.context.reason_admin.en}`);
  if (policy) assert.ok(r.context.policyIds.includes(policy), `expected ${policy}, got ${r.context.policyIds}`);
  return r;
}

test("gateway: MCP access needs an Mcp.* permission", async () => {
  await expectDecision(true, "gateway-mcp-access", agent(["Mcp.Analyze.All"]), "mcp:tools/call", mcpServer, { pep: "gateway" });
  await expectDecision(false, null, agent([]), "mcp:initialize", mcpServer, { pep: "gateway" });
});

test("gateway: unregistered agent from the same blueprint is refused", async () => {
  await expectDecision(false, "agent-must-be-registered", agent(["Mcp.Analyze.All"], OLD_AGENT), "mcp:initialize", mcpServer, { pep: "gateway" });
});

test("agent app-only: analyze below the autonomous limit, not above", async () => {
  await expectDecision(true, "agent-analyze", agent(["Mcp.Analyze.All"]), "analyze_claim", claim("CLAIM-1001"));
  await expectDecision(false, "agent-autonomous-limit", agent(["Mcp.Analyze.All"]), "analyze_claim", claim("CLAIM-1005"));
  await expectDecision(false, "agent-autonomous-limit", agent(["Mcp.Analyze.All"]), "analyze_claim", claim("CLAIM-1006"));
});

test("agent with the greater autonomous limit (Agent3): high-value app-only analyze allowed, hold still forbidden", async () => {
  await expectDecision(true, "agent-analyze", agent(["Mcp.Analyze.All"], SENIOR_AGENT), "analyze_claim", claim("CLAIM-1006"));
  await expectDecision(true, "agent-analyze", agent(["Mcp.Analyze.All"], SENIOR_AGENT), "analyze_claim", claim("CLAIM-1005"));
  await expectDecision(false, "no-agent-on-litigation-hold", agent(["Mcp.Analyze.All"], SENIOR_AGENT), "analyze_claim", claim("CLAIM-1003"));
});

test("agent never archives (no permit), never touches litigation hold", async () => {
  await expectDecision(false, null, agent(["Mcp.Analyze.All"]), "archive_claim", claim("CLAIM-1001"));
  await expectDecision(false, "no-agent-on-litigation-hold", agent(["Mcp.Analyze.All"]), "get_claim", claim("CLAIM-1003"));
});

test("agent for User1 (EU group): EU yes, US no", async () => {
  const ctx = { onBehalfOf: USER1, onBehalfOfUpn: "poc-claims-user1@contoso.onmicrosoft.com" };
  await expectDecision(true, "agent-analyze", agent(["Mcp.Analyze"]), "analyze_claim", claim("CLAIM-1001"), ctx);
  await expectDecision(true, "agent-analyze", agent(["Mcp.Analyze"]), "analyze_claim", claim("CLAIM-1006"), ctx);
  await expectDecision(false, "agent-same-region-as-user", agent(["Mcp.Analyze"]), "analyze_claim", claim("CLAIM-1002"), ctx);
});

test("agent for User2 (US group): high-value US allowed because a human is in the loop", async () => {
  const ctx = { onBehalfOf: USER2 };
  await expectDecision(true, "agent-analyze", agent(["Mcp.Analyze"]), "analyze_claim", claim("CLAIM-1005"), ctx);
  await expectDecision(false, "agent-same-region-as-user", agent(["Mcp.Analyze"]), "get_claim", claim("CLAIM-1001"), ctx);
});

test("user outside every adjuster group is refused, even at the gateway", async () => {
  await expectDecision(false, "user-must-be-adjuster", agent(["Mcp.Analyze"]), "mcp:tools/list", mcpServer, { pep: "gateway", onBehalfOf: STRANGER });
  await expectDecision(false, "user-must-be-adjuster", agent(["Mcp.Analyze"]), "analyze_claim", claim("CLAIM-1001"), { onBehalfOf: USER3 });
});

test("host archive: status, hold, amount, region and Senior Adjusters group", async () => {
  const host = app(HOST, ["Mcp.Archive"]);
  await expectDecision(true, "host-archive", host, "archive_claim", claim("CLAIM-1001"), { onBehalfOf: USER1 });
  await expectDecision(false, "archive-over-5000-needs-senior", host, "archive_claim", claim("CLAIM-1006"), { onBehalfOf: USER1 });
  await expectDecision(true, "host-archive", host, "archive_claim", claim("CLAIM-2002"), { onBehalfOf: USER2 });
  await expectDecision(false, "archive-own-region", host, "archive_claim", claim("CLAIM-1006"), { onBehalfOf: USER2 });
  await expectDecision(false, "no-archive-twice", host, "archive_claim", claim("CLAIM-1004"), { onBehalfOf: USER1 });
  await expectDecision(false, "no-archive-on-litigation-hold", host, "archive_claim", claim("CLAIM-1003"), { onBehalfOf: USER1 });
  await expectDecision(false, "archive-over-25000-needs-user", app(HOST, ["Mcp.Archive.All"]), "archive_claim", claim("CLAIM-1005"));
  await expectDecision(false, null, app(HOST, ["Mcp.Archive.All"]), "analyze_claim", claim("CLAIM-1001"));
});

test("claims-api (PEP 3): MCP server is a trusted intermediary, record forbids still apply", async () => {
  const mcp = app(MCP, ["Claims.Analyze.All", "Claims.Archive.All"]);
  const props = { region: "EU", status: "archived", amount: 900, litigationHold: false };
  await expectDecision(true, "mcp-server-intermediary", mcp, "analyze_claim", claim("CLAIM-1001"), { pep: "claims-api" });
  await expectDecision(false, null, mcp, "analyze_claim", claim("CLAIM-1001"), { pep: "claims-mcp" });
  const r = await pdp.evaluate({
    subject: mcp, action: { name: "archive_claim" }, resource: { type: "claim", id: "CLAIM-1004", properties: props }, context: { pep: "claims-api" },
  });
  assert.equal(r.decision, false);
  assert.ok(r.context.policyIds.includes("no-archive-twice"));
  assert.equal(r.context.resource.source, "pep");
});

test("tools/list filtering against the MCP server resource", async () => {
  const a = agent(["Mcp.Analyze.All"]);
  await expectDecision(true, null, a, "analyze_claim", mcpServer);
  await expectDecision(false, null, a, "archive_claim", mcpServer);
  await expectDecision(true, null, app(HOST, ["Mcp.Archive.All"]), "archive_claim", mcpServer);
});

test("kill switch: agent, blueprint and user scopes override every permit", async () => {
  const a = agent(["Mcp.Analyze.All"]);
  kills.set(killKeys.agent(GW_AGENT), { reason: "test" });
  await expectDecision(false, "kill-switch-principal", a, "mcp:tools/call", mcpServer, { pep: "gateway" });
  kills.clear();

  kills.set(killKeys.blueprint(BLUEPRINT), { reason: "test" });
  const r = await expectDecision(false, "kill-switch-blueprint", a, "analyze_claim", claim("CLAIM-1001"));
  assert.equal(r.context.killList.hit, true);
  kills.clear();

  kills.set(killKeys.user(USER1), { reason: "test" });
  await expectDecision(false, "kill-switch-user", app(HOST, ["Mcp.Archive"]), "archive_claim", claim("CLAIM-1001"), { onBehalfOf: USER1 });
  kills.clear();

  await expectDecision(true, "agent-analyze", a, "analyze_claim", claim("CLAIM-1001"));
});

test("kill list unavailable: agents fail closed, applications fail open", async () => {
  const broken = createEvaluator(store, { ...pips, killList: { get: async () => { throw new Error("down"); } } });
  const r1 = await broken.evaluate({ subject: agent(["Mcp.Analyze.All"]), action: { name: "analyze_claim" }, resource: claim("CLAIM-1001"), context: { pep: "claims-mcp" } });
  assert.equal(r1.decision, false);
  assert.deepEqual(r1.context.policyIds, ["fail-closed-kill-list"]);
  const r2 = await broken.evaluate({ subject: app(HOST, ["Mcp.Archive.All"]), action: { name: "archive_claim" }, resource: claim("CLAIM-1001"), context: { pep: "claims-mcp" } });
  assert.equal(r2.decision, true);
});

test("registered agent is recognised even when the token had no xms_par_app_azp", async () => {
  const r = await expectDecision(true, "agent-analyze", { type: "application", id: GW_AGENT, properties: { permissions: ["Mcp.Analyze.All"] } }, "analyze_claim", claim("CLAIM-1001"));
  assert.equal(r.context.principal.typeSource, "PDP agent registry");
});

test("unknown application (or agent without agent claims) is refused", async () => {
  await expectDecision(false, "application-must-be-registered", app(OLD_AGENT, ["Mcp.Analyze.All"]), "mcp:initialize", mcpServer, { pep: "gateway" });
});

test("unknown claim is denied by claim-must-exist", async () => {
  await expectDecision(false, "claim-must-exist", agent(["Mcp.Analyze.All"]), "get_claim", claim("CLAIM-9999"));
});

test("batch evaluation merges defaults (AuthZEN 1.0)", async () => {
  const r = await pdp.evaluateBatch({
    subject: agent(["Mcp.Analyze.All"]),
    resource: mcpServer,
    context: { pep: "claims-mcp" },
    evaluations: ["get_claim", "get_claim_evidence", "analyze_claim", "archive_claim"].map((name) => ({ action: { name } })),
  });
  assert.deepEqual(r.evaluations.map((e) => e.decision), [true, true, true, false]);
});

test("registry rows: ids are lowercased, member groups split, unknown kinds ignored", () => {
  const e = entitiesFromRows([...rows, { partitionKey: "something-else", rowKey: "x" }]);
  assert.equal(e.agents.get(GW_AGENT).autonomousLimit, 10000);
  assert.equal(e.applications.get(MCP).isMcpServer, true);
  assert.deepEqual(e.localMembers["poc-claims-user1@contoso.onmicrosoft.com"], ["adjusters-eu"]);
  assert.deepEqual(e.localMembers[USER2], ["adjusters-us", "senior-adjusters"]);
  assert.deepEqual(e.groups.map((g) => g.id), ["adjusters-eu", "adjusters-us", "senior-adjusters"]);
});

test("policy layers: guardrails come from the platform layer, the rest from the domain", () => {
  assert.equal(store.annotations["kill-switch-principal"].layer, "platform");
  assert.equal(store.annotations["agent-must-be-registered"].layer, "platform");
  assert.equal(store.annotations["user-must-be-adjuster"].layer, "claims");
  assert.equal(store.annotations["agent-analyze"].layer, "claims");
});

test("policy layers: a permit in the platform layer is refused at load", () => {
  const policies = fileURLToPath(new URL("../policies", import.meta.url));
  const dir = mkdtempSync(join(tmpdir(), "pdp-layers-"));
  try {
    for (const [layer, files] of [["platform", ["platform.cedarschema", "guardrails.cedar"]], ["claims", ["claims.cedarschema", "claims.cedar"]]]) {
      mkdirSync(join(dir, layer));
      for (const f of files) copyFileSync(join(policies, layer, f), join(dir, layer, f));
    }
    writeFileSync(join(dir, "platform", "widen.cedar"), '@id("platform-allow-all")\npermit (principal, action, resource);\n');
    assert.throws(() => loadPolicyStore(dir), /platform policy platform-allow-all must be a forbid/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("registry reload: registering an agent takes effect on the next decision", async () => {
  const a = agent(["Mcp.Analyze.All"], OLD_AGENT);
  await expectDecision(false, "agent-must-be-registered", a, "analyze_claim", claim("CLAIM-1001"));
  setEntities(store, entitiesFromRows([...rows, { partitionKey: "agent", rowKey: OLD_AGENT, displayName: "local agent", blueprint: BLUEPRINT, autonomousLimit: 10000 }]));
  try {
    await expectDecision(true, "agent-analyze", a, "analyze_claim", claim("CLAIM-1001"));
  } finally {
    setEntities(store, entitiesFromRows(rows));
  }
  await expectDecision(false, "agent-must-be-registered", a, "analyze_claim", claim("CLAIM-1001"));
});
