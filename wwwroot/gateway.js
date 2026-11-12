// "Local LLM & Gateway MCP" tab. Uses state, $, pretty and escapeHtml from app.js.
//
// The agent loop is the same as on the "Agent runtime loop" tab, but /gw/chat/*
// sends tool calls through Azure API Management to claims-mcp-azure as a second
// agent identity, and the trace shows the three enforcement points:
//   PEP 1 gateway (kill list, rate limit, AuthZEN coarse decision)
//   PEP 2 MCP server (AuthZEN per tool and claim)
//   PEP 3 Claims API (AuthZEN per record, then the record changes)

const gw = { info: null, conversationId: null };

const gwModeHints = {
  "agent-app": "Tool calls run as the GATEWAY AGENT with an app-only token (roles: Mcp.Analyze.All). No user is in the loop, so the PDP applies the agent's autonomous limit (10,000) and never lets it touch litigation holds.",
  "agent-user": "Tool calls run as the GATEWAY AGENT on behalf of YOU (scp: Mcp.Analyze). The PDP resolves your Entra groups: the agent may only act on claims of your adjuster group's region.",
  "host-user": "Tool calls run as the HOST APPLICATION on behalf of YOU (scp: Mcp.Archive). Archive needs your region's group, and the Senior Adjusters group above 5,000.",
  "host-app": "Tool calls run as the HOST APPLICATION app-only (roles: Mcp.Archive.All). Archive above 25,000 needs a signed-in adjuster, so it is refused here.",
};

const yesNo = (ok) => (ok ? `<span class="pep-ok">yes</span>` : `<span class="pep-deny">no</span>`);
const list = (a) => (Array.isArray(a) && a.length ? a.join(", ") : "—");

async function gwLoadInfo() {
  try {
    gw.info = await (await fetch("/api/gw/info")).json();
  } catch (error) {
    $("gw-ready").textContent = String(error);
    return;
  }
  const i = gw.info;
  $("gw-endpoint").textContent = i.mcpEndpoint || "—";
  gwFillAgents();
  $("gw-ready").innerHTML =
    `endpoint ${yesNo(i.ready.endpoint)} · agent identity ${yesNo(i.ready.agentIdentity)} · internal key ${yesNo(i.ready.internalKey)} · kill-switch workflow ${yesNo(i.ready.workflow)} · storage (PDP entities) ${yesNo(i.ready.storage)}` +
    (i.ready.agentIdentity && i.ready.internalKey ? "" : ` <span class="hint">(run Configure/Configure-Entra.ps1 -TestAgents and Configure/Deploy-GatewayPoc.ps1)</span>`);
  gwRenderUser();
  ksFillTarget();
}

// Agent identities from appsettings.json GatewayAgentIdentities (same blueprint).
// Entries without a client id yet are shown but cannot be picked.
function gwFillAgents() {
  const select = $("gw-agent-select");
  select.innerHTML = "";
  (gw.info?.agentIdentities || []).forEach((a) => {
    const option = new Option(a.configured ? `${a.name} (${a.clientId.slice(0, 8)}…)` : `${a.name} (not configured)`, a.clientId);
    option.disabled = !a.configured;
    option.title = a.note || "";
    option.selected = a.isDefault;
    select.add(option);
  });
  gwRenderAgent();
}

const gwSelectedAgent = () => (gw.info?.agentIdentities || []).find((a) => a.clientId === $("gw-agent-select").value);

function gwRenderAgent() {
  const a = gwSelectedAgent();
  const i = gw.info || {};
  $("gw-agent").textContent = a
    ? `${a.name} · ${a.clientId}${a.note ? ` · ${a.note}` : ""} (blueprint ${i.blueprintClientId})`
    : "none configured (run Configure/Configure-Entra.ps1 -TestAgents)";
  // Host modes act as the host application, so the agent choice does not apply.
  $("gw-agent-select").disabled = $("gw-mode").value.startsWith("host");
}

function gwRenderUser() {
  const u = state.session?.user;
  $("gw-user").textContent = state.session?.signedIn ? `${u.name} (oid ${u.objectId})` : "not signed in (app-only modes only)";
}

function gwUpdateHint() {
  const mode = $("gw-mode").value;
  let hint = gwModeHints[mode];
  if (mode === "agent-user" && !state.agentToken) hint += " (agent token missing: sign in and refresh tokens)";
  if (mode === "host-user" && !state.hostToken) hint += " (host token missing: sign in and refresh tokens)";
  $("gw-mode-hint").textContent = hint;
}

function gwAppend(role, text) {
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  div.textContent = text;
  $("gw-chat-log").appendChild(div);
  $("gw-chat-log").scrollTop = $("gw-chat-log").scrollHeight;
  return div;
}

async function gwNewConversation() {
  if (gw.conversationId) {
    try {
      await fetch(`/chat/${gw.conversationId}`, { method: "DELETE" });
    } catch {
      /* ignore */
    }
  }
  gw.conversationId = null;
  $("gw-chat-log").innerHTML = "";
  $("gw-trace").innerHTML = "";
  const agent = gwSelectedAgent();
  const asAgent = !$("gw-mode").value.startsWith("host") && agent ? ` · agent ${agent.name}` : "";
  gwAppend("system", `New conversation. Identity for tool calls: ${$("gw-mode").selectedOptions[0].text}${asAgent}`);
}

// ---------------------------------------------------------------------------
// Trace: one block per tool call, three enforcement points
// ---------------------------------------------------------------------------

function decisionCell(decision, text) {
  if (decision === undefined || decision === null) return `<span class="pep-skip">${text || "not reached"}</span>`;
  return `<span class="${decision ? "pep-ok" : "pep-deny"}">${decision ? "PERMIT" : "DENY"}</span>${text ? ` · ${escapeHtml(String(text))}` : ""}`;
}

function parseResult(step) {
  try {
    return JSON.parse(step.resultPreview);
  } catch {
    return null;
  }
}

function gwRenderTrace(trace) {
  const container = $("gw-trace");
  if (!trace || trace.length === 0) {
    container.innerHTML += `<div class="trace-step"><em>No tool calls in this turn.</em></div>`;
    return;
  }
  trace.forEach((step) => {
    const result = parseResult(step) || {};
    const gateway = step.gateway || result.gateway || {};
    const refusal = gateway.refusal;
    const gwDecision = gateway.decision;
    const a2 = step.authzen || result.authzen;
    const a3 = step.downstreamAuthzen || result.downstreamAuthzen;
    const deniedAtGateway = step.decidedBy === "gateway";
    const deniedAtPep2 = step.decidedBy === "pdp" && step.pep === "claims-mcp";
    const ok = step.decision === "ALLOW";
    const user = a2?.user || a3?.user;
    const res = a2?.resource;
    const body = result.body || {};
    const claim = body.claim;

    let pep1;
    if (deniedAtGateway) pep1 = decisionCell(false, `${refusal?.error || "refused"}: ${refusal?.reason || ""}`);
    else if (gwDecision) pep1 = decisionCell(true, `${list(gwDecision.policyIds)} · kill list ${gwDecision.killList?.cached ? "(cached) " : ""}clear · ${gwDecision.rateLimit?.count}/${gwDecision.rateLimit?.limitPerMinute} this minute`);
    else if (gateway.viaGateway === false) pep1 = `<span class="pep-deny">request did not come through the gateway</span>`;
    else pep1 = decisionCell(undefined);

    const div = document.createElement("div");
    div.className = "trace-step";
    div.innerHTML = `
      <div class="head">
        <span><b>${escapeHtml(step.tool)}</b>(${step.arguments ? escapeHtml(JSON.stringify(step.arguments)) : ""})</span>
        <span class="${ok ? "status-ok" : "status-deny"}">${escapeHtml(step.decision)}</span>
      </div>
      <table>
        <tr><td>identity</td><td>${escapeHtml(step.identity)} · ${escapeHtml(step.permissionKind)}</td></tr>
        <tr><th colspan="2">PEP 1 · API Management gateway</th></tr>
        <tr><td>decision</td><td>${pep1}</td></tr>
        ${refusal?.authzen ? `<tr><td>policies</td><td>${escapeHtml(list(refusal.authzen.policyIds))} (${escapeHtml(refusal.authzen.reason_admin || "")})</td></tr>` : ""}
        ${refusal?.killList?.entries ? `<tr><td>kill list</td><td>${escapeHtml(Object.keys(refusal.killList.entries).join(", "))}</td></tr>` : ""}
        <tr><th colspan="2">PEP 2 · MCP server → PDP (per tool, per claim)</th></tr>
        <tr><td>decision</td><td>${deniedAtGateway ? decisionCell(undefined) : decisionCell(a2?.decision, a2 ? `${list(a2.policyIds)}` : "")}</td></tr>
        ${a2 && !a2.decision ? `<tr><td>reason</td><td>${escapeHtml(a2.reason_user || "")} <span class="hint">(${escapeHtml(a2.reason_admin || "")})</span></td></tr>` : ""}
        ${user ? `<tr><td>user groups</td><td>${escapeHtml(user.upn || user.oid)} → ${escapeHtml(list(user.groups))} <span class="hint">(${escapeHtml(user.groupSource || "")})</span></td></tr>` : ""}
        ${res?.exists ? `<tr><td>claim attributes</td><td>${escapeHtml(res.region)} · ${escapeHtml(res.status)} · ${res.amount}${res.litigationHold ? " · litigation hold" : ""} <span class="hint">(${escapeHtml(res.source)})</span></td></tr>` : ""}
        ${result.killList ? `<tr><td>kill list</td><td>${result.killList.hit ? `<span class="pep-deny">hit: ${escapeHtml(Object.keys(result.killList.entries || {}).join(", "))}</span>` : "clear"} (${escapeHtml(list(result.killList.keys))})</td></tr>` : ""}
        <tr><th colspan="2">Token exchange and PEP 3 · Claims API → PDP (per record)</th></tr>
        <tr><td>exchange</td><td>${step.exchange ? `${escapeHtml(step.exchange.grant)} as ${escapeHtml(step.exchange.actor)} (azp ${escapeHtml(step.exchange.outboundToken?.azp || "")})` : deniedAtGateway || deniedAtPep2 ? "— (refused before the exchange)" : "—"}</td></tr>
        <tr><td>decision</td><td>${a3 ? decisionCell(a3.decision, `${list(a3.policyIds)}${a3.decision ? "" : ` · ${a3.reason_user || ""}`}`) : decisionCell(undefined, step.tool === "list_claims" ? "list route (no record decision)" : undefined)}</td></tr>
        ${claim ? `<tr><td>effect on record</td><td>${escapeHtml(body.result || "read")} · status ${escapeHtml(body.statusBefore || claim.status)} → <b>${escapeHtml(claim.status)}</b>${claim.riskScore !== undefined ? ` · risk ${claim.riskScore}` : ""}</td></tr>` : ""}
        ${body.claims ? `<tr><td>visible claims</td><td>${escapeHtml(body.claims.map((c) => c.claimId).join(", ") || "none")}${body.hiddenByPolicy?.length ? ` · hidden by PDP: ${escapeHtml(body.hiddenByPolicy.map((h) => `${h.claimId} (${list(h.policyIds)})`).join(", "))}` : ""}</td></tr>` : ""}
      </table>
      <details><summary>raw tool result</summary><pre class="json">${escapeHtml(step.resultPreview || "")}</pre></details>`;
    container.appendChild(div);
  });
}

async function gwSend() {
  const message = $("gw-input").value.trim();
  if (!message) return;
  saveLlmSettings();
  $("gw-chat-error").hidden = true;

  const mode = $("gw-mode").value;
  const headers = { "Content-Type": "application/json" };
  if (mode === "agent-user" || mode === "host-user") {
    const token = mode === "agent-user" ? state.agentToken : state.hostToken;
    if (!token) {
      $("gw-chat-error").textContent = "This mode needs a user token. Sign in (as User1, User2 or User3, see docs/test-identities.md) and refresh tokens on the Profile tab.";
      $("gw-chat-error").hidden = false;
      return;
    }
    headers.Authorization = `Bearer ${token}`;
  }

  gwAppend("user", message);
  $("gw-input").value = "";
  $("gw-send").disabled = true;
  const thinking = gwAppend("system", "Running agent loop through the gateway…");

  try {
    const response = await fetch(`/gw/chat/${mode}`, {
      method: "POST",
      headers,
      body: JSON.stringify({ conversationId: gw.conversationId, message, llm: state.llm, agentIdentityClientId: $("gw-agent-select").value || null }),
    });
    const json = await response.json();
    thinking.remove();
    if (!response.ok) {
      $("gw-chat-error").textContent = `HTTP ${response.status}: ${json.message || json.error || pretty(json)}${json.inner ? ` — ${json.inner}` : ""}`;
      $("gw-chat-error").hidden = false;
      gwAppend("system", `Turn failed (${json.error || response.status}).`);
      return;
    }
    gw.conversationId = json.conversationId;
    (json.trace || []).forEach((step) => gwAppend("tool", `${step.tool}(${step.arguments ? JSON.stringify(step.arguments) : ""}) → ${step.decision}`));
    gwAppend("assistant", json.answer || "(no answer)");
    const header = document.createElement("div");
    header.className = "hint";
    header.textContent = `Turn: ${json.iterations} model call(s), ${json.trace.length} tool call(s), model ${json.model}, actor ${json.actor}`;
    $("gw-trace").appendChild(header);
    gwRenderTrace(json.trace);
    claimsLoad();
  } catch (error) {
    thinking.remove();
    $("gw-chat-error").textContent = String(error);
    $("gw-chat-error").hidden = false;
  } finally {
    $("gw-send").disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Kill switch
// ---------------------------------------------------------------------------

function ksFillTarget() {
  const i = gw.info || {};
  const scope = $("ks-scope").value;
  $("ks-target").value =
    scope === "agent:gateway" ? gwSelectedAgent()?.clientId || ""
    : scope === "blueprint" ? i.blueprintClientId || ""
    : scope === "user" ? state.session?.user?.objectId || ""
    : i.hostApplicationClientId || "";
  $("ks-entra").disabled = scope !== "agent:gateway";
  if (scope !== "agent:gateway") $("ks-entra").checked = false;
}

async function ksSend(action) {
  const scope = $("ks-scope").value.split(":")[0];
  const targetId = $("ks-target").value.trim();
  if (!targetId) {
    $("ks-result").textContent = "Target id is empty (for the user scope, sign in first).";
    return;
  }
  $("ks-result").textContent = `${action} ${scope} ${targetId}: running Logic App workflow…`;
  const response = await fetch("/api/gw/killswitch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action,
      scope,
      targetId,
      reason: $("ks-reason").value,
      disableInEntra: $("ks-entra").checked,
      blueprintId: gw.info?.blueprintClientId,
    }),
  });
  $("ks-result").textContent = pretty(await response.json());
  ksLoad();
}

async function ksLoad() {
  const json = await (await fetch("/api/gw/kills")).json();
  const kills = json.kills?.kills;
  $("ks-list").innerHTML = Array.isArray(kills)
    ? kills.length
      ? `<table class="grid-table"><tr><th>key</th><th>reason</th><th>by</th><th>since</th><th>source</th></tr>${kills
          .map((k) => `<tr><td class="mono">${escapeHtml(k.key)}</td><td>${escapeHtml(k.reason || "")}</td><td>${escapeHtml(k.requestedBy || "")}</td><td>${escapeHtml(k.since || "")}</td><td>${escapeHtml(k.source || "")}</td></tr>`)
          .join("")}</table>`
      : "empty: nobody is blocked"
    : `<pre class="json">${escapeHtml(pretty(json.kills))}</pre>`;
  const drift = json.kills?.drift;
  if (drift?.lastRun) $("ks-list").innerHTML += `<p class="hint">Entra drift sync last ran ${escapeHtml(drift.lastRun)}${drift.lastError ? `, error: ${escapeHtml(drift.lastError)}` : ""}: ${escapeHtml(Object.entries(drift.principals || {}).map(([id, p]) => `${p.displayName || id} accountEnabled=${p.accountEnabled}`).join("; "))}</p>`;
  const audit = json.audit?.audit;
  $("ks-audit").innerHTML = Array.isArray(audit) && audit.length
    ? `<table class="grid-table"><tr><th>at</th><th>action</th><th>key</th><th>reason</th><th>by</th></tr>${audit
        .map((a) => `<tr><td>${escapeHtml(a.at || "")}</td><td>${escapeHtml(a.action || "")}</td><td class="mono">${escapeHtml(a.key || "")}</td><td>${escapeHtml(a.reason || "")}</td><td>${escapeHtml(a.requestedBy || a.source || "")}</td></tr>`)
        .join("")}</table>`
    : "no audit records yet";
}

// ---------------------------------------------------------------------------
// Claims table
// ---------------------------------------------------------------------------

async function claimsLoad() {
  const response = await fetch("/api/gw/claims");
  const json = await response.json();
  if (!response.ok || !Array.isArray(json.claims)) {
    $("claims-table").innerHTML = `<pre class="json">${escapeHtml(pretty(json))}</pre>`;
    return;
  }
  $("claims-table").innerHTML = `<table class="grid-table">
    <tr><th>claim</th><th>region</th><th>status</th><th>amount</th><th>last change</th><th>what it demonstrates</th></tr>
    ${json.claims
      .map((c) => `<tr>
        <td class="mono">${escapeHtml(c.claimId)}</td>
        <td>${escapeHtml(c.region)}</td>
        <td><span class="badge ${escapeHtml(c.status)}">${escapeHtml(c.status)}</span>${c.litigationHold ? ` <span class="badge hold">hold</span>` : ""}</td>
        <td>${Number(c.amount).toLocaleString()}</td>
        <td>${c.archivedAt ? `archived ${escapeHtml(c.archivedAt)} for ${escapeHtml(c.archivedFor || "")}` : c.lastAnalyzedAt ? `analyzed ×${c.analysisCount} ${escapeHtml(c.lastAnalyzedAt)} for ${escapeHtml(c.lastAnalyzedFor || "")}, risk ${c.riskScore}` : "—"}</td>
        <td class="hint">${escapeHtml(c.demo || "")}</td></tr>`)
      .join("")}</table>`;
}

async function claimsReset() {
  if (!confirm("Reset every claim record in the Azure table to the sample data?")) return;
  const response = await fetch("/api/gw/claims/reset", { method: "POST" });
  if (!response.ok) $("claims-table").innerHTML = `<pre class="json">${escapeHtml(pretty(await response.json()))}</pre>`;
  else claimsLoad();
}

// ---------------------------------------------------------------------------
// PDP playground
// ---------------------------------------------------------------------------

function pdpPresets() {
  const i = gw.info || {};
  const agentId = gwSelectedAgent()?.clientId || i.gatewayAgentIdentityClientId;
  const agent = (perms) => ({ type: "agent", id: agentId, properties: { blueprint: i.blueprintClientId, permissions: perms } });
  // Test users' object ids: appsettings.json GatewayMcp:User1ObjectId..User3ObjectId
  // (written by Configure/Configure-Entra.ps1 -TestUsers; docs/test-identities.md).
  const user1 = i.user1ObjectId || "<User1 object id>";
  const user2 = i.user2ObjectId || "<User2 object id>";
  const user3 = i.user3ObjectId || "<User3 object id>";
  const rogueId = (i.agentIdentities || []).find((a) => /\(Agent4\)/.test(a.name) || a.note?.startsWith("Agent4"))?.clientId || "<Agent4 client id>";
  return {
    "Selected agent app-only analyzes CLAIM-1001 (permit)": { subject: agent(["Mcp.Analyze.All"]), action: { name: "analyze_claim" }, resource: { type: "claim", id: "CLAIM-1001" }, context: { pep: "claims-mcp" } },
    "Selected agent app-only analyzes CLAIM-1006 (12,000: Agent2 over its limit, Agent3 permit)": { subject: agent(["Mcp.Analyze.All"]), action: { name: "analyze_claim" }, resource: { type: "claim", id: "CLAIM-1006" }, context: { pep: "claims-mcp" } },
    "Selected agent app-only analyzes CLAIM-1005 (42,000: above Agent2's limit, within Agent3's)": { subject: agent(["Mcp.Analyze.All"]), action: { name: "analyze_claim" }, resource: { type: "claim", id: "CLAIM-1005" }, context: { pep: "claims-mcp" } },
    "Agent for User1 analyzes US CLAIM-1002 (region)": { subject: agent(["Mcp.Analyze"]), action: { name: "analyze_claim" }, resource: { type: "claim", id: "CLAIM-1002" }, context: { pep: "claims-mcp", onBehalfOf: user1 } },
    "Agent for User2 analyzes US CLAIM-1005 (permit, human in loop)": { subject: agent(["Mcp.Analyze"]), action: { name: "analyze_claim" }, resource: { type: "claim", id: "CLAIM-1005" }, context: { pep: "claims-mcp", onBehalfOf: user2 } },
    "Agent for User3 analyzes CLAIM-1001 (not an adjuster)": { subject: agent(["Mcp.Analyze"]), action: { name: "analyze_claim" }, resource: { type: "claim", id: "CLAIM-1001" }, context: { pep: "claims-mcp", onBehalfOf: user3 } },
    "Host for User1 archives CLAIM-1006 (needs Senior group)": { subject: { type: "application", id: i.hostApplicationClientId, properties: { permissions: ["Mcp.Archive"] } }, action: { name: "archive_claim" }, resource: { type: "claim", id: "CLAIM-1006" }, context: { pep: "claims-mcp", onBehalfOf: user1 } },
    "Host for User2 archives CLAIM-2002 (Senior, permit)": { subject: { type: "application", id: i.hostApplicationClientId, properties: { permissions: ["Mcp.Archive"] } }, action: { name: "archive_claim" }, resource: { type: "claim", id: "CLAIM-2002" }, context: { pep: "claims-mcp", onBehalfOf: user2 } },
    "Agent4 (rogue) at the gateway (unregistered)": { subject: { type: "agent", id: rogueId, properties: { blueprint: i.blueprintClientId, permissions: ["Mcp.Analyze.All"] } }, action: { name: "mcp:tools/list" }, resource: { type: "mcp_server", id: "claims-mcp" }, context: { pep: "gateway" } },
    "Agent1 (local agent) at the gateway (unregistered)": { subject: { type: "agent", id: i.localAgentIdentityClientId, properties: { blueprint: i.blueprintClientId, permissions: ["Mcp.Analyze.All"] } }, action: { name: "mcp:tools/list" }, resource: { type: "mcp_server", id: "claims-mcp" }, context: { pep: "gateway" } },
    "Batch: which tools may the gateway agent use?": {
      subject: agent(["Mcp.Analyze.All"]),
      resource: { type: "mcp_server", id: "claims-mcp" },
      context: { pep: "claims-mcp" },
      evaluations: ["get_claim", "get_claim_evidence", "analyze_claim", "archive_claim"].map((name) => ({ action: { name } })),
    },
  };
}

function pdpFillPresets() {
  const presets = pdpPresets();
  const select = $("pdp-preset");
  select.innerHTML = "";
  Object.keys(presets).forEach((name) => select.add(new Option(name, name)));
  $("pdp-request").value = pretty(presets[select.value]);
}

async function pdpEvaluate() {
  let body;
  try {
    body = JSON.parse($("pdp-request").value);
  } catch (error) {
    $("pdp-result").textContent = `Invalid JSON: ${error.message}`;
    return;
  }
  $("pdp-result").textContent = "Evaluating…";
  const response = await fetch("/api/gw/pdp/evaluate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  $("pdp-result").textContent = pretty(await response.json());
}

async function pdpShowPolicies() {
  const json = await (await fetch("/api/gw/pdp/policies")).json();
  $("pdp-policy-text").textContent = json.policies
    ? `// policy version ${json.policyVersion}, group source ${json.groupSource}\n\n${json.policies}\n\n// ---------- schema ----------\n${json.schema}\n\n// ---------- entities (${json.entities?.source}, version ${json.entities?.version}, loaded ${json.entities?.loadedAt}) ----------\n${pretty({ blueprints: json.blueprints, agents: json.agents, applications: json.applications, groups: json.groups, localMembers: json.localMembers })}`
    : pretty(json);
  $("pdp-policy-text").closest("details").open = true;
}

// ---------------------------------------------------------------------------
// PDP entities: the PDP's registry, written straight into the storage account
// (table PdpEntities, PartitionKey = kind) by /api/gw/entities
// ---------------------------------------------------------------------------

const ent = { rows: null };

const entColumns = {
  agent: [["displayName", "name"], ["blueprint", "blueprint"], ["autonomousLimit", "autonomous limit"]],
  blueprint: [["displayName", "name"]],
  application: [["displayName", "name"], ["isMcpServer", "MCP server"]],
  group: [["displayName", "name"], ["region", "region"], ["entraObjectId", "Entra object id"]],
  member: [["groups", "groups"]],
};
const entTitles = { agent: "Agent identities", blueprint: "Agent blueprints", application: "Applications", group: "Groups", member: "Local members (only when the PDP runs with GROUP_SOURCE=local)" };
const entIdHints = { agent: "agent identity app id", blueprint: "blueprint app id", application: "app id (azp)", group: "id used in the policies, e.g. adjusters-eu", member: "user oid or UPN" };

function entCell(kind, column, value) {
  if (column === "autonomousLimit") return Number(value || 0).toLocaleString();
  if (column === "isMcpServer") return value ? "yes" : "—";
  if (column === "blueprint") {
    const b = ent.rows?.blueprint?.find((x) => x.id === value);
    return `<span class="mono">${escapeHtml(value || "")}</span>${b ? ` <span class="hint">(${escapeHtml(b.displayName || "")})</span>` : value ? ` <span class="pep-deny">not in blueprints</span>` : ""}`;
  }
  return escapeHtml(value === undefined || value === null || value === "" ? "—" : String(value));
}

async function entLoad() {
  $("ent-status").textContent = "Loading…";
  const response = await fetch("/api/gw/entities");
  const json = await response.json();
  if (!response.ok || !json.entities) {
    ent.rows = null;
    $("ent-status").textContent = "";
    $("ent-tables").innerHTML = `<pre class="json">${escapeHtml(pretty(json))}</pre>`;
    return;
  }
  ent.rows = json.entities;
  $("ent-status").textContent = `table ${json.table} in storage account ${json.account}${json.note ? ` · ${json.note}` : ""}`;
  $("ent-tables").innerHTML = Object.keys(entColumns)
    .map((kind) => {
      const rows = ent.rows[kind] || [];
      const head = `<tr><th>id</th>${entColumns[kind].map(([, label]) => `<th>${label}</th>`).join("")}<th></th></tr>`;
      const body = rows
        .map((r) => `<tr><td class="mono">${escapeHtml(r.id)}</td>${entColumns[kind].map(([c]) => `<td>${entCell(kind, c, r[c])}</td>`).join("")}
          <td><button class="chip ent-edit" data-kind="${kind}" data-id="${escapeHtml(r.id)}">Edit</button> <button class="chip ent-delete" data-kind="${kind}" data-id="${escapeHtml(r.id)}">Delete</button></td></tr>`)
        .join("");
      return `<h3>${entTitles[kind]}</h3>${rows.length ? `<table class="grid-table">${head}${body}</table>` : "<p>none</p>"}${kind === "agent" ? entUnregisteredAgents() : ""}`;
    })
    .join("");
  entFillChoices();
}

// Agent identities from appsettings.json (the drop-down above) that the PDP does not know.
function entUnregisteredAgents() {
  const known = new Set((ent.rows?.agent || []).map((a) => a.id));
  const missing = (gw.info?.agentIdentities || []).filter((a) => a.configured && !known.has(a.clientId.toLowerCase()));
  if (!missing.length) return "";
  return `<p class="hint">Not registered (refused at the gateway): ${missing
    .map((a) => `${escapeHtml(a.name)} <button class="chip ent-register" data-id="${escapeHtml(a.clientId)}" data-name="${escapeHtml(a.name)}">Register</button>`)
    .join(" ")}</p>`;
}

function entFillChoices() {
  const list = $("ent-blueprint-list");
  list.innerHTML = "";
  (ent.rows?.blueprint || []).forEach((b) => list.appendChild(new Option(b.displayName || b.id, b.id)));
  const selected = new Set($("ent-kind").value === "member" ? entCheckedGroups() : []);
  $("ent-groups").innerHTML = (ent.rows?.group || [])
    .map((g) => `<label class="inline"><input type="checkbox" value="${escapeHtml(g.id)}" ${selected.has(g.id) ? "checked" : ""} /> ${escapeHtml(g.id)}</label>`)
    .join("") || `<span class="hint">no groups yet</span>`;
}

const entCheckedGroups = () => [...$("ent-groups").querySelectorAll("input:checked")].map((i) => i.value);

function entShowFields() {
  const kind = $("ent-kind").value;
  document.querySelectorAll("#subtab-entities [data-kinds]").forEach((el) => (el.hidden = !el.dataset.kinds.split(" ").includes(kind)));
  $("ent-id").placeholder = entIdHints[kind];
}

function entFillForm(kind, row) {
  $("ent-kind").value = kind;
  entShowFields();
  $("ent-id").value = row?.id || "";
  $("ent-id").readOnly = Boolean(row?.id && row.existing);
  $("ent-displayName").value = row?.displayName || "";
  $("ent-blueprint").value = row?.blueprint || (kind === "agent" ? gw.info?.blueprintClientId?.toLowerCase() || "" : "");
  $("ent-autonomousLimit").value = row?.autonomousLimit ?? 10000;
  $("ent-isMcpServer").checked = Boolean(row?.isMcpServer);
  $("ent-entraObjectId").value = row?.entraObjectId || "";
  $("ent-region").value = row?.region || "";
  const groups = new Set(String(row?.groups || "").split(",").filter(Boolean));
  $("ent-groups").querySelectorAll("input").forEach((i) => (i.checked = groups.has(i.value)));
  $("ent-form-title").textContent = row?.existing ? `Edit ${kind} ${row.id}` : "Add entity";
}

async function entSave() {
  const kind = $("ent-kind").value;
  const id = $("ent-id").value.trim();
  if (!id) {
    $("ent-result").textContent = "Id is required.";
    return;
  }
  const body = {
    agent: { displayName: $("ent-displayName").value, blueprint: $("ent-blueprint").value, autonomousLimit: $("ent-autonomousLimit").value },
    blueprint: { displayName: $("ent-displayName").value },
    application: { displayName: $("ent-displayName").value, isMcpServer: $("ent-isMcpServer").checked },
    group: { displayName: $("ent-displayName").value, entraObjectId: $("ent-entraObjectId").value, region: $("ent-region").value },
    member: { groups: entCheckedGroups() },
  }[kind];
  $("ent-result").textContent = `Saving ${kind} ${id}…`;
  const response = await fetch(`/api/gw/entities/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  $("ent-result").textContent = pretty(await response.json());
  if (response.ok) {
    await entLoad();
    entFillForm(kind, { ...(ent.rows?.[kind] || []).find((r) => r.id === (kind === "group" ? id : id.toLowerCase())), existing: true });
  }
}

async function entDelete(kind, id) {
  if (!confirm(`Delete ${kind} ${id} from the PDP registry?`)) return;
  const response = await fetch(`/api/gw/entities/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`, { method: "DELETE" });
  $("ent-result").textContent = pretty(await response.json());
  if (response.ok) entLoad();
}

$("ent-tables").addEventListener("click", (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  const { kind, id } = button.dataset;
  if (button.classList.contains("ent-edit")) entFillForm(kind, { ...ent.rows[kind].find((r) => r.id === id), existing: true });
  if (button.classList.contains("ent-delete")) entDelete(kind, id);
  if (button.classList.contains("ent-register")) entFillForm("agent", { id: id.toLowerCase(), displayName: button.dataset.name });
  $("ent-form-title").scrollIntoView({ behavior: "smooth", block: "nearest" });
});
$("ent-kind").addEventListener("change", () => entFillForm($("ent-kind").value));
$("ent-refresh").addEventListener("click", entLoad);
$("ent-save").addEventListener("click", entSave);
$("ent-clear").addEventListener("click", () => entFillForm($("ent-kind").value));
entFillForm("agent");

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

$("gw-mode").addEventListener("change", () => {
  gwUpdateHint();
  gwRenderAgent();
  gwNewConversation();
});
$("gw-agent-select").addEventListener("change", () => {
  gwRenderAgent();
  ksFillTarget();
  pdpFillPresets();
  gwNewConversation();
});
$("gw-new").addEventListener("click", gwNewConversation);
$("gw-send").addEventListener("click", gwSend);
$("gw-input").addEventListener("keydown", (event) => {
  if (event.key === "Enter") gwSend();
});
document.querySelectorAll(".gw-chip").forEach((chip) =>
  chip.addEventListener("click", () => {
    $("gw-input").value = chip.dataset.prompt;
    gwSend();
  })
);
$("gw-tools").addEventListener("click", async () => {
  const mode = $("gw-mode").value.startsWith("host") ? "host-app" : "agent-app";
  $("gw-tools-result").textContent = "Connecting through the gateway…";
  const agent = encodeURIComponent($("gw-agent-select").value || "");
  $("gw-tools-result").textContent = pretty(await (await fetch(`/api/gw/tools?mode=${mode}&agent=${agent}`)).json());
});
$("ks-scope").addEventListener("change", ksFillTarget);
$("ks-kill").addEventListener("click", () => ksSend("kill"));
$("ks-restore").addEventListener("click", () => ksSend("restore"));
$("ks-refresh").addEventListener("click", ksLoad);
$("claims-refresh").addEventListener("click", claimsLoad);
$("claims-reset").addEventListener("click", claimsReset);
$("pdp-preset").addEventListener("change", () => ($("pdp-request").value = pretty(pdpPresets()[$("pdp-preset").value])));
$("pdp-evaluate").addEventListener("click", pdpEvaluate);
$("pdp-policies").addEventListener("click", pdpShowPolicies);

// Sub-tabs: kill switch / claims table / PDP playground / PDP entities. The kill list,
// the claims table and the entities are reloaded on open, since something else may have
// changed them.
document.querySelectorAll(".subtabs button").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".subtabs button").forEach((b) => b.classList.toggle("active", b === button));
    document.querySelectorAll(".subtab").forEach((p) => p.classList.toggle("active", p.id === `subtab-${button.dataset.subtab}`));
    // Storage is reached with its own connection string, so this does not need the internal key.
    if (button.dataset.subtab === "entities") entLoad();
    if (!gw.info?.ready?.internalKey) return;
    if (button.dataset.subtab === "killswitch") ksLoad();
    if (button.dataset.subtab === "claims") claimsLoad();
  });
});

// Load the tab's data when it is first opened (the session is loaded by app.js).
let gwLoaded = false;
document.querySelector('.tabs button[data-tab="gateway"]').addEventListener("click", async () => {
  gwRenderUser();
  gwUpdateHint();
  if (gwLoaded) return;
  gwLoaded = true;
  await gwLoadInfo();
  pdpFillPresets();
  gwNewConversation();
  if (gw.info?.ready?.internalKey) {
    ksLoad();
    claimsLoad();
  }
});
