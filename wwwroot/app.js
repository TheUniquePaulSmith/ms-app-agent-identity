// POC Claims Web UI. Vanilla JS, no build step.
//
// Two ways to reach the Claims API are shown side by side:
//   Application runtime : deterministic code calls fixed endpoints (tab "direct").
//   Agent runtime loop  : an LLM proposes tool calls, the host app decides the
//                         identity and mints a token FOR THE MCP SERVER; the MCP
//                         server validates it, authorizes, and exchanges it for a
//                         Claims API token of its own (tab "agent").
//
// Tokens for the *-user modes come from /auth/token (browser session cookie).

const state = {
  session: null,
  hostToken: null,
  agentToken: null,
  conversationId: null,
  llm: loadLlmSettings(),
};

const $ = (id) => document.getElementById(id);
const pretty = (value) => (typeof value === "string" ? value : JSON.stringify(value, null, 2));

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------
document.querySelectorAll(".tabs button").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b === button));
    document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab.id === `tab-${button.dataset.tab}`));
  });
});

// ---------------------------------------------------------------------------
// Session, profile, tokens
// ---------------------------------------------------------------------------
function decodeJwt(token) {
  try {
    const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload.padEnd(payload.length + ((4 - (payload.length % 4)) % 4), "=")));
  } catch {
    return null;
  }
}

function summarizeToken(token) {
  const p = decodeJwt(token);
  if (!p) return "(not decodable)";
  return {
    aud: p.aud,
    scp: p.scp,
    azp: p.azp || p.appid,
    oid: p.oid,
    name: p.preferred_username || p.name,
    tid: p.tid,
    expires: p.exp ? new Date(p.exp * 1000).toLocaleString() : undefined,
  };
}

async function loadSession() {
  const response = await fetch("/api/session");
  state.session = await response.json();
  const s = state.session;

  $("session-text").textContent = s.signedIn ? `Signed in as ${s.user.name}` : "Not signed in";
  $("sign-in").hidden = s.signedIn;
  $("sign-out").hidden = !s.signedIn;
  $("profile-user").textContent = pretty(s.user);
  $("id-host").textContent = s.hostApplicationClientId;
  $("id-blueprint").textContent = s.agentBlueprintClientId;
  $("id-agent").textContent = s.agentIdentityClientId;
  $("id-scope").textContent = s.claimsApiScope;
  $("id-mcp").textContent = s.mcpEndpoint;
  $("id-mcp-client").textContent = s.mcpClientId || "—";
  $("id-mcp-scope").textContent = s.mcpScope || "—";

  if (!state.llm.baseUrl && s.llmDefaults?.baseUrl) state.llm.baseUrl = s.llmDefaults.baseUrl;
  if (!state.llm.model && s.llmDefaults?.model) state.llm.model = s.llmDefaults.model;
  renderLlmSettings();

  if (s.signedIn) await refreshTokens();
  updateModeHint();
}

async function refreshTokens() {
  $("token-error").hidden = true;
  if (!state.session?.signedIn) {
    $("token-error").textContent = "Sign in first.";
    $("token-error").hidden = false;
    return;
  }
  const response = await fetch("/auth/token");
  if (!response.ok) {
    $("token-error").textContent = `/auth/token failed: HTTP ${response.status}`;
    $("token-error").hidden = false;
    return;
  }
  const json = await response.json();
  state.hostToken = json.hostToken?.accessToken || null;
  state.agentToken = json.agentToken?.accessToken || null;
  $("host-token-claims").textContent = state.hostToken ? pretty(summarizeToken(state.hostToken)) : "—";
  $("agent-token-claims").textContent = state.agentToken
    ? pretty(summarizeToken(state.agentToken))
    : pretty({ error: json.agentToken?.error, adminConsentUrl: json.adminConsentUrlForAgentScope });
  updateModeHint();
}

$("refresh-tokens").addEventListener("click", refreshTokens);

// ---------------------------------------------------------------------------
// LLM connection
// ---------------------------------------------------------------------------
function loadLlmSettings() {
  try {
    return JSON.parse(localStorage.getItem("poc-llm") || "{}");
  } catch {
    return {};
  }
}

function saveLlmSettings() {
  state.llm = {
    baseUrl: $("llm-base").value.trim(),
    apiKey: $("llm-key").value.trim(),
    model: ($("llm-model-text").value || $("llm-model").value || "").trim(),
  };
  try {
    localStorage.setItem("poc-llm", JSON.stringify(state.llm));
  } catch {
    /* storage unavailable */
  }
}

function renderLlmSettings() {
  $("llm-base").value = state.llm.baseUrl || "";
  $("llm-key").value = state.llm.apiKey || "";
  $("llm-model-text").value = state.llm.model || "";
  if (state.llm.model && ![...$("llm-model").options].some((o) => o.value === state.llm.model)) {
    $("llm-model").add(new Option(state.llm.model, state.llm.model, true, true));
  }
}

["llm-base", "llm-key", "llm-model-text"].forEach((id) => $(id).addEventListener("change", saveLlmSettings));
$("llm-model").addEventListener("change", () => {
  $("llm-model-text").value = $("llm-model").value;
  saveLlmSettings();
});

$("llm-list").addEventListener("click", async () => {
  saveLlmSettings();
  $("llm-result").textContent = "Listing models…";
  const query = new URLSearchParams({ baseUrl: state.llm.baseUrl || "", apiKey: state.llm.apiKey || "" });
  const response = await fetch(`/api/llm/models?${query}`);
  const json = await response.json();
  $("llm-result").textContent = pretty(json);
  if (Array.isArray(json.models) && json.models.length) {
    const select = $("llm-model");
    select.innerHTML = "";
    json.models.forEach((m) => select.add(new Option(m, m)));
    if (!state.llm.model) {
      select.value = json.models[0];
      $("llm-model-text").value = json.models[0];
      saveLlmSettings();
    } else {
      select.value = state.llm.model;
    }
  }
});

$("llm-test").addEventListener("click", async () => {
  saveLlmSettings();
  $("llm-result").textContent = "Testing tool calling…";
  const response = await fetch("/api/llm/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(state.llm),
  });
  $("llm-result").textContent = pretty(await response.json());
});

// ---------------------------------------------------------------------------
// Application runtime: direct API calls
// ---------------------------------------------------------------------------
function tokenFor(auth) {
  if (auth === "host") return state.hostToken;
  if (auth === "agent") return state.agentToken;
  return null;
}

function renderTokenSummary(container, status, body) {
  const info = body?.downstream?._debug?.tokenInfo || body?._debug?.tokenInfo;
  container.hidden = false;
  const ok = status < 300;
  container.innerHTML = `
    <b>HTTP</b><span class="${ok ? "status-ok" : "status-deny"}">${status} ${ok ? "ALLOW" : status === 403 ? "DENY (Claims API refused)" : ""}</span>
    <b>Scenario</b><span>${body?.scenario ?? ""}</span>
    <b>Caller kind</b><span>${info?.callerKind ?? "—"}</span>
    <b>azp (actor)</b><span>${info?.callerAppId ?? "—"}</span>
    <b>oid (subject)</b><span>${info?.objectId ?? "—"}</span>
    <b>roles</b><span>${(info?.roles || []).join(" ") || "—"}</span>
    <b>scp</b><span>${info?.scp ?? "—"}</span>
    <b>parent blueprint</b><span>${info?.parentBlueprintAppId ?? "—"}${info?.agentDetectedBy ? ` (${info.agentDetectedBy})` : ""}</span>
    <b>required</b><span>${(body?.downstream?.required || []).join(" or ") || body?.requiredPermission || "—"}</span>`;
}

document.querySelectorAll(".scenario").forEach((button) => {
  button.addEventListener("click", async () => {
    const claimId = encodeURIComponent($("claim-id").value.trim() || "CLAIM-1001");
    const headers = { "Content-Type": "application/json" };
    const token = tokenFor(button.dataset.auth);
    if (button.dataset.auth !== "none") {
      if (!token) {
        $("direct-result").textContent = `This scenario needs the ${button.dataset.auth} token. Sign in and refresh tokens on the Profile tab.`;
        return;
      }
      headers.Authorization = `Bearer ${token}`;
    }
    $("direct-result").textContent = "Calling…";
    $("direct-summary").hidden = true;
    const response = await fetch(`/claims/${claimId}/${button.dataset.path}`, { method: "POST", headers, body: "{}" });
    let body;
    try {
      body = await response.json();
    } catch {
      body = { raw: await response.text() };
    }
    renderTokenSummary($("direct-summary"), response.status, body);
    $("direct-result").textContent = pretty(body);
  });
});

// ---------------------------------------------------------------------------
// Agent runtime loop: chat + trace
// ---------------------------------------------------------------------------
const modeHints = {
  "agent-app": "Tool calls run as the AGENT IDENTITY with an app-only token for the MCP server (roles: Mcp.Analyze.All). The MCP server enforces that, then calls the Claims API as itself (client credentials). The agent can analyze but not archive. No sign-in needed.",
  "agent-user": "Tool calls run as the AGENT IDENTITY on behalf of YOU (scp: Mcp.Analyze on the MCP server token). Needs the agent token (aud = blueprint). The MCP server does an on-behalf-of exchange, so the Claims API still sees you as subject but the MCP server as actor.",
  "host-user": "Tool calls run as the HOST APPLICATION on behalf of YOU (scp: Mcp.Archive). Needs the host token. The MCP server sees the app as actor, not the agent; the Claims API sees the MCP server.",
  "host-app": "Tool calls run as the HOST APPLICATION app-only (roles: Mcp.Archive.All). Shown as the anti-pattern: the agent would borrow the app's identity and audit trail.",
};

function updateModeHint() {
  const mode = $("chat-mode").value;
  let hint = modeHints[mode];
  if (mode === "agent-user" && !state.agentToken) hint += " (agent token missing: sign in and refresh tokens)";
  if (mode === "host-user" && !state.hostToken) hint += " (host token missing: sign in and refresh tokens)";
  $("chat-mode-hint").textContent = hint;
}

$("chat-mode").addEventListener("change", () => {
  updateModeHint();
  newConversation();
});

function appendMessage(role, text) {
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  div.textContent = text;
  $("chat-log").appendChild(div);
  $("chat-log").scrollTop = $("chat-log").scrollHeight;
}

async function newConversation() {
  if (state.conversationId) {
    try {
      await fetch(`/chat/${state.conversationId}`, { method: "DELETE" });
    } catch {
      /* ignore */
    }
  }
  state.conversationId = null;
  $("chat-log").innerHTML = "";
  $("trace").innerHTML = "";
  appendMessage("system", `New conversation. Identity for tool calls: ${$("chat-mode").selectedOptions[0].text}`);
}

$("chat-new").addEventListener("click", newConversation);

document.querySelectorAll(".chip").forEach((chip) =>
  chip.addEventListener("click", () => {
    $("chat-input").value = chip.dataset.prompt;
    sendChat();
  })
);

$("chat-send").addEventListener("click", sendChat);
$("chat-input").addEventListener("keydown", (event) => {
  if (event.key === "Enter") sendChat();
});

function renderTrace(trace) {
  const container = $("trace");
  if (!trace || trace.length === 0) {
    container.innerHTML += `<div class="trace-step"><em>No tool calls in this turn.</em></div>`;
    return;
  }
  trace.forEach((step) => {
    const mcp = step.mcpServerSaw || {};
    const api = step.tokenInfo || {};
    const exchange = step.exchange || null;
    const ok = step.decision === "ALLOW";
    const deniedAtMcp = step.decidedBy === "mcp-server";
    const div = document.createElement("div");
    div.className = "trace-step";
    div.innerHTML = `
      <div class="head">
        <span><b>${step.tool}</b>(${step.arguments ? JSON.stringify(step.arguments) : ""})</span>
        <span class="${ok ? "status-ok" : "status-deny"}">${step.decision}${step.downstreamStatus ? ` · HTTP ${step.downstreamStatus}` : ""}</span>
      </div>
      <table>
        <tr><td>identity chosen by host app</td><td>${step.identity}</td></tr>
        <tr><td>permission kind</td><td>${step.permissionKind}</td></tr>
        <tr><th colspan="2">Hop 1 · MCP server validated (aud = MCP server)</th></tr>
        <tr><td>MCP server saw</td><td>${mcp.callerKind ?? "—"}</td></tr>
        <tr><td>azp (actor)</td><td>${mcp.callerAppId ?? "—"}</td></tr>
        <tr><td>oid (subject)</td><td>${mcp.objectId ?? "—"}${mcp.userName ? ` (${mcp.userName})` : ""}</td></tr>
        <tr><td>roles / scp</td><td>${(mcp.roles || []).join(" ") || "—"} / ${mcp.scp ?? "—"}</td></tr>
        <tr><td>parent blueprint</td><td>${mcp.parentBlueprintAppId ?? "—"}</td></tr>
        <tr><td>MCP server decision</td><td class="${deniedAtMcp ? "status-deny" : "status-ok"}">${deniedAtMcp ? "DENY" : "ALLOW"}${deniedAtMcp ? " · the inbound token was never exchanged" : ""}</td></tr>
        <tr><th colspan="2">Hop 2 · token exchange and Claims API (aud = Claims API)</th></tr>
        <tr><td>exchange</td><td>${exchange ? `${exchange.grant} as ${exchange.actor}` : deniedAtMcp ? "— (denied before exchange)" : "—"}</td></tr>
        <tr><td>Claims API saw</td><td>${api.callerKind ?? "—"}</td></tr>
        <tr><td>azp (actor)</td><td>${api.callerAppId ?? "—"}${api.viaIntermediary ? " (MCP server)" : ""}</td></tr>
        <tr><td>oid (subject)</td><td>${api.objectId ?? "—"}${api.userName ? ` (${api.userName})` : ""}</td></tr>
        <tr><td>roles / scp</td><td>${(api.roles || []).join(" ") || "—"} / ${api.scp ?? "—"}</td></tr>
      </table>
      <details><summary>raw tool result</summary><pre class="json">${escapeHtml(step.resultPreview || "")}</pre></details>`;
    container.appendChild(div);
  });
}

function escapeHtml(text) {
  return text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

async function sendChat() {
  const message = $("chat-input").value.trim();
  if (!message) return;
  saveLlmSettings();
  $("chat-error").hidden = true;

  const mode = $("chat-mode").value;
  const headers = { "Content-Type": "application/json" };
  if (mode === "agent-user" || mode === "host-user") {
    const token = mode === "agent-user" ? state.agentToken : state.hostToken;
    if (!token) {
      $("chat-error").textContent = "This mode needs a user token. Sign in and refresh tokens on the Profile tab.";
      $("chat-error").hidden = false;
      return;
    }
    headers.Authorization = `Bearer ${token}`;
  }

  appendMessage("user", message);
  $("chat-input").value = "";
  $("chat-send").disabled = true;
  const thinking = document.createElement("div");
  thinking.className = "msg system";
  thinking.textContent = "Running agent loop…";
  $("chat-log").appendChild(thinking);

  try {
    const response = await fetch(`/chat/${mode}`, {
      method: "POST",
      headers,
      body: JSON.stringify({ conversationId: state.conversationId, message, llm: state.llm }),
    });
    const json = await response.json();
    thinking.remove();
    if (!response.ok) {
      $("chat-error").textContent = `HTTP ${response.status}: ${json.message || json.error || pretty(json)}${json.inner ? ` — ${json.inner}` : ""}`;
      $("chat-error").hidden = false;
      appendMessage("system", `Turn failed (${json.error || response.status}). See the error above.`);
      return;
    }
    state.conversationId = json.conversationId;
    (json.trace || []).forEach((step) =>
      appendMessage("tool", `${step.tool}(${step.arguments ? JSON.stringify(step.arguments) : ""}) as ${step.identity} → ${step.decision}`)
    );
    appendMessage("assistant", json.answer || "(no answer)");
    const header = document.createElement("div");
    header.className = "hint";
    header.textContent = `Turn: ${json.iterations} model call(s), ${json.trace.length} tool call(s), model ${json.model}, actor ${json.actor}`;
    $("trace").appendChild(header);
    renderTrace(json.trace);
  } catch (error) {
    thinking.remove();
    $("chat-error").textContent = String(error);
    $("chat-error").hidden = false;
  } finally {
    $("chat-send").disabled = false;
  }
}

$("mcp-refresh").addEventListener("click", async () => {
  const mode = $("chat-mode").value.startsWith("host") ? "host-app" : "agent-app";
  $("mcp-tools").textContent = "Connecting to MCP server…";
  const response = await fetch(`/api/mcp/tools?mode=${mode}`);
  $("mcp-tools").textContent = pretty(await response.json());
});

// ---------------------------------------------------------------------------
loadSession().then(() => appendMessage("system", "Pick an identity mode, then ask about a claim."));
