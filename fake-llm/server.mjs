// Minimal OpenAI-compatible stand-in for vLLM, for demos and tests without a GPU.
//
// It is NOT a language model. It pattern-matches the latest user message and
// emits an OpenAI-style tool call for the matching Claims tool, then, once the
// tool result comes back, writes a short canned answer that reflects whether
// the MCP server or the Claims API allowed or denied the call (the tool result
// carries decidedBy, the claims each hop saw, and the exchange details). Good
// enough to exercise the agent loop and the identity/authorization trace end to end.
//
// Env: PORT (default 8000). Endpoints: GET /v1/models, POST /v1/chat/completions

import http from "node:http";

const PORT = process.env.PORT || 8000;
const MODEL = "fake-claims-model";

function pickTool(text, tools) {
  const names = new Set((tools || []).map((t) => t.function?.name));
  const claim = (text.match(/CLAIM-\d+/i) || ["CLAIM-1001"])[0].toUpperCase();
  const lower = text.toLowerCase();
  let tool = null;
  if (/\blist\b|which claims|my claims/.test(lower) && names.has("list_claims")) return { tool: "list_claims", args: {} };
  if (/\barchive|close\b/.test(lower)) tool = "archive_claim";
  else if (/evidence|attach|photo|document/.test(lower)) tool = "get_claim_evidence";
  else if (/analy[sz]e|assess|review|finding/.test(lower)) tool = "analyze_claim";
  else if (/status|look ?up|summar|amount|what is|tell me/.test(lower)) tool = "get_claim";
  else if (/time/.test(lower) && names.has("get_server_time")) tool = "get_server_time";
  else tool = "analyze_claim";
  if (!names.has(tool)) return null;
  return { tool, args: tool === "get_server_time" ? {} : { claimId: claim } };
}

function answerFromToolResult(toolName, resultText) {
  let parsed;
  try {
    parsed = JSON.parse(resultText);
  } catch {
    return `The ${toolName} tool returned: ${resultText.slice(0, 300)}`;
  }
  if (toolName === "get_server_time") return `The server time is ${resultText}.`;

  const status = parsed.httpStatus;
  const body = parsed.body || {};

  // Gateway scenario (claims-mcp-azure behind API Management, AuthZEN/Cedar PDP).
  if (parsed.pep) {
    if (status >= 400) {
      const where = parsed.decidedBy === "gateway" ? "the API Management gateway" : parsed.decidedBy === "pdp" ? `the policy decision point (asked by ${parsed.pep})` : parsed.decidedBy;
      const policies = parsed.authzen?.policyIds || parsed.downstreamAuthzen?.policyIds || body.policyIds || [];
      return `I could not run ${toolName}: ${where} refused it (HTTP ${status}). ${body.reason || body.error || ""}${policies.length ? ` Policies: ${policies.join(", ")}.` : ""}`;
    }
    if (toolName === "list_claims") return `You can see ${(body.claims || []).map((c) => `${c.claimId} (${c.region}, ${c.status}, ${c.amount})`).join(", ") || "no claims"}.${body.hiddenByPolicy?.length ? ` The PDP hid ${body.hiddenByPolicy.map((h) => h.claimId).join(", ")}.` : ""}`;
    const c = body.claim || {};
    if (toolName === "analyze_claim") return `Analysis of ${c.claimId} stored (status ${body.statusBefore} -> ${c.status}, risk ${c.riskScore}): ${(c.findings || []).join("; ")}.`;
    if (toolName === "archive_claim") return `Claim ${c.claimId} is now archived (was ${body.statusBefore}).`;
    if (toolName === "get_claim_evidence") return `Evidence on ${body.claimId}: ${(body.evidence || []).join(", ")}.`;
    if (toolName === "get_claim") return `Claim ${c.claimId} (${c.region}) is ${c.status} with an amount of ${c.amount}${c.litigationHold ? ", on litigation hold" : ""}.`;
  }
  const decidedBy = parsed.decidedBy === "mcp-server" ? "the MCP server" : "the Claims API";
  const mcpSaw = parsed.mcpServer?.saw || {};
  const apiSaw = body._debug?.tokenInfo || {};
  const who =
    (mcpSaw.callerKind ? ` The MCP server saw: ${mcpSaw.callerKind}.` : "") +
    (apiSaw.callerKind ? ` The Claims API saw: ${apiSaw.callerKind}${parsed.exchange ? ` after a ${parsed.exchange.grant.split(" ")[0]} exchange` : ""}.` : "");
  if (status === 403) {
    const seen = parsed.decidedBy === "mcp-server" ? mcpSaw : apiSaw;
    return `I could not run ${toolName}: ${decidedBy} refused with 403. The current identity (${seen.callerKind || "unknown"}) has roles [${(seen.roles || []).join(", ")}] and scp "${seen.scp || ""}", but this operation requires ${(body.required || []).join(" or ")}.${parsed.decidedBy === "mcp-server" ? " The token was not exchanged, so the Claims API was never called." : ""}`;
  }
  if (status === 401) return `${decidedBy} rejected the token (401): ${body.error}.`;
  if (status === 502 && body.stage === "token-exchange") return `The MCP server could not exchange the token for a Claims API token: ${body.detail}`;
  if (status >= 400) return `${toolName} failed with HTTP ${status} at ${decidedBy}.`;
  if (toolName === "analyze_claim") return `Analysis complete for ${body.received?.claimId}: ${(body.findings || []).join("; ")}.${who}`;
  if (toolName === "archive_claim") return `Claim ${body.received?.claimId} has been archived.${who}`;
  if (toolName === "get_claim_evidence") return `Evidence on ${body.claimId}: ${(body.evidence || []).join(", ")}.${who}`;
  if (toolName === "get_claim") return `Claim ${body.claimId} is ${body.status} with an amount of ${body.amount}.${who}`;
  return `Done: ${JSON.stringify(body).slice(0, 300)}`;
}

function completion(message, finishReason) {
  return {
    id: `chatcmpl-${Date.now()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: MODEL,
    choices: [{ index: 0, message, finish_reason: finishReason }],
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  };
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
  });
}

const server = http.createServer(async (req, res) => {
  const path = req.url.split("?")[0];
  const send = (status, payload) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(payload));
  };

  if (req.method === "GET" && path === "/v1/models") {
    return send(200, { object: "list", data: [{ id: MODEL, object: "model", owned_by: "poc" }] });
  }

  if (req.method === "POST" && path === "/v1/chat/completions") {
    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      return send(400, { error: { message: "invalid json" } });
    }
    const messages = body.messages || [];
    const last = messages[messages.length - 1] || {};

    // Tool result came back: produce the final answer.
    if (last.role === "tool") {
      const call = [...messages].reverse().find((m) => m.role === "assistant" && m.tool_calls?.length);
      const toolName = call?.tool_calls?.find((t) => t.id === last.tool_call_id)?.function?.name || "tool";
      const text = typeof last.content === "string" ? last.content : JSON.stringify(last.content);
      console.log(`[fake-llm] tool result for ${toolName} -> final answer`);
      return send(200, completion({ role: "assistant", content: answerFromToolResult(toolName, text) }, "stop"));
    }

    const userText = typeof last.content === "string" ? last.content : JSON.stringify(last.content);
    const choice = pickTool(userText, body.tools);
    if (!choice) {
      return send(200, completion({ role: "assistant", content: "I have no tool for that request." }, "stop"));
    }
    console.log(`[fake-llm] "${userText.slice(0, 60)}" -> tool_call ${choice.tool}(${JSON.stringify(choice.args)})`);
    return send(
      200,
      completion(
        {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: `call_${Math.random().toString(36).slice(2, 10)}`,
              type: "function",
              function: { name: choice.tool, arguments: JSON.stringify(choice.args) },
            },
          ],
        },
        "tool_calls"
      )
    );
  }

  send(404, { error: { message: `no route for ${req.method} ${path}` } });
});

server.listen(PORT, () => {
  console.log(`Fake OpenAI-compatible LLM listening on http://localhost:${PORT}/v1 (model: ${MODEL})`);
  console.log("Not a real model: it maps the user's wording to one Claims tool call, then summarises the tool result.");
});
