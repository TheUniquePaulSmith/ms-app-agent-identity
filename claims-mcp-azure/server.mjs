// Hosted MCP server for the gateway scenario (Proposal PEP 2). It sits behind
// Azure API Management (PEP 1) and calls the hosted Claims API (PEP 3).
//
// Same OAuth design as claims-mcp/server.mjs (own Entra registration, jose
// validation, never forwards the inbound token, OBO / client credentials for
// the Claims API), with these changes from the proposal:
//
//   - hasPermission() is replaced by an AuthZEN call to the PDP per tool call,
//     with the claim id as the resource (the PDP loads region/status/amount);
//   - tools/list is filtered with one AuthZEN batch evaluation, so the LLM is
//     only offered tools the PDP allows for this caller;
//   - list_claims returns only the records the PDP lets this caller read
//     (batch evaluation per record);
//   - the gateway's decision (header x-gateway-decision, trusted only with the
//     matching x-gateway-key) and both PDP decisions go into the tool result,
//     so the host app's trace shows all three enforcement points.
//
// Config (env, or claims-mcp-azure/config.json, falling back to claims-mcp/config.json
// for the MCP credential when run locally):
//   PORT (5012), SELF_URL (public URL of this server's /mcp parent: the APIM API URL),
//   CLAIMS_API_URL, TENANT_ID, MCP_CLIENT_ID, MCP_CLIENT_SECRET, CLAIMS_API_APP_ID,
//   CLAIMS_API_SCOPE, PDP_URL, POC_INTERNAL_KEY, GATEWAY_KEY

import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import express from "express";
import { z } from "zod";
import { createRemoteJWKSet, jwtVerify, decodeJwt } from "jose";
import { ConfidentialClientApplication } from "@azure/msal-node";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const here = dirname(fileURLToPath(import.meta.url));
const readConfig = (path) => {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return {};
  }
};
const fileConfig = { ...readConfig(join(here, "..", "claims-mcp", "config.json")), ...readConfig(join(here, "config.json")) };
const cfg = (key, fallback) => process.env[key] ?? fileConfig[key] ?? fallback;
const required = (key) => {
  const value = cfg(key);
  if (!value || String(value).startsWith("<")) {
    console.error(`Missing ${key}: set it in App Service settings (main.bicep) or claims-mcp/config.json or as an environment variable.`);
    process.exit(1);
  }
  return String(value);
};

const PORT = process.env.PORT || 5012; // App Service sets PORT; config.json's PORT belongs to the local server
const SELF_URL = String(process.env.SELF_URL ?? `http://localhost:${PORT}`).replace(/\/$/, "");
const CLAIMS_API_URL = String(process.env.CLAIMS_API_URL ?? "http://localhost:5021").replace(/\/$/, "");
const TENANT_ID = required("TENANT_ID");
const MCP_CLIENT_ID = cfg("MCP_CLIENT_ID", "");
const MCP_CLIENT_SECRET = cfg("MCP_CLIENT_SECRET", "");
const CLAIMS_API_APP_ID = required("CLAIMS_API_APP_ID");
const CLAIMS_API_SCOPE = cfg("CLAIMS_API_SCOPE", `api://${CLAIMS_API_APP_ID}/.default`);
const PDP_URL = String(process.env.PDP_URL ?? "http://localhost:5010").replace(/\/$/, "");
const INTERNAL_KEY = process.env.POC_INTERNAL_KEY ?? "";
const GATEWAY_KEY = process.env.GATEWAY_KEY ?? "";

const RESOURCE = `${SELF_URL}/mcp`;
const ISSUER = `https://login.microsoftonline.com/${TENANT_ID}/v2.0`;
const JWKS_URL = `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`;
const PRM_URL = `${SELF_URL}/.well-known/oauth-protected-resource`;

// tool name -> PDP action (list_claims reads, so it is get_claim per record)
const TOOL_ACTIONS = {
  list_claims: "get_claim",
  get_claim: "get_claim",
  get_claim_evidence: "get_claim_evidence",
  analyze_claim: "analyze_claim",
  archive_claim: "archive_claim",
};

if (!MCP_CLIENT_ID || !MCP_CLIENT_SECRET) {
  console.error("MCP_CLIENT_ID and MCP_CLIENT_SECRET are required (env, config.json or ../claims-mcp/config.json).");
  process.exit(1);
}

const stamp = () => new Date().toISOString();

// ---------------------------------------------------------------------------
// 1. Inbound token validation (this server is the audience)
// ---------------------------------------------------------------------------

const jwks = createRemoteJWKSet(new URL(JWKS_URL));

async function validateInboundToken(token) {
  const { payload } = await jwtVerify(token, jwks, {
    issuer: ISSUER,
    audience: [MCP_CLIENT_ID, `api://${MCP_CLIENT_ID}`],
    algorithms: ["RS256"],
  });
  if (payload.tid !== TENANT_ID) throw new Error(`tenant mismatch: ${payload.tid}`);
  return payload;
}

const tokenVerifier = {
  async verifyAccessToken(token) {
    let payload;
    try {
      payload = await validateInboundToken(token);
    } catch (error) {
      let hint = error.message;
      try {
        const raw = decodeJwt(token);
        hint += ` (token aud=${raw.aud}, iss=${raw.iss}, azp=${raw.azp || raw.appid})`;
      } catch {
        /* not a JWT */
      }
      console.log(`[${stamp()}] 401 invalid_token: ${hint}`);
      throw new InvalidTokenError(hint.replaceAll('"', "'"));
    }
    return {
      token,
      clientId: payload.azp || payload.appid,
      scopes: scopesOf(payload),
      expiresAt: payload.exp,
      resource: new URL(RESOURCE),
      extra: { payload },
    };
  },
};

const bearerAuth = requireBearerAuth({ verifier: tokenVerifier, resourceMetadataUrl: PRM_URL, expectedResource: new URL(RESOURCE) });

const rolesOf = (p) => (Array.isArray(p.roles) ? p.roles : []);
const scopesOf = (p) => (typeof p.scp === "string" ? p.scp.split(" ").filter(Boolean) : []);

function summarizeInbound(payload) {
  const isDelegated = scopesOf(payload).length > 0;
  const isAgent = Boolean(payload.xms_par_app_azp) || payload.xms_act_fct === "11";
  return {
    audience: payload.aud,
    callerKind: isAgent
      ? isDelegated ? "user via agent-identity (delegated)" : "agent-identity (app-only)"
      : isDelegated ? "user via host-application (delegated)" : "host-application (app-only)",
    agentDetectedBy: payload.xms_par_app_azp ? "xms_par_app_azp claim" : payload.xms_act_fct === "11" ? "xms_act_fct claim" : undefined,
    tokenType: isDelegated ? "DELEGATED (scp claim)" : "APP-ONLY (roles claim)",
    callerAppId: payload.azp || payload.appid,
    objectId: payload.oid,
    userName: payload.preferred_username || payload.upn,
    roles: payload.roles,
    scp: payload.scp,
    parentBlueprintAppId: payload.xms_par_app_azp,
    actorFacets: payload.xms_act_fct,
    expires: payload.exp ? new Date(payload.exp * 1000).toISOString() : undefined,
  };
}

// ---------------------------------------------------------------------------
// 2. PEP 2: AuthZEN calls to the PDP (fail closed)
// ---------------------------------------------------------------------------

// Builds the AuthZEN subject + context from the validated inbound token
// (Proposal 5.2): the actor is the subject, the user travels in onBehalfOf.
function authzenParty(payload) {
  const delegated = scopesOf(payload).length > 0;
  const isAgent = Boolean(payload.xms_par_app_azp) || payload.xms_act_fct === "11";
  return {
    subject: {
      type: isAgent ? "agent" : "application",
      id: payload.azp || payload.appid,
      properties: {
        blueprint: payload.xms_par_app_azp,
        permissions: delegated ? scopesOf(payload) : rolesOf(payload),
        tenant: payload.tid,
      },
    },
    context: {
      pep: "claims-mcp",
      onBehalfOf: delegated ? payload.oid : undefined,
      onBehalfOfUpn: delegated ? payload.preferred_username || payload.upn : undefined,
    },
  };
}

async function pdpPost(path, body) {
  const response = await fetch(`${PDP_URL}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-pdp-key": INTERNAL_KEY, "x-request-id": randomUUID() },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error(`PDP HTTP ${response.status}`);
  return response.json();
}

async function authorize(payload, actionName, claimId) {
  const party = authzenParty(payload);
  const request = {
    ...party,
    action: { name: actionName },
    resource: { type: "claim", id: claimId },
    context: { ...party.context, time: stamp() },
  };
  try {
    return { reachable: true, request, ...(await pdpPost("/access/v1/evaluation", request)) };
  } catch (error) {
    return {
      reachable: false,
      request,
      decision: false,
      context: { reason_admin: { en: `PDP unavailable: ${error.message}; failing closed` }, reason_user: { en: "Authorization is temporarily unavailable." }, policyIds: ["fail-closed-pdp"] },
    };
  }
}

const authzenSummary = (a) =>
  a && {
    request: a.request,
    decision: a.decision,
    policyIds: a.context?.policyIds,
    policyVersion: a.context?.policyVersion,
    reason_admin: a.context?.reason_admin?.en,
    reason_user: a.context?.reason_user?.en,
    user: a.context?.user,
    resource: a.context?.resource,
  };

// tools/list: which tools may this caller use at all? One batch evaluation
// against the MCP server resource (no claim chosen yet).
async function allowedTools(payload) {
  const party = authzenParty(payload);
  const names = Object.keys(TOOL_ACTIONS);
  try {
    const result = await pdpPost("/access/v1/evaluations", {
      ...party,
      resource: { type: "mcp_server", id: "claims-mcp" },
      evaluations: names.map((n) => ({ action: { name: TOOL_ACTIONS[n] } })),
    });
    const allowed = names.filter((_, i) => result.evaluations[i]?.decision === true);
    console.log(`[${stamp()}] tools/list for ${party.subject.type}:${party.subject.id} => ${allowed.join(", ") || "(none)"}`);
    return allowed;
  } catch (error) {
    console.error(`[${stamp()}] tools/list PDP batch failed (${error.message}); offering no tools`);
    return [];
  }
}

// ---------------------------------------------------------------------------
// 3. Token exchange: the MCP server's own credential gets the Claims API token
// ---------------------------------------------------------------------------

const confidentialClient = new ConfidentialClientApplication({
  auth: { clientId: MCP_CLIENT_ID, clientSecret: MCP_CLIENT_SECRET, authority: `https://login.microsoftonline.com/${TENANT_ID}` },
});

async function acquireClaimsApiToken(inboundToken, inboundPayload) {
  const delegated = scopesOf(inboundPayload).length > 0;
  const result = delegated
    ? await confidentialClient.acquireTokenOnBehalfOf({ oboAssertion: inboundToken, scopes: [CLAIMS_API_SCOPE] })
    : await confidentialClient.acquireTokenByClientCredential({ scopes: [CLAIMS_API_SCOPE] });
  const outbound = decodeJwt(result.accessToken);
  return {
    accessToken: result.accessToken,
    exchange: {
      grant: delegated ? "on-behalf-of (urn:ietf:params:oauth:grant-type:jwt-bearer)" : "client_credentials",
      actor: MCP_CLIENT_ID,
      scopeRequested: CLAIMS_API_SCOPE,
      outboundToken: { aud: outbound.aud, azp: outbound.azp || outbound.appid, oid: outbound.oid, roles: outbound.roles, scp: outbound.scp, userName: outbound.preferred_username || outbound.upn },
    },
  };
}

async function claimsApi(method, path, accessToken, body) {
  const response = await fetch(`${CLAIMS_API_URL}${path}`, {
    method,
    headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = text;
  }
  return { status: response.status, body: parsed };
}

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

function inboundOf(extra) {
  const auth = extra?.authInfo;
  if (auth?.extra?.payload) return { token: auth.token, payload: auth.extra.payload, gateway: auth.extra.gateway };
  throw new Error("no validated token on the request");
}

function toolResult(payload) {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }], isError: payload.httpStatus >= 400 };
}

async function callTool(toolName, claimId, method, path, extra, body) {
  const { token, payload, gateway } = inboundOf(extra);
  const mcpServerSaw = summarizeInbound(payload);
  const action = TOOL_ACTIONS[toolName];

  // PEP 2
  const authz = await authorize(payload, action, claimId);
  const pep2 = authzenSummary(authz);
  const common = { pep: "claims-mcp", gateway, mcpServer: { saw: mcpServerSaw, action, decision: authz.decision ? "ALLOW" : "DENY" }, authzen: pep2, killList: authz.context?.killList };

  if (!authz.decision) {
    console.log(`[${stamp()}] tools/call ${toolName} ${claimId} => DENY at PDP (${pep2.reason_admin}) | ${mcpServerSaw.callerKind} azp=${mcpServerSaw.callerAppId}`);
    return toolResult({
      httpStatus: authz.reachable ? 403 : 503,
      decidedBy: authz.reachable ? "pdp" : "mcp-server",
      ...common,
      body: { error: "forbidden", reason: pep2.reason_user, policyIds: pep2.policyIds },
    });
  }

  let exchanged;
  try {
    exchanged = await acquireClaimsApiToken(token, payload);
  } catch (error) {
    console.error(`[${stamp()}] tools/call ${toolName} => token exchange failed: ${error.message}`);
    return toolResult({ httpStatus: 502, decidedBy: "mcp-server", ...common, body: { error: "token exchange failed", detail: error.message } });
  }

  const api = await claimsApi(method, path, exchanged.accessToken, body);
  const deniedAtApi = api.status === 403 && api.body?.decidedBy === "pdp";
  console.log(
    `[${stamp()}] tools/call ${toolName} ${claimId} -> ${method} ${path} => ${api.status}` +
      (deniedAtApi ? ` (PDP at claims-api: ${api.body.authzen?.reason_admin})` : "") +
      ` | inbound ${mcpServerSaw.callerKind} azp=${mcpServerSaw.callerAppId} | outbound azp=${exchanged.exchange.outboundToken.azp}`
  );
  return toolResult({
    httpStatus: api.status,
    decidedBy: deniedAtApi ? "pdp" : "claims-api",
    ...common,
    pep: deniedAtApi ? "claims-api" : common.pep,
    exchange: exchanged.exchange,
    downstreamAuthzen: api.body?.authzen,
    body: api.body,
  });
}

async function listClaims(extra) {
  const { token, payload, gateway } = inboundOf(extra);
  const mcpServerSaw = summarizeInbound(payload);
  let exchanged;
  try {
    exchanged = await acquireClaimsApiToken(token, payload);
  } catch (error) {
    return toolResult({ httpStatus: 502, decidedBy: "mcp-server", pep: "claims-mcp", gateway, body: { error: "token exchange failed", detail: error.message } });
  }
  const api = await claimsApi("GET", "/claims", exchanged.accessToken);
  if (api.status !== 200) return toolResult({ httpStatus: api.status, decidedBy: "claims-api", pep: "claims-mcp", gateway, body: api.body });

  // Per-record filter: one AuthZEN batch, record attributes passed as properties.
  const party = authzenParty(payload);
  const claims = api.body.claims || [];
  let batch;
  try {
    batch = await pdpPost("/access/v1/evaluations", {
      ...party,
      action: { name: "get_claim" },
      evaluations: claims.map((c) => ({
        resource: { type: "claim", id: c.claimId, properties: { region: c.region, status: c.status, amount: c.amount, litigationHold: c.litigationHold } },
      })),
    });
  } catch (error) {
    return toolResult({ httpStatus: 503, decidedBy: "mcp-server", pep: "claims-mcp", gateway, body: { error: `PDP unavailable: ${error.message}` } });
  }
  const visible = [];
  const hidden = [];
  claims.forEach((c, i) => {
    const e = batch.evaluations[i];
    if (e?.decision) visible.push({ claimId: c.claimId, region: c.region, status: c.status, amount: c.amount, litigationHold: c.litigationHold, description: c.description });
    else hidden.push({ claimId: c.claimId, policyIds: e?.context?.policyIds });
  });
  console.log(`[${stamp()}] tools/call list_claims => ${visible.length} visible, ${hidden.length} hidden by PDP | ${mcpServerSaw.callerKind}`);
  return toolResult({
    httpStatus: 200,
    decidedBy: "pdp",
    pep: "claims-mcp",
    gateway,
    mcpServer: { saw: mcpServerSaw, action: "get_claim (per record)", decision: "FILTER" },
    exchange: exchanged.exchange,
    body: { claims: visible, hiddenByPolicy: hidden },
  });
}

// ---------------------------------------------------------------------------
// MCP server definition (one instance per request, stateless). Only the tools
// in `allowed` are registered, so tools/list shows the PDP-filtered set.
// ---------------------------------------------------------------------------

function buildServer(allowed) {
  const server = new McpServer({ name: "poc-claims-mcp-gateway", version: "3.0.0" });
  const claimId = z.string().describe("Claim identifier, for example CLAIM-1001");
  const add = (name, def, handler) => {
    if (allowed.includes(name)) server.registerTool(name, def, handler);
  };

  add(
    "list_claims",
    { title: "List claims", description: "Lists the claims this caller may see (filtered per record by the policy decision point).", inputSchema: {} },
    async (_args, extra) => listClaims(extra)
  );
  add(
    "get_claim",
    { title: "Get claim", description: "Returns an insurance claim (region, status, amount, litigation hold).", inputSchema: { claimId } },
    async ({ claimId }, extra) => callTool("get_claim", claimId, "GET", `/claims/${encodeURIComponent(claimId)}`, extra)
  );
  add(
    "get_claim_evidence",
    { title: "Get claim evidence", description: "Lists the evidence files attached to a claim.", inputSchema: { claimId } },
    async ({ claimId }, extra) => callTool("get_claim_evidence", claimId, "GET", `/claims/${encodeURIComponent(claimId)}/evidence`, extra)
  );
  add(
    "analyze_claim",
    { title: "Analyze claim", description: "Runs the claim analysis, stores the findings on the claim and returns them.", inputSchema: { claimId } },
    async ({ claimId }, extra) => callTool("analyze_claim", claimId, "POST", "/claims/analyze", extra, { claimId })
  );
  add(
    "archive_claim",
    { title: "Archive claim", description: "Archives (closes) a claim.", inputSchema: { claimId } },
    async ({ claimId }, extra) => callTool("archive_claim", claimId, "POST", "/claims/archive", extra, { claimId })
  );
  // The SDK only installs the tools handlers once a tool is registered; when the
  // PDP allows nothing, answer tools/list with an empty list instead of "Method not found".
  if (allowed.length === 0) {
    server.server.registerCapabilities({ tools: {} });
    server.server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
  }
  return server;
}

// ---------------------------------------------------------------------------
// HTTP hosting (Streamable HTTP, stateless)
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json({ limit: "1mb" }));

const protectedResourceMetadata = {
  resource: RESOURCE,
  authorization_servers: [ISSUER],
  bearer_methods_supported: ["header"],
  scopes_supported: ["Mcp.Analyze", "Mcp.Archive"],
  resource_name: "POC Claims MCP Server (behind API Management)",
};
app.get("/.well-known/oauth-protected-resource", (_req, res) => res.json(protectedResourceMetadata));
app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => res.json(protectedResourceMetadata));

app.get("/", (_req, res) =>
  res.json({
    name: "poc-claims-mcp-gateway",
    mcpEndpoint: RESOURCE,
    audience: MCP_CLIENT_ID,
    pdp: PDP_URL,
    claimsApi: CLAIMS_API_URL,
    tools: Object.keys(TOOL_ACTIONS),
    note: "Reached through API Management. tools/list is filtered by the PDP; every tools/call is authorized by the PDP before the token exchange.",
  })
);

app.get("/health", (_req, res) => res.json({ ok: true }));

// The gateway's decision travels in x-gateway-decision (base64 JSON). It is only
// trusted when x-gateway-key matches, i.e. the request really came through APIM.
function gatewayInfo(req) {
  const viaGateway = Boolean(GATEWAY_KEY) && req.get("x-gateway-key") === GATEWAY_KEY;
  let decision;
  try {
    const raw = req.get("x-gateway-decision");
    decision = raw ? JSON.parse(Buffer.from(raw, "base64").toString("utf8")) : undefined;
  } catch {
    decision = undefined;
  }
  return { viaGateway, decision: viaGateway ? decision : undefined };
}

app.all("/mcp", bearerAuth, async (req, res) => {
  const payload = req.auth.extra.payload;
  req.auth.extra.gateway = gatewayInfo(req);

  // tools/list is filtered by the PDP; any other request registers every tool
  // (each tools/call is authorized on its own).
  const allowed = req.body?.method === "tools/list" ? await allowedTools(payload) : Object.keys(TOOL_ACTIONS);
  const server = buildServer(allowed);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });

  res.on("close", () => {
    transport.close();
    server.close();
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP request failed:", error);
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
  }
});

app.listen(PORT, () => {
  console.log(`POC Claims MCP server (gateway scenario) listening on :${PORT}, public resource ${RESOURCE}`);
  console.log(`  audience ${MCP_CLIENT_ID} | PDP ${PDP_URL} | Claims API ${CLAIMS_API_URL} | gateway key ${GATEWAY_KEY ? "set" : "not set"}`);
});
