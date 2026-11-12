// MCP server that exposes the POC Claims API as MCP tools and a resource.
//
// It is an OAuth *resource server* in MCP terms AND an OAuth *client* of the
// Claims API. It has its own Entra app registration ("POC Claims MCP Server")
// and never forwards the token it receives:
//
//   1. Validate the inbound token (signature, issuer, tenant, audience = this
//      server, expiry). Anything else is a 401 with a WWW-Authenticate pointer
//      to /.well-known/oauth-protected-resource (RFC 9728).
//   2. Authorize the tool call on the MCP server's OWN permissions
//      (scp Mcp.Analyze / Mcp.Archive, roles Mcp.Analyze.All / Mcp.Archive.All).
//      This is where "agent may analyze but not archive" is enforced now.
//   3. Exchange for a Claims API token with the MCP server's credential:
//        delegated inbound token (scp present) -> on-behalf-of (user stays the subject)
//        app-only inbound token (roles)        -> client credentials as the MCP server
//      The Claims API therefore sees azp = MCP server; the agent identity is
//      visible only here. That is the MCP spec's "no token passthrough" rule.
//
// Config (env, or claims-mcp/config.json with the same keys):
//   PORT (5002), SELF_URL (http://localhost:PORT), CLAIMS_API_URL (http://localhost:5001),
//   TENANT_ID, MCP_CLIENT_ID, MCP_CLIENT_SECRET, CLAIMS_API_APP_ID,
//   CLAIMS_API_SCOPE (default api://<CLAIMS_API_APP_ID>/.default)
//   KNOWN_AGENT_APP_IDS (fallback labelling of agent identities whose tokens lack xms_par_app_azp)

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import express from "express";
import { z } from "zod";
import { createRemoteJWKSet, jwtVerify, decodeJwt } from "jose";
import { ConfidentialClientApplication } from "@azure/msal-node";
import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const here = dirname(fileURLToPath(import.meta.url));
let fileConfig = {};
try {
  fileConfig = JSON.parse(readFileSync(join(here, "config.json"), "utf8"));
} catch {
  /* no config.json: env only */
}
const cfg = (key, fallback) => process.env[key] ?? fileConfig[key] ?? fallback;
const required = (key) => {
  const value = cfg(key);
  if (!value || String(value).startsWith("<")) {
    console.error(`Missing ${key}: set it in claims-mcp/config.json (see config.sample.json) or as an environment variable.`);
    process.exit(1);
  }
  return String(value);
};

const PORT = cfg("PORT", 5002);
const SELF_URL = (cfg("SELF_URL", `http://localhost:${PORT}`)).replace(/\/$/, "");
const CLAIMS_API_URL = (cfg("CLAIMS_API_URL", "http://localhost:5001")).replace(/\/$/, "");
const TENANT_ID = required("TENANT_ID");
const MCP_CLIENT_ID = cfg("MCP_CLIENT_ID", "");
const MCP_CLIENT_SECRET = cfg("MCP_CLIENT_SECRET", "");
const CLAIMS_API_APP_ID = required("CLAIMS_API_APP_ID");
const CLAIMS_API_SCOPE = cfg("CLAIMS_API_SCOPE", `api://${CLAIMS_API_APP_ID}/.default`);
// Same fallback as the mock Claims API: label a caller as an agent when the
// token does not carry xms_par_app_azp (see docs/entra-setup.md 4A step 5).
const KNOWN_AGENT_APP_IDS = String(cfg("KNOWN_AGENT_APP_IDS", ""))
  .split(",")
  .map((x) => x.trim().toLowerCase())
  .filter(Boolean);

const RESOURCE = `${SELF_URL}/mcp`;
const ISSUER = `https://login.microsoftonline.com/${TENANT_ID}/v2.0`;
const JWKS_URL = `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`;
const PRM_URL = `${SELF_URL}/.well-known/oauth-protected-resource`;

// Permissions defined on the MCP server's OWN app registration.
const PERMISSIONS = {
  analyze: { scope: "Mcp.Analyze", role: "Mcp.Analyze.All" },
  archive: { scope: "Mcp.Archive", role: "Mcp.Archive.All" },
};
const SCOPES_SUPPORTED = Object.values(PERMISSIONS).map((p) => p.scope);

if (!MCP_CLIENT_ID || !MCP_CLIENT_SECRET) {
  console.error(
    "MCP_CLIENT_ID and MCP_CLIENT_SECRET are required (run Tests/Configure-McpEntra.ps1, then set env vars or claims-mcp/config.json)."
  );
  process.exit(1);
}

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

// OAuthTokenVerifier for the SDK's requireBearerAuth middleware. Any failure
// must surface as InvalidTokenError so the middleware answers 401 invalid_token
// (anything else becomes a 500).
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
      console.log(`[${new Date().toISOString()}] 401 invalid_token: ${hint}`);
      // The middleware puts this into WWW-Authenticate verbatim: no double quotes.
      throw new InvalidTokenError(hint.replaceAll('"', "'"));
    }
    return {
      token,
      clientId: payload.azp || payload.appid,
      scopes: scopesOf(payload),
      expiresAt: payload.exp,
      // Entra puts the app id (not the URL) in aud; validateInboundToken has
      // already checked it, so the token is for this resource.
      resource: new URL(RESOURCE),
      extra: { payload },
    };
  },
};

const bearerAuth = requireBearerAuth({
  verifier: tokenVerifier,
  resourceMetadataUrl: PRM_URL,
  expectedResource: new URL(RESOURCE),
});

function rolesOf(payload) {
  return Array.isArray(payload.roles) ? payload.roles : [];
}
function scopesOf(payload) {
  return typeof payload.scp === "string" ? payload.scp.split(" ").filter(Boolean) : [];
}

function summarizeInbound(payload) {
  const isDelegated = scopesOf(payload).length > 0;
  const callerAppId = payload.azp || payload.appid;
  const byClaim = Boolean(payload.xms_par_app_azp) || payload.xms_act_fct === "11";
  const byList = typeof callerAppId === "string" && KNOWN_AGENT_APP_IDS.includes(callerAppId.toLowerCase());
  const isAgent = byClaim || byList;
  return {
    audience: payload.aud,
    callerKind: isAgent
      ? isDelegated ? "user via agent-identity (delegated)" : "agent-identity (app-only)"
      : isDelegated ? "user via host-application (delegated)" : "host-application (app-only)",
    agentDetectedBy: payload.xms_par_app_azp
      ? "xms_par_app_azp claim"
      : payload.xms_act_fct === "11"
        ? "xms_act_fct claim"
        : byList
          ? "KNOWN_AGENT_APP_IDS fallback (token has no xms_par_app_azp claim)"
          : undefined,
    tokenType: isDelegated ? "DELEGATED (scp claim)" : "APP-ONLY (roles claim)",
    callerAppId,
    objectId: payload.oid,
    userName: payload.preferred_username || payload.upn,
    roles: payload.roles,
    scp: payload.scp,
    parentBlueprintAppId: payload.xms_par_app_azp,
    actorFacets: payload.xms_act_fct,
    subjectFacets: payload.xms_sub_fct,
    expires: payload.exp ? new Date(payload.exp * 1000).toISOString() : undefined,
  };
}

// ---------------------------------------------------------------------------
// 2. Authorization on the MCP server's own permissions
// ---------------------------------------------------------------------------

function hasPermission(payload, permission) {
  if (!permission) return true;
  const roles = rolesOf(payload).map((r) => r.toLowerCase());
  const scopes = scopesOf(payload).map((s) => s.toLowerCase());
  return roles.includes(permission.role.toLowerCase()) || scopes.includes(permission.scope.toLowerCase());
}

// ---------------------------------------------------------------------------
// 3. Token exchange: the MCP server's own credential gets the Claims API token
// ---------------------------------------------------------------------------

const confidentialClient = new ConfidentialClientApplication({
  auth: {
    clientId: MCP_CLIENT_ID,
    clientSecret: MCP_CLIENT_SECRET,
    authority: `https://login.microsoftonline.com/${TENANT_ID}`,
  },
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
      outboundToken: {
        aud: outbound.aud,
        azp: outbound.azp || outbound.appid,
        oid: outbound.oid,
        roles: outbound.roles,
        scp: outbound.scp,
        userName: outbound.preferred_username || outbound.upn,
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Tool execution = authorize here, exchange, call the Claims API
// ---------------------------------------------------------------------------

function inboundOf(extra) {
  // StreamableHTTPServerTransport copies req.auth into extra.authInfo.
  const auth = extra?.authInfo;
  if (auth?.extra?.payload) return { token: auth.token, payload: auth.extra.payload };
  throw new Error("no validated token on the request");
}

function toolResult(payload) {
  return {
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
    isError: payload.httpStatus >= 400,
  };
}

async function callClaimsApi(toolName, permission, method, path, extra, body) {
  const { token, payload } = inboundOf(extra);
  const mcpServerSaw = summarizeInbound(payload);
  const stamp = () => new Date().toISOString();

  if (!hasPermission(payload, permission)) {
    const required = [permission.scope, permission.role];
    console.log(
      `[${stamp()}] tools/call ${toolName} => DENY 403 at MCP server (requires ${required.join(" or ")}) ` +
        `| caller ${mcpServerSaw.callerKind} azp=${mcpServerSaw.callerAppId ?? "-"} oid=${mcpServerSaw.objectId ?? "-"}`
    );
    return toolResult({
      httpStatus: 403,
      decidedBy: "mcp-server",
      mcpServer: { saw: mcpServerSaw, required, decision: "DENY" },
      body: { error: "forbidden", required, roles: payload.roles, scp: payload.scp },
    });
  }

  let exchanged;
  try {
    exchanged = await acquireClaimsApiToken(token, payload);
  } catch (error) {
    console.error(`[${stamp()}] tools/call ${toolName} => token exchange failed: ${error.message}`);
    return toolResult({
      httpStatus: 502,
      decidedBy: "mcp-server",
      mcpServer: { saw: mcpServerSaw, required: permission ? [permission.scope, permission.role] : [], decision: "ALLOW" },
      body: { error: "token exchange failed", stage: "token-exchange", detail: error.message },
    });
  }

  const response = await fetch(`${CLAIMS_API_URL}${path}`, {
    method,
    headers: { "content-type": "application/json", authorization: `Bearer ${exchanged.accessToken}` },
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = text;
  }

  console.log(
    `[${stamp()}] tools/call ${toolName} -> ${method} ${path} => ${response.status} ` +
      `| inbound ${mcpServerSaw.callerKind} azp=${mcpServerSaw.callerAppId ?? "-"} oid=${mcpServerSaw.objectId ?? "-"}` +
      ` | outbound ${exchanged.exchange.grant} azp=${exchanged.exchange.outboundToken.azp} oid=${exchanged.exchange.outboundToken.oid ?? "-"}`
  );

  return toolResult({
    httpStatus: response.status,
    decidedBy: "claims-api",
    mcpServer: { saw: mcpServerSaw, required: permission ? [permission.scope, permission.role] : [], decision: "ALLOW" },
    exchange: exchanged.exchange,
    body: parsed,
  });
}

// ---------------------------------------------------------------------------
// MCP server definition (one instance per request: stateless mode)
// ---------------------------------------------------------------------------

function buildServer() {
  const server = new McpServer({ name: "poc-claims-mcp", version: "2.0.0" });
  const claimId = z.string().describe("Claim identifier, for example CLAIM-1001");

  server.registerTool(
    "get_claim",
    {
      title: "Get claim",
      description: "Returns the summary of an insurance claim (status, amount). Needs any valid token for this MCP server.",
      inputSchema: { claimId },
    },
    async ({ claimId }, extra) => callClaimsApi("get_claim", null, "GET", `/claims/${encodeURIComponent(claimId)}`, extra)
  );

  server.registerTool(
    "get_claim_evidence",
    {
      title: "Get claim evidence",
      description: "Lists the evidence files attached to a claim. Requires Mcp.Analyze (delegated) or Mcp.Analyze.All (application).",
      inputSchema: { claimId },
    },
    async ({ claimId }, extra) =>
      callClaimsApi("get_claim_evidence", PERMISSIONS.analyze, "GET", `/claims/${encodeURIComponent(claimId)}/evidence`, extra)
  );

  server.registerTool(
    "analyze_claim",
    {
      title: "Analyze claim",
      description: "Runs the claim analysis and returns findings. Requires Mcp.Analyze (delegated) or Mcp.Analyze.All (application).",
      inputSchema: { claimId },
    },
    async ({ claimId }, extra) =>
      callClaimsApi("analyze_claim", PERMISSIONS.analyze, "POST", "/claims/analyze", extra, { claimId, operation: "analyze", via: "mcp" })
  );

  server.registerTool(
    "archive_claim",
    {
      title: "Archive claim",
      description: "Archives (closes) a claim. Requires Mcp.Archive (delegated) or Mcp.Archive.All (application).",
      inputSchema: { claimId },
    },
    async ({ claimId }, extra) =>
      callClaimsApi("archive_claim", PERMISSIONS.archive, "POST", "/claims/archive", extra, { claimId, operation: "archive", via: "mcp" })
  );

  server.registerResource(
    "claim",
    new ResourceTemplate("claims://{claimId}", { list: undefined }),
    {
      title: "Claim record",
      description: "The claim record as an MCP resource (same authorization as get_claim).",
      mimeType: "application/json",
    },
    async (uri, { claimId }, extra) => {
      const result = await callClaimsApi("resource:claim", null, "GET", `/claims/${encodeURIComponent(claimId)}`, extra);
      return { contents: [{ uri: uri.href, mimeType: "application/json", text: result.content[0].text }] };
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// HTTP hosting (Streamable HTTP, stateless)
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json({ limit: "1mb" }));

// MCP authorization spec: protected resource metadata (RFC 9728).
const protectedResourceMetadata = {
  resource: RESOURCE,
  authorization_servers: [ISSUER],
  bearer_methods_supported: ["header"],
  scopes_supported: SCOPES_SUPPORTED,
  resource_name: "POC Claims MCP Server",
  resource_documentation: `${SELF_URL}/`,
};
app.get("/.well-known/oauth-protected-resource", (_req, res) => res.json(protectedResourceMetadata));
app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => res.json(protectedResourceMetadata));

app.get("/", (_req, res) => {
  res.json({
    name: "poc-claims-mcp",
    mcpEndpoint: RESOURCE,
    audience: MCP_CLIENT_ID,
    authorizationServer: ISSUER,
    protectedResourceMetadata: PRM_URL,
    permissions: PERMISSIONS,
    exchangesTo: { claimsApi: CLAIMS_API_URL, scope: CLAIMS_API_SCOPE },
    tools: ["get_claim", "get_claim_evidence", "analyze_claim", "archive_claim"],
    resources: ["claims://{claimId}"],
    note: "Send Authorization: Bearer <token whose audience is this MCP server>. The token is validated here and never forwarded; the Claims API receives a token minted for the MCP server (OBO for delegated, client credentials for app-only).",
  });
});

// requireBearerAuth validates the token and sets req.auth, which the transport
// hands to tool handlers as extra.authInfo. Missing/invalid tokens get a 401
// whose WWW-Authenticate points at the protected resource metadata.
app.all("/mcp", bearerAuth, async (req, res) => {
  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined, // stateless: no session ids
    enableJsonResponse: true,
  });

  res.on("close", () => {
    transport.close();
    server.close();
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP request failed:", error);
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
    }
  }
});

app.listen(PORT, () => {
  console.log(`POC Claims MCP server listening on ${RESOURCE}`);
  console.log(`Audience (this server): ${MCP_CLIENT_ID} | issuer ${ISSUER}`);
  console.log(`Protected resource metadata: ${PRM_URL}`);
  console.log(`Exchanges inbound tokens for ${CLAIMS_API_SCOPE} and calls ${CLAIMS_API_URL}`);
  console.log("Tools: get_claim, get_claim_evidence, analyze_claim, archive_claim | Resource: claims://{claimId}");
});
