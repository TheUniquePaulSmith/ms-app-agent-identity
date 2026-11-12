// Debug stand-in for the downstream "POC Claims API".
//
// It VALIDATES the bearer token as a real resource server would (`jose`, the
// same library the MCP server uses):
//   - signature against the tenant's published signing keys (JWKS, cached and
//     refreshed by jose when an unknown `kid` arrives),
//   - issuer  = https://login.microsoftonline.com/<tenant>/v2.0 (v2 tokens),
//   - tid     = the configured tenant,
//   - aud     = this API's client id, or api://<client id>,
//   - exp / nbf with a small clock-skew tolerance,
//   - alg     = RS256 only.
// Only then does it enforce the permission each route needs, so the demo can
// show both ALLOW and DENY decisions and exactly which identity the API saw.
// When validation fails the response and console still include the DECODED
// (untrusted) payload so the demo shows what was presented and why it failed.
//
// Permissions defined on the Claims API app registration:
//   delegated scopes (scp claim) : Claims.Archive, Claims.Analyze
//   app roles      (roles claim) : Claims.Archive.All, Claims.Analyze.All
//
// Settings come from environment variables, else from config.json next to this
// file (git-ignored; copy config.sample.json):
//      TENANT_ID, CLAIMS_API_APP_ID (required), PORT (default 5001),
//      KNOWN_AGENT_APP_IDS, KNOWN_MCP_APP_IDS (app ids of MCP servers,
//      labelled as intermediaries), CLOCK_TOLERANCE_SECONDS (default 60).

import http from "node:http";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRemoteJWKSet, jwtVerify, decodeJwt, decodeProtectedHeader, errors as joseErrors } from "jose";

let fileConfig = {};
try {
  fileConfig = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "config.json"), "utf8"));
} catch {
  /* no config.json: env only */
}
const cfg = (key, fallback) => process.env[key] || fileConfig[key] || fallback;
const required = (key) => {
  const value = cfg(key);
  if (!value || String(value).startsWith("<")) {
    console.error(`Missing ${key}: set it in claims-api/config.json (see config.sample.json) or as an environment variable.`);
    process.exit(1);
  }
  return String(value);
};

const PORT = cfg("PORT", 5001);
const TENANT_ID = required("TENANT_ID");
const CLAIMS_API_APP_ID = required("CLAIMS_API_APP_ID");
const EXPECTED_AUDIENCES = [CLAIMS_API_APP_ID, `api://${CLAIMS_API_APP_ID}`];
const CLOCK_TOLERANCE_SECONDS = Number(cfg("CLOCK_TOLERANCE_SECONDS", 60));

// v2.0 issuer. v1 tokens (iss https://sts.windows.net/<tenant>/) are rejected
// on purpose: docs/entra-setup.md 4A step 3 sets accessTokenAcceptedVersion = 2 on the
// registration so that `azp` (not `appid`) and the agent claims are emitted.
const ISSUER = `https://login.microsoftonline.com/${TENANT_ID}/v2.0`;
const V1_ISSUER = `https://sts.windows.net/${TENANT_ID}/`;
const JWKS_URL = `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`;

// Fallback only: app (client) ids of agent identities, used to label a caller
// as an agent when the token does NOT carry xms_par_app_azp (for example
// before the Claims API registration is configured to emit it). The proper
// signal is the claim; the list exists so the demo still reads correctly.
const KNOWN_AGENT_APP_IDS = String(cfg("KNOWN_AGENT_APP_IDS", ""))
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// App (client) ids of MCP servers that front this API. They call with their
// OWN identity (client credentials or on-behalf-of), never with a forwarded
// token, so the API sees them as the actor (azp) and labels them as such.
const KNOWN_MCP_APP_IDS = String(cfg("KNOWN_MCP_APP_IDS", ""))
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

const PERMISSIONS = {
  archive: { scope: "Claims.Archive", role: "Claims.Archive.All" },
  analyze: { scope: "Claims.Analyze", role: "Claims.Analyze.All" },
};

// ---------------------------------------------------------------------------
// Token validation
// ---------------------------------------------------------------------------

// Fetches the tenant's signing keys on first use, caches them, and re-fetches
// (rate limited) when a token arrives with a `kid` it has not seen, which is
// how Entra key rollover is handled.
const jwks = createRemoteJWKSet(new URL(JWKS_URL), {
  cooldownDuration: 30_000,
  cacheMaxAge: 10 * 60_000,
});

// Untrusted decode, for logging and error responses only. Never authorize on it.
function decodeUntrusted(token) {
  try {
    return { header: decodeProtectedHeader(token), payload: decodeJwt(token) };
  } catch {
    return null;
  }
}

// Returns { payload } on success or { error, detail } on failure. `error` is
// the short OAuth-style reason, `detail` is the human explanation for the demo.
async function validateToken(token) {
  try {
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer: ISSUER,
      audience: EXPECTED_AUDIENCES,
      algorithms: ["RS256"],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      requiredClaims: ["exp", "iat", "tid", "sub"],
    });
    if (payload.tid !== TENANT_ID) {
      return {
        error: "tenant mismatch",
        detail: `token tid '${payload.tid}' is not the configured tenant '${TENANT_ID}'`,
      };
    }
    return { payload, header: protectedHeader };
  } catch (err) {
    return { error: classifyError(err), detail: describeError(err, token) };
  }
}

function classifyError(err) {
  if (err instanceof joseErrors.JWTExpired) return "token expired";
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    if (err.claim === "aud") return "audience mismatch";
    if (err.claim === "iss") return "issuer mismatch";
    if (err.claim === "nbf") return "token not yet valid";
    return `invalid claim '${err.claim}'`;
  }
  if (err instanceof joseErrors.JWSSignatureVerificationFailed) return "invalid signature";
  if (err instanceof joseErrors.JWKSNoMatchingKey) return "unknown signing key";
  if (err instanceof joseErrors.JOSEAlgNotAllowed) return "algorithm not allowed";
  if (err instanceof joseErrors.JWSInvalid || err instanceof joseErrors.JWTInvalid) return "malformed token";
  if (err instanceof joseErrors.JWKSTimeout) return "signing keys unavailable";
  return "token validation failed";
}

function describeError(err, token) {
  const untrusted = decodeUntrusted(token);
  const payload = untrusted?.payload || {};
  if (err instanceof joseErrors.JWTClaimValidationFailed && err.claim === "iss") {
    if (payload.iss === V1_ISSUER) {
      return (
        `token is a v1 token (iss ${payload.iss}); this API accepts v2 tokens only. ` +
        "Set accessTokenAcceptedVersion = 2 on the Claims API registration (docs/entra-setup.md 4A step 3)."
      );
    }
    return `issuer '${payload.iss}' is not '${ISSUER}' (wrong tenant or cloud)`;
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed && err.claim === "aud") {
    return `audience '${payload.aud}' is not one of ${EXPECTED_AUDIENCES.join(" | ")} (token was minted for another resource)`;
  }
  if (err instanceof joseErrors.JWTExpired) {
    return `token expired at ${new Date(payload.exp * 1000).toISOString()}`;
  }
  if (err instanceof joseErrors.JWKSNoMatchingKey) {
    return `no key with kid '${untrusted?.header?.kid}' in ${JWKS_URL}; token was not signed by this tenant`;
  }
  return err?.message || String(err);
}

function rolesOf(payload) {
  return Array.isArray(payload.roles) ? payload.roles : [];
}

function scopesOf(payload) {
  return typeof payload.scp === "string"
    ? payload.scp.split(" ").filter(Boolean)
    : [];
}

function summarize(payload) {
  const roles = rolesOf(payload);
  const scopes = scopesOf(payload);
  const callerAppId = payload.azp || payload.appid;
  const hasParentClaim =
    typeof payload.xms_par_app_azp === "string" && payload.xms_par_app_azp.length > 0;
  const isKnownAgent =
    typeof callerAppId === "string" && KNOWN_AGENT_APP_IDS.includes(callerAppId.toLowerCase());
  const isAgent = hasParentClaim || isKnownAgent;
  const isMcpServer =
    typeof callerAppId === "string" && KNOWN_MCP_APP_IDS.includes(callerAppId.toLowerCase());
  const agentDetectedBy = hasParentClaim
    ? "xms_par_app_azp claim"
    : isKnownAgent
      ? "KNOWN_AGENT_APP_IDS fallback (token has no xms_par_app_azp claim)"
      : undefined;
  const isDelegated = scopes.length > 0;
  // Entra guidance: an app-only token has oid == sub (no user).
  const looksAppOnly = payload.oid && payload.sub && payload.oid === payload.sub;

  let tokenType = "unknown";
  if (isDelegated) tokenType = "DELEGATED (scp claim)";
  else if (roles.length > 0) tokenType = "APP-ONLY (roles claim)";
  else if (looksAppOnly) tokenType = "APP-ONLY (no roles claim: no application permission granted yet)";

  const callerKind = isMcpServer
    ? isDelegated
      ? "user via mcp-server (delegated, on-behalf-of)"
      : "mcp-server (app-only, client credentials)"
    : isAgent
      ? isDelegated
        ? "user via agent-identity (delegated)"
        : "agent-identity (app-only)"
      : isDelegated
        ? "user via host-application (delegated)"
        : "host-application (app-only)";

  const iso = (seconds) =>
    typeof seconds === "number" ? new Date(seconds * 1000).toISOString() : undefined;

  return {
    callerKind,
    agentDetectedBy,
    viaIntermediary: isMcpServer ? "mcp-server" : undefined,
    tokenType,
    tokenVersion: payload.ver,
    issuer: payload.iss,
    audience: payload.aud,
    tenantId: payload.tid,
    callerAppId,
    objectId: payload.oid,
    subject: payload.sub,
    idtyp: payload.idtyp,
    // Token id: matches uniqueTokenIdentifier on the Entra sign-in log entry
    // that issued this token, which is how a call here is traced back to
    // the agent identity sign-in and from there to the blueprint sign-in.
    uti: payload.uti,
    parentBlueprintAppId: payload.xms_par_app_azp,
    actorFacets: payload.xms_act_fct,
    subjectFacets: payload.xms_sub_fct,
    userName: payload.preferred_username || payload.name || payload.upn,
    roles: payload.roles,
    scp: payload.scp,
    issuedAt: iso(payload.iat),
    expires: iso(payload.exp),
  };
}

function hasPermission(payload, permission) {
  const roles = rolesOf(payload).map((r) => r.toLowerCase());
  const scopes = scopesOf(payload).map((s) => s.toLowerCase());
  return (
    roles.includes(permission.role.toLowerCase()) ||
    scopes.includes(permission.scope.toLowerCase())
  );
}

// ---------------------------------------------------------------------------
// Routes (matched with or without a leading /api)
// ---------------------------------------------------------------------------

function matchRoute(method, path) {
  const evidence = path.match(/^\/claims\/([^/]+)\/evidence$/);
  const claim = path.match(/^\/claims\/([^/]+)$/);

  if (method === "POST" && path === "/claims/archive") {
    return {
      name: "POST /claims/archive",
      permission: PERMISSIONS.archive,
      handle: (body) => ({ result: "archived (debug stub)", received: body }),
    };
  }
  if (method === "POST" && path === "/claims/analyze") {
    return {
      name: "POST /claims/analyze",
      permission: PERMISSIONS.analyze,
      handle: (body) => ({
        result: "analyzed (debug stub)",
        received: body,
        findings: ["water damage consistent with claim", "no fraud indicators"],
      }),
    };
  }
  if (method === "GET" && evidence) {
    return {
      name: "GET /claims/:id/evidence",
      permission: PERMISSIONS.analyze,
      handle: () => ({
        claimId: evidence[1],
        evidence: ["photo-001.jpg", "adjuster-notes.pdf"],
      }),
    };
  }
  if (method === "GET" && claim) {
    return {
      name: "GET /claims/:id",
      permission: null,
      handle: () => ({ claimId: claim[1], status: "open", amount: 1250 }),
    };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
  });
}

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function send(res, status, payload, extraHeaders = {}) {
  res.writeHead(status, { "Content-Type": "application/json", ...extraHeaders });
  res.end(JSON.stringify(payload, null, 2));
}

const server = http.createServer(async (req, res) => {
  const rawBody = await readBody(req);
  const body = rawBody ? safeJson(rawBody) : undefined;
  const stamp = new Date().toISOString();

  console.log("\n" + "=".repeat(72));
  console.log(`[${stamp}] ${req.method} ${req.url}`);
  console.log("-".repeat(72));

  const headers = { ...req.headers };
  if (headers.authorization) {
    headers.authorization = headers.authorization.slice(0, 25) + "...(truncated)";
  }
  console.log("Headers:", JSON.stringify(headers, null, 2));
  if (body !== undefined) console.log("Body:", JSON.stringify(body, null, 2));

  const path = req.url.split("?")[0].replace(/^\/api(?=\/|$)/, "");
  const route = matchRoute(req.method, path);

  // 1. Bearer token present?
  const auth = req.headers.authorization || "";
  const token = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";

  if (!token) {
    console.log("Auth: NO bearer token");
    console.log("Decision: DENY 401 (missing bearer token)");
    console.log("=".repeat(72));
    return send(res, 401, { error: "missing bearer token" }, { "WWW-Authenticate": "Bearer" });
  }

  // 2. Token valid: signature (tenant JWKS), issuer, tenant, audience, expiry?
  const verified = await validateToken(token);

  if (verified.error) {
    const untrusted = decodeUntrusted(token);
    console.log(`Auth: INVALID token (${verified.error}): ${verified.detail}`);
    if (untrusted) {
      console.log("Untrusted header :", JSON.stringify(untrusted.header));
      console.log("Untrusted payload:", JSON.stringify(untrusted.payload, null, 2));
    }
    console.log(`Decision: DENY 401 (${verified.error})`);
    console.log("=".repeat(72));
    return send(
      res,
      401,
      {
        error: verified.error,
        detail: verified.detail,
        expected: { issuer: ISSUER, tenantId: TENANT_ID, audience: EXPECTED_AUDIENCES },
        _debug: untrusted ? { untrustedTokenInfo: summarize(untrusted.payload) } : undefined,
      },
      { "WWW-Authenticate": `Bearer error="invalid_token", error_description="${verified.error}"` }
    );
  }

  const decoded = { header: verified.header, payload: verified.payload };
  const tokenInfo = summarize(decoded.payload);
  console.log("Auth: token VALID (signature, issuer, tenant, audience, expiry)");
  // One greppable line per request for joining with Entra sign-in logs.
  console.log(
    `Correlation: uti=${tokenInfo.uti || "(none)"} caller=${tokenInfo.callerAppId}` +
      (tokenInfo.parentBlueprintAppId ? ` parentBlueprint=${tokenInfo.parentBlueprintAppId}` : "")
  );
  console.log("Token header:", JSON.stringify(decoded.header));
  console.log("Token summary:", JSON.stringify(tokenInfo, null, 2));
  console.log("Full payload:", JSON.stringify(decoded.payload, null, 2));

  // 3. Route exists?
  if (!route) {
    console.log("Decision: 404 (no debug route for this path)");
    console.log("=".repeat(72));
    return send(res, 404, {
      error: "No debug route for this path",
      method: req.method,
      path: req.url,
      _debug: { tokenInfo },
    });
  }

  // 4. Permission present (either the delegated scope or the app role)?
  if (route.permission && !hasPermission(decoded.payload, route.permission)) {
    const required = [route.permission.scope, route.permission.role];
    console.log(
      `Decision: DENY 403 (${route.name} requires ${required.join(" or ")}; ` +
        `caller is ${tokenInfo.callerKind})`
    );
    console.log("=".repeat(72));
    return send(res, 403, {
      error: "forbidden",
      required,
      roles: decoded.payload.roles,
      scp: decoded.payload.scp,
      _debug: { tokenInfo },
    });
  }

  console.log(
    `Decision: ALLOW 200 (${route.name}` +
      (route.permission
        ? `, satisfied by ${route.permission.scope} or ${route.permission.role}`
        : ", any valid token") +
      `; caller is ${tokenInfo.callerKind})`
  );
  console.log("=".repeat(72));
  return send(res, 200, { ...route.handle(body), _debug: { tokenInfo } });
});

server.listen(PORT, () => {
  console.log(`Debug Claims API listening on http://localhost:${PORT}`);
  console.log("Token validation (jose):");
  console.log(`  issuer    : ${ISSUER}`);
  console.log(`  tenant    : ${TENANT_ID}`);
  console.log(`  audience  : ${EXPECTED_AUDIENCES.join(" or ")}`);
  console.log(`  keys      : ${JWKS_URL}`);
  console.log(`  alg RS256, exp/nbf with ${CLOCK_TOLERANCE_SECONDS}s tolerance`);
  console.log("Routes (also under /api):");
  console.log("  POST /claims/archive         requires Claims.Archive (scp) or Claims.Archive.All (roles)");
  console.log("  POST /claims/analyze         requires Claims.Analyze (scp) or Claims.Analyze.All (roles)");
  console.log("  GET  /claims/:id/evidence    requires Claims.Analyze (scp) or Claims.Analyze.All (roles)");
  console.log("  GET  /claims/:id             any valid token for this audience");
  console.log(`Known agent app ids (fallback labelling): ${KNOWN_AGENT_APP_IDS.join(", ") || "(none)"}`);
  console.log(`Known MCP server app ids (intermediary labelling): ${KNOWN_MCP_APP_IDS.join(", ") || "(none)"}`);
});
