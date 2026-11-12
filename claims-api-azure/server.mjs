// Hosted "POC Claims API" for the gateway scenario (Proposal PEP 3).
//
// Same Entra resource as the local mock (claims-api/, same app id), but:
//   - claim records live in an Azure Storage table ("Claims"), seeded with
//     seed-claims.json on first start and by POST /admin/reset;
//   - after JWT validation (jose, as before) every claim route loads the record
//     and asks the PDP (AuthZEN) with the record's attributes as
//     resource.properties. The Entra roles/scp string match is gone: Entra
//     decides whether a token exists, the PDP decides whether it may be used here;
//   - analyze and archive CHANGE the record, so a later PDP decision sees the
//     effect (archive twice -> no-archive-twice, analyze archived -> denied).
//
// Option A of Proposal 5.8: after the MCP server's token exchange the caller
// (azp) is the MCP server, so the PDP is asked about subject = MCP server and
// context.onBehalfOf = the user (oid) for delegated tokens.
//
// Env: PORT (5021 locally), TENANT_ID, CLAIMS_API_APP_ID, PDP_URL, POC_INTERNAL_KEY,
//      STORAGE_TABLE_ENDPOINT, CLAIMS_TABLE (Claims), KNOWN_MCP_APP_IDS,
//      CLOCK_TOLERANCE_SECONDS (60)

import { readFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { createRemoteJWKSet, jwtVerify, decodeJwt, errors as joseErrors } from "jose";
import { TableClient } from "@azure/data-tables";
import { DefaultAzureCredential } from "@azure/identity";

const here = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 5021;
// Local runs can reuse the local Claims API's git-ignored config.json for the ids.
const readConfig = (path) => {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return {};
  }
};
const fileConfig = { ...readConfig(join(here, "..", "claims-api", "config.json")), ...readConfig(join(here, "config.json")) };
const required = (key) => {
  const value = process.env[key] || fileConfig[key];
  if (!value || String(value).startsWith("<")) {
    console.error(`Missing ${key}: set it as an environment variable (App Service settings in main.bicep) or in claims-api/config.json.`);
    process.exit(1);
  }
  return value;
};
const TENANT_ID = required("TENANT_ID");
const CLAIMS_API_APP_ID = required("CLAIMS_API_APP_ID");
const PDP_URL = (process.env.PDP_URL || "http://localhost:5010").replace(/\/$/, "");
const INTERNAL_KEY = process.env.POC_INTERNAL_KEY || "";
const TABLE_ENDPOINT = process.env.STORAGE_TABLE_ENDPOINT || "";
const CLAIMS_TABLE = process.env.CLAIMS_TABLE || "Claims";
const CLOCK_TOLERANCE_SECONDS = Number(process.env.CLOCK_TOLERANCE_SECONDS || 60);
const KNOWN_MCP_APP_IDS = String(process.env.KNOWN_MCP_APP_IDS || fileConfig.KNOWN_MCP_APP_IDS || "")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);

const ISSUER = `https://login.microsoftonline.com/${TENANT_ID}/v2.0`;
const JWKS_URL = `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`;
const AUDIENCES = [CLAIMS_API_APP_ID, `api://${CLAIMS_API_APP_ID}`];
const SEED = JSON.parse(readFileSync(join(here, "seed-claims.json"), "utf8"));
const stamp = () => new Date().toISOString();

// ---------------------------------------------------------------------------
// Storage: Azure Table (managed identity) or in-memory for local runs
// ---------------------------------------------------------------------------

const table = TABLE_ENDPOINT ? new TableClient(TABLE_ENDPOINT, CLAIMS_TABLE, new DefaultAzureCredential()) : null;
const memory = new Map();

const toEntity = (c) => ({ partitionKey: "claims", rowKey: c.claimId, ...c, findings: c.findings ? JSON.stringify(c.findings) : "" });
const fromEntity = (e) => {
  const { partitionKey, rowKey, etag, timestamp, "odata.etag": _o, ...rest } = e;
  let findings = [];
  try {
    findings = rest.findings ? JSON.parse(rest.findings) : [];
  } catch {
    /* keep empty */
  }
  return { ...rest, claimId: rowKey, findings, etag };
};

const repo = {
  async list() {
    if (!table) return [...memory.values()];
    const rows = [];
    for await (const e of table.listEntities({ queryOptions: { filter: "PartitionKey eq 'claims'" } })) rows.push(fromEntity(e));
    return rows.sort((a, b) => a.claimId.localeCompare(b.claimId));
  },
  async get(id) {
    if (!table) return memory.get(id) || null;
    try {
      return fromEntity(await table.getEntity("claims", id));
    } catch (error) {
      if (error.statusCode === 404) return null;
      throw error;
    }
  },
  async update(record) {
    const { etag, ...data } = record;
    if (!table) {
      memory.set(record.claimId, data);
      return;
    }
    // Optimistic concurrency: fails if someone changed the record since we read it.
    await table.updateEntity(toEntity(data), "Replace", { etag });
  },
  async reset() {
    if (!table) {
      memory.clear();
      for (const c of SEED) memory.set(c.claimId, { ...c, findings: [] });
      return SEED.length;
    }
    for await (const e of table.listEntities({ queryOptions: { filter: "PartitionKey eq 'claims'" } })) {
      await table.deleteEntity(e.partitionKey, e.rowKey);
    }
    for (const c of SEED) await table.upsertEntity(toEntity({ ...c, findings: [] }), "Replace");
    return SEED.length;
  },
  async seedIfEmpty() {
    if (table) {
      await table.createTable().catch((e) => {
        if (e.statusCode !== 409) throw e;
      });
    }
    const existing = await this.list();
    if (existing.length === 0) {
      const n = await this.reset();
      console.log(`Seeded ${n} sample claims`);
    }
  },
};

// ---------------------------------------------------------------------------
// Token validation (same rules as claims-api/server.js)
// ---------------------------------------------------------------------------

const jwks = createRemoteJWKSet(new URL(JWKS_URL), { cooldownDuration: 30_000, cacheMaxAge: 10 * 60_000 });

async function validateToken(token) {
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: ISSUER,
      audience: AUDIENCES,
      algorithms: ["RS256"],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      requiredClaims: ["exp", "iat", "tid", "sub"],
    });
    if (payload.tid !== TENANT_ID) return { error: "tenant mismatch" };
    return { payload };
  } catch (err) {
    let detail = err.message;
    try {
      const raw = decodeJwt(token);
      detail += ` (aud=${raw.aud}, iss=${raw.iss})`;
    } catch {
      /* not a JWT */
    }
    return { error: err instanceof joseErrors.JWTExpired ? "token expired" : "invalid token", detail };
  }
}

const rolesOf = (p) => (Array.isArray(p.roles) ? p.roles : []);
const scopesOf = (p) => (typeof p.scp === "string" ? p.scp.split(" ").filter(Boolean) : []);

function summarize(p) {
  const callerAppId = p.azp || p.appid;
  const delegated = scopesOf(p).length > 0;
  const isMcp = KNOWN_MCP_APP_IDS.includes(String(callerAppId).toLowerCase());
  const isAgent = Boolean(p.xms_par_app_azp);
  return {
    callerKind: isMcp
      ? delegated ? "user via mcp-server (delegated, on-behalf-of)" : "mcp-server (app-only, client credentials)"
      : isAgent
        ? delegated ? "user via agent-identity (delegated)" : "agent-identity (app-only)"
        : delegated ? "user via host-application (delegated)" : "host-application (app-only)",
    viaIntermediary: isMcp ? "mcp-server" : undefined,
    tokenType: delegated ? "DELEGATED (scp claim)" : "APP-ONLY (roles claim)",
    audience: p.aud,
    callerAppId,
    objectId: p.oid,
    userName: p.preferred_username || p.upn,
    roles: p.roles,
    scp: p.scp,
    parentBlueprintAppId: p.xms_par_app_azp,
    uti: p.uti,
    expires: p.exp ? new Date(p.exp * 1000).toISOString() : undefined,
  };
}

// ---------------------------------------------------------------------------
// PEP 3: AuthZEN call to the PDP (fail closed)
// ---------------------------------------------------------------------------

async function authorize(payload, actionName, record) {
  const delegated = scopesOf(payload).length > 0;
  const request = {
    subject: {
      type: payload.xms_par_app_azp ? "agent" : "application",
      id: payload.azp || payload.appid,
      properties: {
        blueprint: payload.xms_par_app_azp,
        permissions: delegated ? scopesOf(payload) : rolesOf(payload),
        tenant: payload.tid,
      },
    },
    action: { name: actionName },
    resource: {
      type: "claim",
      id: record.claimId,
      properties: { region: record.region, status: record.status, amount: record.amount, litigationHold: record.litigationHold },
    },
    context: {
      pep: "claims-api",
      onBehalfOf: delegated ? payload.oid : undefined,
      onBehalfOfUpn: delegated ? payload.preferred_username || payload.upn : undefined,
      time: stamp(),
    },
  };
  try {
    const response = await fetch(`${PDP_URL}/access/v1/evaluation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-pdp-key": INTERNAL_KEY, "x-request-id": randomUUID() },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(`PDP HTTP ${response.status}`);
    const result = await response.json();
    return { reachable: true, request, ...result };
  } catch (error) {
    return {
      reachable: false,
      request,
      decision: false,
      context: { reason_admin: { en: `PDP unavailable: ${error.message}; failing closed` }, reason_user: { en: "Authorization is temporarily unavailable." }, policyIds: ["fail-closed-pdp"] },
    };
  }
}

const authzenSummary = (a) => ({
  request: a.request,
  decision: a.decision,
  policyIds: a.context?.policyIds,
  policyVersion: a.context?.policyVersion,
  reason_admin: a.context?.reason_admin?.en,
  reason_user: a.context?.reason_user?.en,
  user: a.context?.user,
  killList: a.context?.killList,
});

// ---------------------------------------------------------------------------
// Business logic (deterministic stand-ins that change the record)
// ---------------------------------------------------------------------------

function analyze(record) {
  const h = createHash("sha256").update(record.claimId).digest();
  const riskScore = Math.min(99, Math.round((h[0] / 255) * 40 + Math.min(record.amount / 1000, 50)));
  const findings = [
    `${record.description}: damage pattern consistent with the claim`,
    riskScore > 60 ? "elevated risk: refer to a senior adjuster" : "no fraud indicators",
    `estimated settlement ${Math.round(record.amount * (0.8 + (h[1] / 255) * 0.2))}`,
  ];
  return { riskScore, findings };
}

const evidenceFor = (record) => [`${record.claimId.toLowerCase()}-photo-001.jpg`, `${record.claimId.toLowerCase()}-adjuster-notes.pdf`, record.amount > 10000 ? `${record.claimId.toLowerCase()}-assessor-report.pdf` : null].filter(Boolean);

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json({ limit: "256kb" }));

// Health and info are anonymous; everything else needs a valid Claims API token.
app.get("/health", (_req, res) => res.json({ ok: true, storage: table ? `table ${CLAIMS_TABLE}` : "in-memory", pdp: PDP_URL }));

app.use(async (req, res, next) => {
  const auth = req.get("authorization") || "";
  const token = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  if (!token) return res.status(401).set("WWW-Authenticate", "Bearer").json({ error: "missing bearer token" });
  const v = await validateToken(token);
  if (v.error) {
    console.log(`[${stamp()}] 401 ${v.error}: ${v.detail ?? ""}`);
    return res.status(401).set("WWW-Authenticate", `Bearer error="invalid_token"`).json({ error: v.error, detail: v.detail });
  }
  req.token = v.payload;
  req.tokenInfo = summarize(v.payload);
  next();
});

const strip = (r) => {
  const { etag, ...rest } = r;
  return rest;
};

// Route helper: load the record, ask the PDP, then run the handler.
function guarded(actionName, handler) {
  return async (req, res) => {
    const claimId = req.params.claimId || req.body?.claimId;
    if (!claimId) return res.status(400).json({ error: "claimId is required" });
    const record = await repo.get(claimId);
    if (!record) return res.status(404).json({ error: `claim ${claimId} not found`, _debug: { tokenInfo: req.tokenInfo } });

    const authz = await authorize(req.token, actionName, record);
    const summary = authzenSummary(authz);
    console.log(
      `[${stamp()}] ${actionName} ${claimId} => ${authz.decision ? "PERMIT" : "DENY"} (${summary.reason_admin}) ` +
        `| caller ${req.tokenInfo.callerKind} azp=${req.tokenInfo.callerAppId} oid=${req.tokenInfo.objectId}`
    );
    if (!authz.decision) {
      return res.status(authz.reachable ? 403 : 503).json({
        error: authz.reachable ? "forbidden" : "pdp unavailable",
        decidedBy: authz.reachable ? "pdp" : "claims-api",
        pep: "claims-api",
        reason: summary.reason_user,
        authzen: summary,
        record: strip(record),
        _debug: { tokenInfo: req.tokenInfo },
      });
    }
    try {
      const body = await handler(record, req);
      res.json({ ...body, decidedBy: "pdp", pep: "claims-api", authzen: summary, _debug: { tokenInfo: req.tokenInfo } });
    } catch (error) {
      const conflict = error.statusCode === 412;
      res.status(conflict ? 409 : 500).json({ error: conflict ? "record changed concurrently, retry" : error.message, _debug: { tokenInfo: req.tokenInfo } });
    }
  };
}

// List: any valid token. Per-record filtering is the MCP server's job (AuthZEN batch).
app.get(["/claims", "/api/claims"], async (req, res) => {
  const all = await repo.list();
  res.json({ claims: all.map(strip), _debug: { tokenInfo: req.tokenInfo } });
});

app.get(["/claims/:claimId", "/api/claims/:claimId"], guarded("get_claim", async (record) => ({ claim: strip(record) })));

app.get(
  ["/claims/:claimId/evidence", "/api/claims/:claimId/evidence"],
  guarded("get_claim_evidence", async (record) => ({ claimId: record.claimId, evidence: evidenceFor(record) }))
);

app.post(
  ["/claims/analyze", "/api/claims/analyze"],
  guarded("analyze_claim", async (record, req) => {
    const before = record.status;
    const { riskScore, findings } = analyze(record);
    const updated = {
      ...record,
      status: record.status === "open" ? "analyzed" : record.status,
      riskScore,
      findings,
      analysisCount: Number(record.analysisCount || 0) + 1,
      lastAnalyzedAt: stamp(),
      lastAnalyzedBy: req.tokenInfo.callerAppId,
      lastAnalyzedFor: req.tokenInfo.userName || "(app-only, no user)",
    };
    await repo.update(updated);
    return { result: "analyzed", statusBefore: before, claim: strip(updated) };
  })
);

app.post(
  ["/claims/archive", "/api/claims/archive"],
  guarded("archive_claim", async (record, req) => {
    const before = record.status;
    const updated = {
      ...record,
      status: "archived",
      archivedAt: stamp(),
      archivedBy: req.tokenInfo.callerAppId,
      archivedFor: req.tokenInfo.userName || "(app-only, no user)",
    };
    await repo.update(updated);
    return { result: "archived", statusBefore: before, claim: strip(updated) };
  })
);

// Demo helper: restore the sample data. Host application app-only token only.
app.post(["/admin/reset", "/api/admin/reset"], async (req, res) => {
  if (!rolesOf(req.token).includes("Claims.Archive.All")) {
    return res.status(403).json({ error: "reset requires the Claims.Archive.All app role", _debug: { tokenInfo: req.tokenInfo } });
  }
  const n = await repo.reset();
  console.log(`[${stamp()}] sample data reset by ${req.tokenInfo.callerAppId} (${n} claims)`);
  res.json({ reset: n });
});

await repo.seedIfEmpty();
app.listen(PORT, () => {
  console.log(`Hosted POC Claims API listening on :${PORT}`);
  console.log(`  audience ${AUDIENCES.join(" | ")} | storage ${table ? `Azure Table ${CLAIMS_TABLE}` : "in-memory"} | PDP ${PDP_URL}`);
});
