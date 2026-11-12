// POC Claims Policy Decision Point: OpenID AuthZEN Authorization API 1.0 in
// front of a Cedar engine (@cedar-policy/cedar-wasm).
//
//   GET  /.well-known/authzen-configuration   PDP metadata (public)
//   POST /access/v1/evaluation                one decision
//   POST /access/v1/evaluations               batch (AuthZEN 1.0 evaluations[])
//   GET  /policies                            schema, policies, version, entity registry (UI)
//   POST /admin/reload                        re-read the entity registry now (web app, after a change)
//   GET  /health
//
// PEPs (APIM gateway, claims-mcp-azure, claims-api-azure) authenticate with the
// shared header x-pdp-key (POC simplification; Proposal section 8 describes the
// production variant: an app registration for the PDP and managed identity tokens).
//
// Entity registry (blueprints, agents, applications, groups, local members):
//   Azure Table "PdpEntities" in the same storage account, PartitionKey = kind
//   (see pdp-core.mjs). Read at start, on POST /admin/reload and every
//   ENTITY_REFRESH_MS (30 s); a failed read keeps the last good registry. With no
//   storage configured the registry is empty (every agent unregistered).
//
// Policy information points:
//   kill list  Redis keys kill:agent:<id>, kill:blueprint:<id>, kill:user:<oid>
//              (written only by claims-killswitch), cached KILL_CACHE_MS (2 s)
//   claims     Azure Table "Claims" (managed identity), when the PEP did not send
//              resource.properties
//   groups     Microsoft Graph checkMemberGroups for the user (managed identity,
//              GroupMember.Read.All + User.ReadBasic.All), cached GROUP_CACHE_MS (60 s)
//
// Env: PORT (5010), POC_INTERNAL_KEY, REDIS_URL, STORAGE_TABLE_ENDPOINT (managed identity)
//      or STORAGE_CONNECTION_STRING (local runs, Azurite), CLAIMS_TABLE (Claims),
//      PDP_ENTITIES_TABLE (PdpEntities), ENTITY_REFRESH_MS (30000), GROUP_SOURCE (graph | local),
//      FAIL_OPEN_FOR_APPLICATIONS (true), CLAIMS_SEED_FILE (local runs without a table)

import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { createClient } from "redis";
import { TableClient } from "@azure/data-tables";
import { DefaultAzureCredential } from "@azure/identity";
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";
import { loadPolicyStore, createEvaluator, localGroupResolver, entitiesFromRows, setEntities } from "./pdp-core.mjs";

const cedarVersion = cedar.getCedarVersion();

const here = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 5010;
const INTERNAL_KEY = process.env.POC_INTERNAL_KEY || "";
const REDIS_URL = process.env.REDIS_URL || "";
// Azure Managed Redis: host + access key (keys contain / and +, so no URL form). TLS on port 10000.
const REDIS_HOST = process.env.REDIS_HOST || "";
const REDIS_PASSWORD = process.env.REDIS_PASSWORD || "";
const redisOptions = REDIS_HOST
  ? { socket: { host: REDIS_HOST, port: Number(process.env.REDIS_PORT || 10000), tls: true, reconnectStrategy: (n) => Math.min(n * 200, 3000) }, password: REDIS_PASSWORD }
  : REDIS_URL
    ? { url: REDIS_URL, socket: { reconnectStrategy: (n) => Math.min(n * 200, 3000) } }
    : null;
const TABLE_ENDPOINT = process.env.STORAGE_TABLE_ENDPOINT || "";
const STORAGE_CONNECTION_STRING = process.env.STORAGE_CONNECTION_STRING || "";
const CLAIMS_TABLE = process.env.CLAIMS_TABLE || "Claims";
const ENTITIES_TABLE = process.env.PDP_ENTITIES_TABLE || "PdpEntities";
const ENTITY_REFRESH_MS = Number(process.env.ENTITY_REFRESH_MS || 30000);
const KILL_CACHE_MS = Number(process.env.KILL_CACHE_MS || 2000);
const GROUP_CACHE_MS = Number(process.env.GROUP_CACHE_MS || 60000);
const FAIL_OPEN_FOR_APPLICATIONS = (process.env.FAIL_OPEN_FOR_APPLICATIONS || "true") === "true";
const SEED_FILE = process.env.CLAIMS_SEED_FILE || join(here, "..", "claims-api-azure", "seed-claims.json");

const store = loadPolicyStore();
const credential = new DefaultAzureCredential();
const stamp = () => new Date().toISOString();

// Managed identity in Azure; a connection string locally (allowInsecureConnection: Azurite is http).
const tableClient = (name) =>
  STORAGE_CONNECTION_STRING
    ? TableClient.fromConnectionString(STORAGE_CONNECTION_STRING, name, { allowInsecureConnection: true })
    : TABLE_ENDPOINT
      ? new TableClient(TABLE_ENDPOINT, name, credential)
      : null;

// ---------------------------------------------------------------------------
// PIP: kill list (Redis)
// ---------------------------------------------------------------------------

let redis = null;
if (redisOptions) {
  redis = createClient(redisOptions);
  redis.on("error", (e) => console.error(`[${stamp()}] redis error: ${e.message}`));
  redis.connect().catch((e) => console.error(`[${stamp()}] redis connect failed: ${e.message}`));
}

const killCache = new Map(); // key -> { at, value }
const killList = {
  async get(keys) {
    const now = Date.now();
    const result = new Map();
    const missing = [];
    for (const k of keys) {
      const cached = killCache.get(k);
      if (cached && now - cached.at < KILL_CACHE_MS) {
        if (cached.value) result.set(k, cached.value);
      } else {
        missing.push(k);
      }
    }
    if (missing.length === 0) return result;
    if (!redis) return result; // local run without Redis: empty kill list
    if (!redis.isReady) throw new Error("redis not connected");
    const values = await redis.mGet(missing);
    missing.forEach((k, i) => {
      let value = null;
      if (values[i]) {
        try {
          value = JSON.parse(values[i]);
        } catch {
          value = { raw: values[i] };
        }
      }
      killCache.set(k, { at: now, value });
      if (value) result.set(k, value);
    });
    return result;
  },
};

// ---------------------------------------------------------------------------
// PIP: claim attributes (Azure Table, or the seed file locally)
// ---------------------------------------------------------------------------

const claimsTable = tableClient(CLAIMS_TABLE);
const seed = !claimsTable && existsSync(SEED_FILE) ? JSON.parse(readFileSync(SEED_FILE, "utf8")) : [];

const claims = {
  async get(id) {
    if (claimsTable) {
      try {
        const e = await claimsTable.getEntity("claims", id);
        return { region: e.region, status: e.status, amount: e.amount, litigationHold: e.litigationHold };
      } catch (error) {
        if (error.statusCode === 404) return null;
        throw error;
      }
    }
    return seed.find((c) => c.claimId === id) || null;
  },
};

// ---------------------------------------------------------------------------
// PIP: Entra group membership (Microsoft Graph, or the registry's "member" rows)
// ---------------------------------------------------------------------------

const GROUP_SOURCE = process.env.GROUP_SOURCE || (process.env.WEBSITE_SITE_NAME ? "graph" : "local");
const local = localGroupResolver(store);
const groupCache = new Map(); // oid -> { at, value }

const groups =
  GROUP_SOURCE === "graph"
    ? {
        async resolve(oid, upn) {
          const cached = groupCache.get(oid);
          if (cached && Date.now() - cached.at < GROUP_CACHE_MS) return { ...cached.value, source: `${cached.value.source} (cached)` };
          const configuredGroups = store.groups.filter((g) => g.entraObjectId);
          if (!configuredGroups.length) return { groups: [], source: "graph: no group in the registry has an entraObjectId" };
          let value;
          try {
            const token = await credential.getToken("https://graph.microsoft.com/.default");
            const response = await fetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(oid)}/checkMemberGroups`, {
              method: "POST",
              headers: { authorization: `Bearer ${token.token}`, "content-type": "application/json" },
              body: JSON.stringify({ groupIds: configuredGroups.map((g) => g.entraObjectId) }),
            });
            if (!response.ok) throw new Error(`Graph ${response.status}: ${(await response.text()).slice(0, 200)}`);
            const ids = new Set(((await response.json()).value || []).map((x) => x.toLowerCase()));
            value = {
              groups: configuredGroups.filter((g) => ids.has(g.entraObjectId.toLowerCase())).map((g) => g.id),
              source: "graph:checkMemberGroups",
            };
          } catch (error) {
            // Fail closed: no groups means user-must-be-adjuster denies.
            console.error(`[${stamp()}] group lookup for ${oid} failed: ${error.message}`);
            value = { groups: [], source: `graph-error: ${error.message}` };
            return value; // do not cache failures
          }
          groupCache.set(oid, { at: Date.now(), value });
          return value;
        },
      }
    : local;

// ---------------------------------------------------------------------------
// Entity registry (Azure Table "PdpEntities")
// ---------------------------------------------------------------------------

const entitiesTable = tableClient(ENTITIES_TABLE);
const entityState = {
  source: entitiesTable ? `table ${ENTITIES_TABLE}` : "none (no storage configured: empty registry)",
  loadedAt: null,
  rows: 0,
  version: null,
  lastError: null,
};

async function reloadEntities(trigger) {
  if (!entitiesTable) return entityState;
  try {
    const rows = [];
    for await (const e of entitiesTable.listEntities()) rows.push(e);
    const version = createHash("sha256")
      .update(rows.map((r) => `${r.partitionKey}/${r.rowKey}/${r.etag}`).sort().join("\n"))
      .digest("hex")
      .slice(0, 8);
    if (version !== entityState.version) {
      setEntities(store, entitiesFromRows(rows));
      groupCache.clear(); // group object ids may have changed
      console.log(`[${stamp()}] entities ${version} loaded (${trigger}): ${rows.length} rows, agents ${[...store.agents.keys()].join(", ") || "(none)"}`);
    }
    Object.assign(entityState, { loadedAt: stamp(), rows: rows.length, version, lastError: null });
  } catch (error) {
    // Keep the last good registry; at start that is an empty one (agents fail closed).
    entityState.lastError = `${stamp()} ${error.message}`;
    console.error(`[${stamp()}] entities reload (${trigger}) failed: ${error.message}`);
  }
  return entityState;
}

await reloadEntities("startup");
setInterval(() => reloadEntities("timer"), ENTITY_REFRESH_MS).unref();

const evaluator = createEvaluator(store, { killList, claims, groups }, { failOpenForApplications: FAIL_OPEN_FOR_APPLICATIONS });

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json({ limit: "256kb" }));

function requireKey(req, res, next) {
  if (!INTERNAL_KEY || req.get("x-pdp-key") === INTERNAL_KEY) return next();
  res.status(401).json({ error: "missing or wrong x-pdp-key" });
}

function logDecision(request, result) {
  const s = request.subject || {};
  const c = request.context || {};
  console.log(
    `[${stamp()}] ${result.decision ? "PERMIT" : "DENY  "} ${s.type}:${s.id} ${request.action?.name} ` +
      `${request.resource?.type}:${request.resource?.id ?? "-"} pep=${c.pep ?? "-"} obo=${c.onBehalfOf ?? "-"} ` +
      `| ${result.context.reason_admin.en} | ${result.context.evaluationMs} ms`
  );
}

app.get("/.well-known/authzen-configuration", (req, res) => {
  const base = `${req.protocol}://${req.get("host")}`;
  res.json({
    policy_decision_point: base,
    access_evaluation_endpoint: `${base}/access/v1/evaluation`,
    access_evaluations_endpoint: `${base}/access/v1/evaluations`,
  });
});

app.post("/access/v1/evaluation", requireKey, async (req, res) => {
  try {
    const result = await evaluator.evaluate(req.body || {});
    logDecision(req.body || {}, result);
    res.set("X-Request-ID", req.get("X-Request-ID") || "").json(result);
  } catch (error) {
    console.error(`[${stamp()}] evaluation failed:`, error);
    res.status(500).json({ decision: false, context: { reason_admin: { en: `PDP error: ${error.message}` } } });
  }
});

app.post("/access/v1/evaluations", requireKey, async (req, res) => {
  try {
    const result = await evaluator.evaluateBatch(req.body || {});
    result.evaluations.forEach((r, i) => logDecision({ ...req.body, ...(req.body.evaluations?.[i] || {}) }, r));
    res.json(result);
  } catch (error) {
    console.error(`[${stamp()}] batch evaluation failed:`, error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/admin/reload", requireKey, async (_req, res) => {
  const state = await reloadEntities("admin/reload");
  res.status(state.lastError ? 502 : 200).json({ ...state, agents: store.agents.size, applications: store.applications.size, groups: store.groups.length });
});

app.get("/policies", requireKey, (_req, res) => {
  res.json({
    policyVersion: store.version,
    schema: store.schemaText,
    policies: store.policyText,
    policyIds: Object.entries(store.annotations).map(([id, a]) => ({ id, layer: a.layer, effect: a.effect, reason: a.reason })),
    blueprints: [...store.blueprints.values()],
    agents: [...store.agents.values()],
    applications: [...store.applications.values()],
    groups: store.groups,
    localMembers: store.localMembers,
    groupSource: GROUP_SOURCE,
    entities: entityState,
  });
});

app.get("/health", (_req, res) =>
  res.json({
    ok: true,
    policyVersion: store.version,
    redis: redis ? (redis.isReady ? "ready" : "not ready") : "not configured (empty kill list)",
    claims: claimsTable ? `table ${CLAIMS_TABLE}` : `seed file ${seed.length ? SEED_FILE : "(none)"}`,
    entities: entityState,
    groupSource: GROUP_SOURCE,
  })
);

app.listen(PORT, () => {
  console.log(`POC Claims PDP (AuthZEN 1.0 + Cedar ${cedarVersion}) listening on :${PORT}`);
  console.log(`  policy version ${store.version}, ${Object.keys(store.staticPolicies).length} policies, schema validated (strict)`);
  console.log(`  kill list: ${redisOptions ? "Redis" : "none (local)"} | claims: ${claimsTable ? "Azure Table" : "seed file"} | groups: ${GROUP_SOURCE}`);
  console.log(`  entities: ${entityState.source}, refresh every ${ENTITY_REFRESH_MS / 1000} s | registered agents: ${[...store.agents.keys()].join(", ") || "(none)"}`);
});
