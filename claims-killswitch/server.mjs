// Kill switch service: the ONLY writer of the kill list (Proposal section 6).
//
//   POST    /events?code=<key>   Event Grid push endpoint (CloudEvents 1.0, structured
//                                or batch). Poc.Agent.Killed -> SET kill:<scope>:<id>,
//                                Poc.Agent.Restored -> DEL. Idempotent on the CloudEvents id.
//   OPTIONS /events              CloudEvents abuse-protection handshake (Event Grid
//                                validates the endpoint when the subscription is created)
//   GET     /kills               current kill list            (x-pdp-key)
//   GET     /kills/check         ?agent=&blueprint=&user=     (x-pdp-key, used by APIM)
//   GET     /audit               last audit records           (x-pdp-key)
//   GET     /health
//
// Drift sync (Proposal 6.5): every DRIFT_INTERVAL_SECONDS the service reads
// accountEnabled of WATCHED_PRINCIPALS from Microsoft Graph (managed identity,
// Application.Read.All). A principal disabled outside the workflow (Entra admin
// center, ID Protection) is added to the kill list with source "drift"; when it
// is re-enabled in Entra, a drift entry is removed again.
//
// Env: PORT (5011), POC_INTERNAL_KEY, REDIS_URL, STORAGE_TABLE_ENDPOINT, AUDIT_TABLE (KillAudit),
//      WATCHED_PRINCIPALS (comma separated object ids), DRIFT_INTERVAL_SECONDS (60, 0 = off)

import { randomUUID } from "node:crypto";
import express from "express";
import { createClient } from "redis";
import { TableClient } from "@azure/data-tables";
import { DefaultAzureCredential } from "@azure/identity";

const PORT = process.env.PORT || 5011;
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
const AUDIT_TABLE = process.env.AUDIT_TABLE || "KillAudit";
const WATCHED = (process.env.WATCHED_PRINCIPALS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const DRIFT_INTERVAL_SECONDS = Number(process.env.DRIFT_INTERVAL_SECONDS ?? 60);
const INDEX_KEY = "kill:index";
const SCOPES = ["agent", "blueprint", "user"];

const credential = new DefaultAzureCredential();
const stamp = () => new Date().toISOString();

// ---------------------------------------------------------------------------
// Kill list store: Redis, or an in-memory map for local runs
// ---------------------------------------------------------------------------

let redis = null;
if (redisOptions) {
  redis = createClient(redisOptions);
  redis.on("error", (e) => console.error(`[${stamp()}] redis error: ${e.message}`));
  await redis.connect().catch((e) => console.error(`[${stamp()}] redis connect failed: ${e.message}`));
}

const memory = new Map();
const kv = redis
  ? {
      async set(key, value, ttlSeconds) {
        const options = ttlSeconds > 0 ? { expiration: { type: "EX", value: ttlSeconds } } : undefined;
        await redis.set(key, JSON.stringify(value), options);
        await redis.sAdd(INDEX_KEY, key);
      },
      async del(key) {
        await redis.del(key);
        await redis.sRem(INDEX_KEY, key);
      },
      async get(key) {
        const v = await redis.get(key);
        return v ? JSON.parse(v) : null;
      },
      async list() {
        const keys = await redis.sMembers(INDEX_KEY);
        if (keys.length === 0) return [];
        const values = await redis.mGet(keys);
        const live = [];
        for (let i = 0; i < keys.length; i++) {
          if (values[i]) live.push({ key: keys[i], ...JSON.parse(values[i]) });
          else await redis.sRem(INDEX_KEY, keys[i]); // expired (expiresAt) or removed
        }
        return live;
      },
      // Idempotency on the CloudEvents id: first writer wins for 24 h.
      async firstTime(eventId) {
        return (await redis.set(`kill:event:${eventId}`, "1", { condition: "NX", expiration: { type: "EX", value: 86400 } })) === "OK";
      },
    }
  : {
      async set(key, value) {
        memory.set(key, value);
      },
      async del(key) {
        memory.delete(key);
      },
      async get(key) {
        return memory.get(key) || null;
      },
      async list() {
        return [...memory.entries()].map(([key, v]) => ({ key, ...v }));
      },
      seen: new Set(),
      async firstTime(eventId) {
        if (this.seen.has(eventId)) return false;
        this.seen.add(eventId);
        return true;
      },
    };

// ---------------------------------------------------------------------------
// Audit trail (Azure Table, newest first via inverted RowKey)
// ---------------------------------------------------------------------------

const auditTable = TABLE_ENDPOINT ? new TableClient(TABLE_ENDPOINT, AUDIT_TABLE, credential) : null;
const auditMemory = [];

async function audit(record) {
  const entry = { at: stamp(), ...record };
  console.log(`[${entry.at}] AUDIT ${JSON.stringify(record)}`);
  if (!auditTable) {
    auditMemory.unshift(entry);
    auditMemory.length = Math.min(auditMemory.length, 200);
    return;
  }
  const inverted = String(8640000000000000 - Date.now()).padStart(16, "0");
  try {
    await auditTable.createEntity({
      partitionKey: "audit",
      rowKey: `${inverted}-${randomUUID().slice(0, 8)}`,
      ...Object.fromEntries(Object.entries(entry).map(([k, v]) => [k, typeof v === "object" && v !== null ? JSON.stringify(v) : v ?? ""])),
    });
  } catch (error) {
    console.error(`[${stamp()}] audit write failed: ${error.message}`);
  }
}

async function readAudit(top = 50) {
  if (!auditTable) return auditMemory.slice(0, top);
  const rows = [];
  for await (const e of auditTable.listEntities({ queryOptions: { filter: "PartitionKey eq 'audit'" } })) {
    const { partitionKey, rowKey, etag, timestamp, ...rest } = e;
    rows.push(rest);
    if (rows.length >= top) break;
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Event handling
// ---------------------------------------------------------------------------

const keyFor = (scope, id) => `kill:${scope}:${String(id).toLowerCase()}`;

async function handleEvent(event) {
  const data = typeof event.data === "string" ? JSON.parse(event.data) : event.data || {};
  const scope = String(data.scope || "agent").toLowerCase();
  const targetId = data.targetId || { agent: data.agentId, blueprint: data.blueprintId, user: data.userId }[scope];
  if (!SCOPES.includes(scope) || !targetId) {
    return { id: event.id, outcome: "rejected", detail: `scope must be ${SCOPES.join("|")} and data needs a target id` };
  }
  if (!(await kv.firstTime(event.id))) {
    return { id: event.id, outcome: "duplicate (already processed)" };
  }

  const key = keyFor(scope, targetId);
  if (event.type === "Poc.Agent.Killed") {
    const ttl = data.expiresAt ? Math.max(1, Math.round((Date.parse(data.expiresAt) - Date.now()) / 1000)) : 0;
    const entry = {
      scope,
      targetId,
      reason: data.reason || "",
      requestedBy: data.requestedBy || "",
      since: stamp(),
      expiresAt: data.expiresAt || null,
      eventId: event.id,
      source: event.source || "event-grid",
    };
    await kv.set(key, entry, ttl);
    await audit({ action: "kill", key, eventId: event.id, scope, targetId, reason: entry.reason, requestedBy: entry.requestedBy, source: entry.source });
    return { id: event.id, outcome: "killed", key };
  }
  if (event.type === "Poc.Agent.Restored") {
    await kv.del(key);
    await audit({ action: "restore", key, eventId: event.id, scope, targetId, reason: data.reason || "", requestedBy: data.requestedBy || "", source: event.source || "event-grid" });
    return { id: event.id, outcome: "restored", key };
  }
  return { id: event.id, outcome: "ignored", detail: `unknown type ${event.type}` };
}

// ---------------------------------------------------------------------------
// Drift sync: Entra accountEnabled -> kill list
// ---------------------------------------------------------------------------

const drift = { lastRun: null, lastError: null, principals: {} };

async function driftSync() {
  try {
    const token = await credential.getToken("https://graph.microsoft.com/.default");
    for (const id of WATCHED) {
      const response = await fetch(
        `https://graph.microsoft.com/v1.0/servicePrincipals/${id}?$select=id,appId,displayName,accountEnabled`,
        { headers: { authorization: `Bearer ${token.token}` } }
      );
      if (!response.ok) {
        drift.principals[id] = { error: `Graph ${response.status}` };
        continue;
      }
      const sp = await response.json();
      drift.principals[id] = { displayName: sp.displayName, accountEnabled: sp.accountEnabled };
      const key = keyFor("agent", sp.appId || id);
      const existing = await kv.get(key);
      if (sp.accountEnabled === false && !existing) {
        await kv.set(key, {
          scope: "agent",
          targetId: sp.appId || id,
          reason: "disabled in Entra outside the kill switch workflow (drift sync)",
          requestedBy: "drift-sync",
          since: stamp(),
          expiresAt: null,
          eventId: null,
          source: "drift",
        }, 0);
        await audit({ action: "kill", key, scope: "agent", targetId: sp.appId || id, reason: "drift: accountEnabled=false in Entra", source: "drift" });
      } else if (sp.accountEnabled === true && existing?.source === "drift") {
        await kv.del(key);
        await audit({ action: "restore", key, scope: "agent", targetId: sp.appId || id, reason: "drift: accountEnabled=true in Entra", source: "drift" });
      }
    }
    drift.lastError = null;
  } catch (error) {
    drift.lastError = error.message;
    console.error(`[${stamp()}] drift sync failed: ${error.message}`);
  } finally {
    drift.lastRun = stamp();
  }
}

if (WATCHED.length && DRIFT_INTERVAL_SECONDS > 0) {
  setInterval(driftSync, DRIFT_INTERVAL_SECONDS * 1000).unref();
  setTimeout(driftSync, 5000).unref();
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json({ limit: "256kb", type: ["application/json", "application/cloudevents+json", "application/cloudevents-batch+json"] }));

const keyOk = (req) => !INTERNAL_KEY || req.get("x-pdp-key") === INTERNAL_KEY || req.query.code === INTERNAL_KEY;
const requireKey = (req, res, next) => (keyOk(req) ? next() : res.status(401).json({ error: "missing or wrong key" }));

// CloudEvents webhook validation (abuse protection) used by Event Grid.
app.options("/events", (req, res) => {
  const origin = req.get("WebHook-Request-Origin");
  console.log(`[${stamp()}] webhook validation handshake from ${origin}`);
  res.set("WebHook-Allowed-Origin", origin || "*").set("WebHook-Allowed-Rate", "*").status(200).end();
});

app.post("/events", requireKey, async (req, res) => {
  const events = Array.isArray(req.body) ? req.body : [req.body];
  const results = [];
  for (const event of events) {
    if (!event?.id || !event?.type) {
      results.push({ outcome: "rejected", detail: "not a CloudEvent (id and type required)" });
      continue;
    }
    try {
      results.push(await handleEvent(event));
    } catch (error) {
      console.error(`[${stamp()}] event ${event.id} failed: ${error.message}`);
      // 5xx makes Event Grid retry (and dead-letter after the last attempt).
      return res.status(503).json({ error: error.message, results });
    }
  }
  console.log(`[${stamp()}] /events ${JSON.stringify(results)}`);
  res.json({ results });
});

app.get("/kills", requireKey, async (_req, res) => {
  try {
    res.json({ kills: await kv.list(), drift });
  } catch (error) {
    res.status(503).json({ error: error.message });
  }
});

// Used by the APIM gateway (cached there for a few seconds in the external Redis cache).
app.get("/kills/check", requireKey, async (req, res) => {
  try {
    const keys = [];
    if (req.query.agent) keys.push(keyFor("agent", req.query.agent));
    if (req.query.blueprint) keys.push(keyFor("blueprint", req.query.blueprint));
    if (req.query.user) keys.push(keyFor("user", req.query.user));
    const hits = {};
    for (const k of keys) {
      const v = await kv.get(k);
      if (v) hits[k] = v;
    }
    res.json({ checked: keys, hit: Object.keys(hits).length > 0, entries: hits });
  } catch (error) {
    // The gateway treats a failed check as "kill list unavailable" and fails closed for agents.
    res.status(503).json({ error: error.message });
  }
});

app.get("/audit", requireKey, async (req, res) => {
  try {
    res.json({ audit: await readAudit(Number(req.query.top || 50)) });
  } catch (error) {
    res.status(503).json({ error: error.message });
  }
});

app.get("/health", (_req, res) =>
  res.json({
    ok: true,
    store: redis ? (redis.isReady ? "redis ready" : "redis not ready") : "in-memory (local)",
    audit: auditTable ? `table ${AUDIT_TABLE}` : "in-memory",
    watched: WATCHED,
    drift,
  })
);

app.listen(PORT, () => {
  console.log(`POC kill switch service listening on :${PORT}`);
  console.log(`  store: ${redis ? "Redis" : "in-memory (local)"} | audit: ${auditTable ? "Azure Table" : "in-memory"}`);
  console.log(`  drift sync: ${WATCHED.length && DRIFT_INTERVAL_SECONDS > 0 ? `${WATCHED.join(", ")} every ${DRIFT_INTERVAL_SECONDS}s` : "off"}`);
});
