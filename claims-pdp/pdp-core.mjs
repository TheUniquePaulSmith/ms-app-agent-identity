// AuthZEN -> Cedar evaluation, with no I/O of its own.
//
// The entity registry (blueprints, agents, applications, groups, local members)
// comes from the "PdpEntities" Azure Table; the server reads the rows and hands
// them to setEntities(store, entitiesFromRows(rows)) at start, on POST
// /admin/reload and on a timer. The server also injects three policy
// information points (PIPs):
//   killList.get(keys)            -> Map<key, entry>   (Redis in Azure)
//   claims.get(claimId)           -> record | null     (Azure Table "Claims")
//   groups.resolve(oid, upn)      -> { groups: [friendly ids], source }  (Microsoft Graph)
// so the same code runs in Azure, locally and in the unit tests.

import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";

const here = dirname(fileURLToPath(import.meta.url));
// Identity types live in the platform layer's namespace, domain types in the domain's.
const PLATFORM_NS = "Platform";
const PLATFORM_TYPES = new Set(["Blueprint", "Agent", "Application", "Group", "User"]);
const NS = "Claims";
const uid = (type, id) => ({ type: `${PLATFORM_TYPES.has(type) ? PLATFORM_NS : NS}::${type}`, id: String(id) });
const ref = (type, id) => ({ __entity: uid(type, id) });

// ---------------------------------------------------------------------------
// Policy store: one directory per layer, each with *.cedarschema and *.cedar.
//
//   platform  guardrails shared by every domain PDP (forbid only)
//   claims    this PDP's domain
//
// Schemas of all layers are concatenated (one namespace each) and policies
// validated together; @ids must be unique across layers.
// ---------------------------------------------------------------------------

export const POLICY_LAYERS = ["platform", "claims"];

export function loadPolicyStore(dir = join(here, "policies"), layers = POLICY_LAYERS) {
  const read = (layer, ext) =>
    readdirSync(join(dir, layer))
      .filter((f) => f.endsWith(ext))
      .sort()
      .map((f) => ({ layer, file: `${layer}/${f}`, text: readFileSync(join(dir, layer, f), "utf8") }));
  const schemaFiles = layers.flatMap((l) => read(l, ".cedarschema"));
  const policyFiles = layers.flatMap((l) => read(l, ".cedar"));
  const joined = (files) => files.map((f) => `// ===== ${f.file} =====\n${f.text}`).join("\n");
  const schemaText = joined(schemaFiles);
  const policyText = joined(policyFiles);

  const staticPolicies = {};
  const annotations = {};
  for (const { layer, file, text: fileText } of policyFiles) {
    const parts = cedar.policySetTextToParts(fileText);
    if (parts.type !== "success") throw new Error(`policy parse failed in ${file}: ${JSON.stringify(parts.errors)}`);
    for (const text of parts.policies) {
      const json = cedar.policyToJson(text);
      if (json.type !== "success") throw new Error(`policy to JSON failed: ${JSON.stringify(json.errors)}`);
      const id = json.json.annotations?.id;
      if (!id) throw new Error(`policy without @id in ${file}: ${text.slice(0, 80)}`);
      if (staticPolicies[id]) throw new Error(`duplicate policy @id ${id} (${file})`);
      // Platform rules may only take access away; granting is the domain's job.
      if (layer === "platform" && json.json.effect !== "forbid") throw new Error(`platform policy ${id} must be a forbid`);
      staticPolicies[id] = text;
      annotations[id] = { effect: json.json.effect, layer, ...json.json.annotations };
    }
  }

  const validation = cedar.validate({
    schema: schemaText,
    policies: { staticPolicies },
    validationSettings: { mode: "strict" },
  });
  if (validation.type !== "success") throw new Error(`policy validation failed: ${JSON.stringify(validation.errors)}`);
  if (validation.validationErrors.length) {
    throw new Error(`policy validation errors: ${validation.validationErrors.map((e) => `${e.policyId}: ${e.error.message}`).join("; ")}`);
  }

  const version =
    process.env.POLICY_VERSION ||
    `${new Date().toISOString().slice(0, 10)}.${createHash("sha256").update(schemaText + policyText).digest("hex").slice(0, 8)}`;

  return {
    schemaText,
    policyText,
    staticPolicies,
    annotations,
    version,
    ...entitiesFromRows([]),
    validationWarnings: validation.validationWarnings,
  };
}

// ---------------------------------------------------------------------------
// Entity registry: rows of the "PdpEntities" table, PartitionKey = kind
//
//   blueprint    RowKey app id     displayName
//   agent        RowKey app id     displayName, blueprint, autonomousLimit
//   application  RowKey app id     displayName, isMcpServer
//   group        RowKey group id   displayName, entraObjectId, region   (ids used in the policies)
//   member       RowKey oid / UPN  groups (comma separated group ids; only for GROUP_SOURCE=local)
//
// Agents not in the registry are evaluated with registered=false and denied by
// agent-must-be-registered.
// ---------------------------------------------------------------------------

export const ENTITY_KINDS = ["blueprint", "agent", "application", "group", "member"];

export function entitiesFromRows(rows) {
  const blueprints = new Map();
  const agents = new Map();
  const applications = new Map();
  const groups = [];
  const localMembers = {};
  const text = (v) => (v === undefined || v === null ? "" : String(v));
  for (const row of rows) {
    const id = text(row.rowKey);
    const key = id.toLowerCase();
    switch (row.partitionKey) {
      case "blueprint":
        blueprints.set(key, { id: key, displayName: text(row.displayName) });
        break;
      case "agent":
        agents.set(key, {
          id: key,
          displayName: text(row.displayName),
          blueprint: text(row.blueprint).toLowerCase(),
          autonomousLimit: Number(row.autonomousLimit ?? 0),
        });
        break;
      case "application":
        applications.set(key, { id: key, displayName: text(row.displayName), isMcpServer: row.isMcpServer === true || row.isMcpServer === "true" });
        break;
      case "group":
        groups.push({ id, displayName: text(row.displayName), entraObjectId: text(row.entraObjectId), region: text(row.region) || undefined });
        break;
      case "member":
        localMembers[key] = text(row.groups).split(",").map((g) => g.trim()).filter(Boolean);
        break;
    }
  }
  groups.sort((a, b) => a.id.localeCompare(b.id));
  return { blueprints, agents, applications, groups, localMembers };
}

// Swaps the registry in place, so evaluators and resolvers built on the store see it at once.
export function setEntities(store, entities) {
  Object.assign(store, entities);
}

// ---------------------------------------------------------------------------
// Kill list keys (shared with claims-killswitch and the APIM policy)
// ---------------------------------------------------------------------------

export const killKeys = {
  agent: (id) => `kill:agent:${String(id).toLowerCase()}`,
  blueprint: (id) => `kill:blueprint:${String(id).toLowerCase()}`,
  user: (id) => `kill:user:${String(id).toLowerCase()}`,
};

// ---------------------------------------------------------------------------
// One AuthZEN evaluation
// ---------------------------------------------------------------------------

export function createEvaluator(store, pips, options = {}) {
  const failOpenForApplications = options.failOpenForApplications ?? true;

  async function evaluate(request) {
    const started = Date.now();
    const regionGroup = Object.fromEntries(store.groups.filter((g) => g.region).map((g) => [g.region, g.id]));
    const subject = request.subject || {};
    const action = request.action || {};
    const resource = request.resource || {};
    const ctx = request.context || {};
    const subjectId = String(subject.id || "").toLowerCase();
    // The registry is a PIP too: a registered agent is an agent even when the
    // token lacked xms_par_app_azp and the PEP therefore said "application".
    const isAgent = subject.type === "agent" || store.agents.has(subjectId);
    const permissions = Array.isArray(subject.properties?.permissions) ? subject.properties.permissions : [];

    if (!subjectId || !action.name) {
      return deny("bad request: subject.id and action.name are required", "Invalid authorization request.", [], started);
    }

    // --- subject -----------------------------------------------------------
    const registeredAgent = isAgent ? store.agents.get(subjectId) : undefined;
    const blueprintId = String(subject.properties?.blueprint || registeredAgent?.blueprint || "unknown").toLowerCase();
    const onBehalfOf = ctx.onBehalfOf ? String(ctx.onBehalfOf).toLowerCase() : null;

    // --- kill list (fail closed for agents) --------------------------------
    const keys = [killKeys.agent(subjectId)];
    if (isAgent) keys.push(killKeys.blueprint(blueprintId));
    if (onBehalfOf) keys.push(killKeys.user(onBehalfOf));
    let kills;
    const killList = { checked: true, keys, hit: false, entries: {} };
    try {
      kills = await pips.killList.get(keys);
    } catch (error) {
      killList.checked = false;
      killList.error = error.message;
      if (isAgent || !failOpenForApplications) {
        return deny(
          `kill list unavailable (${error.message}); failing closed for ${isAgent ? "agents" : "all callers"}`,
          "Authorization is temporarily unavailable.",
          ["fail-closed-kill-list"],
          started,
          { killList }
        );
      }
      kills = new Map();
    }
    for (const [k, v] of kills) killList.entries[k] = v;
    killList.hit = kills.size > 0;

    const entities = [];
    let principal;
    if (isAgent) {
      principal = uid("Agent", subjectId);
      entities.push({
        uid: uid("Blueprint", blueprintId),
        attrs: {
          displayName: store.blueprints.get(blueprintId)?.displayName || "unknown blueprint",
          killed: kills.has(killKeys.blueprint(blueprintId)),
        },
        parents: [],
      });
      entities.push({
        uid: principal,
        attrs: {
          displayName: registeredAgent?.displayName || "unregistered agent",
          registered: Boolean(registeredAgent),
          killed: kills.has(killKeys.agent(subjectId)),
          blueprint: ref("Blueprint", blueprintId),
        },
        parents: [uid("Blueprint", blueprintId)],
      });
    } else {
      const app = store.applications.get(subjectId);
      principal = uid("Application", subjectId);
      entities.push({
        uid: principal,
        attrs: {
          displayName: app?.displayName || "unknown application",
          registered: Boolean(app),
          killed: kills.has(killKeys.agent(subjectId)),
          isMcpServer: Boolean(app?.isMcpServer),
        },
        parents: [],
      });
    }

    // --- user and Entra groups ---------------------------------------------
    const cedarContext = { permissions, pep: String(ctx.pep || "unknown") };
    if (ctx.mcpMethod) cedarContext.mcpMethod = String(ctx.mcpMethod);
    // Claims-domain data about the agent, so it travels in the domain's context,
    // not on the platform's Agent entity.
    if (isAgent) cedarContext.agentAutonomousLimit = Math.trunc(Number(registeredAgent?.autonomousLimit ?? 0));
    let user;
    if (onBehalfOf) {
      const membership = await pips.groups.resolve(onBehalfOf, ctx.onBehalfOfUpn);
      user = { oid: onBehalfOf, upn: ctx.onBehalfOfUpn || "", groups: membership.groups, groupSource: membership.source };
      for (const g of store.groups) entities.push({ uid: uid("Group", g.id), attrs: { displayName: g.displayName }, parents: [] });
      entities.push({
        uid: uid("User", onBehalfOf),
        attrs: { upn: user.upn, killed: kills.has(killKeys.user(onBehalfOf)) },
        parents: membership.groups.map((g) => uid("Group", g)),
      });
      cedarContext.onBehalfOf = ref("User", onBehalfOf);
    }

    // --- resource ----------------------------------------------------------
    let cedarResource;
    let resourceInfo;
    if (resource.type === "claim") {
      const id = String(resource.id || "");
      let record = resource.properties && Object.keys(resource.properties).length ? resource.properties : null;
      let source = record ? "pep" : "pip";
      if (!record) record = await pips.claims.get(id);
      const region = String(record?.region || "");
      const group = regionGroup[region] || "none";
      cedarResource = uid("Claim", id);
      resourceInfo = {
        id,
        source,
        exists: Boolean(record),
        region,
        status: String(record?.status || ""),
        amount: Number(record?.amount || 0),
        litigationHold: Boolean(record?.litigationHold),
        adjusterGroup: group,
      };
      if (!entities.some((e) => e.uid.type === uid("Group", group).type && e.uid.id === group)) {
        const g = store.groups.find((x) => x.id === group);
        entities.push({ uid: uid("Group", group), attrs: { displayName: g?.displayName || "no group" }, parents: [] });
      }
      entities.push({
        uid: cedarResource,
        attrs: {
          exists: resourceInfo.exists,
          region,
          status: resourceInfo.status,
          amount: Math.trunc(resourceInfo.amount),
          litigationHold: resourceInfo.litigationHold,
          adjusterGroup: ref("Group", group),
        },
        parents: [],
      });
    } else {
      cedarResource = uid("McpServer", resource.id || "claims-mcp");
      resourceInfo = { id: resource.id || "claims-mcp", type: "mcp_server" };
      entities.push({ uid: cedarResource, attrs: {}, parents: [] });
    }

    // --- action: "mcp:<method>" from the gateway -> mcp_request --------------
    let cedarAction = String(action.name);
    if (cedarAction.startsWith("mcp:")) {
      cedarContext.mcpMethod = cedarContext.mcpMethod || cedarAction.slice(4);
      cedarAction = "mcp_request";
    }

    const answer = cedar.isAuthorized({
      principal,
      action: { type: `${NS}::Action`, id: cedarAction },
      resource: cedarResource,
      context: cedarContext,
      schema: store.schemaText,
      validateRequest: true,
      policies: { staticPolicies: store.staticPolicies },
      entities,
    });

    const details = {
      killList,
      principal: {
        type: principal.type,
        id: subjectId,
        typeSource: subject.type === "agent" ? "token (xms_par_app_azp)" : isAgent ? "PDP agent registry" : "token",
        ...entities.find((e) => e.uid === principal).attrs,
      },
      user,
      resource: resourceInfo,
      cedarAction,
      agentAutonomousLimit: cedarContext.agentAutonomousLimit,
    };

    if (answer.type !== "success") {
      return deny(
        `cedar evaluation failed: ${answer.errors.map((e) => e.message).join("; ")}`,
        "Authorization failed.",
        [],
        started,
        details
      );
    }

    const decision = answer.response.decision === "allow";
    const policyIds = answer.response.diagnostics.reason;
    const errors = answer.response.diagnostics.errors.map((e) => `${e.policyId}: ${e.error.message}`);
    const forbids = policyIds.filter((id) => store.annotations[id]?.effect === "forbid");

    let reasonAdmin;
    let reasonUser;
    if (decision) {
      reasonAdmin = `permit: ${policyIds.join(", ")}`;
      reasonUser = "Allowed.";
    } else if (forbids.length) {
      reasonAdmin = `forbid: ${forbids.map((id) => `${id} (${store.annotations[id]?.layer})`).join(", ")}`;
      reasonUser = forbids.map((id) => store.annotations[id]?.reason).filter(Boolean).join(" ");
    } else {
      reasonAdmin = "no permit policy matched (default deny)";
      reasonUser = "This identity has no permission for this action.";
    }

    return {
      decision,
      context: {
        reason_admin: { en: reasonAdmin },
        reason_user: { en: reasonUser },
        policyIds,
        policyVersion: store.version,
        evaluationErrors: errors.length ? errors : undefined,
        evaluationMs: Date.now() - started,
        ...details,
      },
    };
  }

  function deny(admin, user, policyIds, started, extra = {}) {
    return {
      decision: false,
      context: {
        reason_admin: { en: admin },
        reason_user: { en: user },
        policyIds,
        policyVersion: store.version,
        evaluationMs: Date.now() - started,
        ...extra,
      },
    };
  }

  // AuthZEN 1.0 batch: top-level subject/action/resource/context are defaults
  // that each entry in evaluations[] may override.
  async function evaluateBatch(request) {
    const items = Array.isArray(request.evaluations) && request.evaluations.length ? request.evaluations : [{}];
    const merged = items.map((item) => ({
      subject: item.subject || request.subject,
      action: item.action || request.action,
      resource: item.resource || request.resource,
      context: { ...(request.context || {}), ...(item.context || {}) },
    }));
    return { evaluations: await Promise.all(merged.map(evaluate)) };
  }

  return { evaluate, evaluateBatch };
}

// Local group resolution (no Graph): "member" rows of the registry, by oid or UPN.
export function localGroupResolver(store) {
  return {
    async resolve(oid, upn) {
      const byOid = store.localMembers[String(oid || "").toLowerCase()];
      const byUpn = store.localMembers[String(upn || "").toLowerCase()];
      return { groups: byOid || byUpn || [], source: byOid ? "local:oid" : byUpn ? "local:upn" : "local:none" };
    },
  };
}
