# Identity concepts

[← Back to README](../README.md)

Sections 1 to 3: the identity model, how permissions are defined and consumed, and the objects this POC uses.

## 1. Agent Identity vs Application Identity

### The rule

> **Where the code runs does not pick the identity. The logical actor performing
> the operation picks the identity.**

One process (the host application) can hold two credentials and mint tokens for
two different actors:

- **Host application** (App Registration `POC Claims Web`): deterministic,
  application-owned operations. Sign-in, UI, business rules, "archive this
  claim because the workflow said so".
- **Agent identity** (`POC Claims Analysis Agent`): operations an agent decided
  to perform. Tool calls chosen by a model, autonomous background analysis,
  anything you want audited and authorized *as the agent* rather than as the app.

A second, independent axis is **whether a user is present**:

- No user: **application permission**. The token carries a `roles` claim.
- User present: **delegated permission**. The token carries a `scp` claim and
  the user's `oid`; the actor is the `azp` (authorized party).

That gives the 2x2 this POC demonstrates, plus two negative cases that prove the
downstream API can tell the actors apart:

| # | Endpoint on the host app | Actor whose credential mints the downstream token | User present | Permission kind | What the Claims API sees |
| --- | --- | --- | --- | --- | --- |
| 1 | `POST /claims/{id}/archive` | Host application | No | Application | `roles: [Claims.Archive.All]`, `oid` = host SP, `azp` = host app id, `idtyp = app` |
| 2 | `POST /claims/{id}/archive-as-user` | Host application (OBO) | Yes | Delegated | `scp: Claims.Archive`, `oid` = user, `azp` = host app id |
| 3 | `POST /claims/{id}/agent-analyze` | **Agent identity** (blueprint mints it) | No | Application | `roles: [Claims.Analyze.All]`, `oid` = agent identity, `azp` = agent identity app id, `xms_par_app_azp` = blueprint |
| 4 | `POST /claims/{id}/agent-analyze-as-user` | **Agent identity** (OBO) | Yes | Delegated | `scp: Claims.Analyze`, `oid` = user, `azp` = agent identity app id, `xms_par_app_azp` = blueprint |
| N1 | `POST /claims/{id}/archive-as-agent` | Agent identity | No | Application | **403**: agent holds `Claims.Analyze.All`, not `Claims.Archive.All` |
| N2 | `POST /claims/{id}/analyze-as-host` | Host application | No | Application | **403**: host holds `Claims.Archive.All`, not `Claims.Analyze.All` |

### What an agent identity is

- An **agent identity blueprint** is a special application object. It is the
  only agent object that **holds a credential** (secret, certificate, or a
  federated managed identity). One blueprint can create many agent identities.
- An **agent identity** is a special service principal created from a
  blueprint. It has **no credential of its own**. The blueprint acquires tokens
  *as* the agent identity (the SDK does this through a federated-credential
  exchange when you call `WithAgentIdentity`).
- The downstream API sees the **agent identity** as the caller (`azp`/`appid`
  and `oid`), not the blueprint and not the host application, so it can
  authorize and audit the agent separately. The blueprint appears only as the
  parent in `xms_par_app_azp`.
- Agent identities **cannot run an interactive consent prompt** (`AADSTS82014`).
  Their permissions are granted either **directly** (Graph or an admin-consent
  URL using the agent identity's client id) or **inherited** from the blueprint
  (admin consent on the blueprint principal *plus* an `inheritablePermissions`
  entry for the resource). Inherited grants are not visible on the agent
  identity in the portal; they only show up in the token.
- For an interactive agent (scenario 4) the incoming user token must have the
  **blueprint as its audience** (`api://<blueprint-id>/access_agent`). The host
  app then performs an on-behalf-of exchange with the blueprint's credential
  and `WithAgentIdentity`.

### Claims cheat sheet (what to read in a downstream token)

| Claim | Meaning | Host app, app-only | Agent, app-only | User via host app | User via agent |
| --- | --- | --- | --- | --- | --- |
| `aud` | the API being called | Claims API | Claims API | Claims API | Claims API |
| `azp` (v2) / `appid` (v1) | the actor / client | host app id | **agent identity app id** | host app id | **agent identity app id** |
| `oid` | the subject | host SP object id | agent identity object id | user object id | user object id |
| `idtyp` | subject type (optional claim) | `app` | `app` | absent/`user` | absent/`user` |
| `roles` | application permissions | `Claims.Archive.All` | `Claims.Analyze.All` | absent | absent |
| `scp` | delegated permissions | absent | absent | `Claims.Archive` | `Claims.Analyze` |
| `xms_par_app_azp` | parent blueprint of the actor | absent | **blueprint app id** | absent | **blueprint app id** |
| `xms_act_fct` / `xms_sub_fct` | actor / subject facets (`11` = agent identity, `13` = agent user account) | absent | `11` | absent | `11` |

The mock Claims API prints every one of these for each call and derives a
`callerKind` from them. Microsoft's guidance: use `azp`/`oid` for authorization
and audit, log `xms_par_app_azp`, and do not authorize on the parent id alone
(many agents share one blueprint).


## 2. App roles vs "Expose an API" (and where "API permissions" fits)

This is the part that is easy to get wrong because the portal splits it over
three blades on two different registrations.

| Portal blade | On which registration | Defines or consumes? | Permission kind | Token claim | Who can consent |
| --- | --- | --- | --- | --- | --- |
| **Expose an API** → *Add a scope* | the **resource** (POC Claims API) | defines | **Delegated** (scope) | `scp` | user, or admin for everyone |
| **App roles** → *Allowed member types = Applications* | the **resource** (POC Claims API) | defines | **Application** (app role) | `roles` | admin only |
| **API permissions** | the **client** (POC Claims Web) | consumes | either | | admin consent button |

Why the POC needs **both** kinds on the Claims API:

- Scenarios 2 and 4 have a user, so the Claims API must expose **scopes**.
- Scenarios 1 and 3 have no user. An app-only token for a resource that defines
  no app roles is still issued, but it carries **no `roles` claim at all**, so
  the API cannot authorize by permission (only by allow-listing `appid`). That is
  exactly what you see before step [4A](entra-setup.md#4a-poc-claims-api-the-resource) is done: a 403 whose token summary shows
  `tokenType: APP-ONLY (no roles claim ...)`. App roles are therefore required
  for the two autonomous scenarios, which are the heart of the agent story.

Naming: scopes and app roles are stored in one underlying collection, and an
entry with the same id in both merges into a single definition. Follow
Microsoft's own convention and keep the names distinct:

| Operation | Delegated scope (user present) | Application app role (no user) |
| --- | --- | --- |
| Archive a claim | `Claims.Archive` | `Claims.Archive.All` |
| Analyze a claim / read evidence | `Claims.Analyze` | `Claims.Analyze.All` |

How a client gets them:

| Client | Delegated scope | Application app role |
| --- | --- | --- |
| Normal App Registration (host app) | API permissions → Delegated → grant admin consent (creates an `oauth2PermissionGrant`) | API permissions → Application → grant admin consent (creates an `appRoleAssignment`) |
| Agent identity, **direct** | Graph `oauth2PermissionGrants` with `clientId` = agent identity, or admin-consent URL with `client_id=<agent identity app id>&scope=...` | Graph `appRoleAssignments` on the agent identity SP, or admin-consent URL with `role=...` |
| Agent identity, **inherited** | admin consent on the blueprint principal + blueprint `inheritablePermissions` (`inheritableScopes: allAllowed`) | same, with `inheritableRoles: allAllowed` |


## 3. Identity inventory and naming

Display names can be changed in Entra without changing any id. The names below
make it obvious which permissions belong to the application runtime and which
belong to the agent.

| Object | Suggested display name | Type | App (client) id | Object id |
| --- | --- | --- | --- | --- |
| Downstream resource | **POC Claims API** | App Registration | `{Client API GUID}` | `{Object API GUID}` |
| Host application | **POC Claims Web** | App Registration | `{Host App Client GUID}` | `{Host App Object GUID}` (SP) |
| Agent blueprint | **POC Claims Analysis Agent Blueprint** | Agent identity blueprint | `{Agent Blueprint Client GUID}` | (same as app id); blueprint **principal** object id `{Agent Blueprint Principal GUID}` |
| Agent | **POC Claims Analysis Agent** | Agent identity | `{Agent Identity Client GUID}` | `{Agent Identity Client GUID}` |
| MCP server ([section 8](mcp-server.md)) | **POC Claims MCP Server** | App Registration | printed by `Configure/Configure-McpEntra.ps1` | (SP) printed by the script |

Tenant id: `{Agent Tenant ID}`.

### Who holds what

| Permission on POC Claims API | Host app (`POC Claims Web`) | Agent identity (`POC Claims Analysis Agent`) |
| --- | --- | --- |
| `Claims.Archive` (delegated) | scenario 2 | |
| `Claims.Archive.All` (application) | scenario 1 | |
| `Claims.Analyze` (delegated) | | scenario 4 |
| `Claims.Analyze.All` (application) | | scenario 3 |

Plus two delegated scopes that are **not** on the Claims API:

| Scope | Exposed by | Granted to | Used for |
| --- | --- | --- | --- |
| `api://<host-app-id>/access_as_user` | host app | host app (token to self) | incoming token for scenario 2 |
| `api://<blueprint-id>/access_agent` | blueprint | host app | incoming token for scenario 4 |
