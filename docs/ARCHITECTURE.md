# Architecture

Diagrams for the Agent Identity vs Application Identity POC. See the [README](../README.md) for the
narrative, the Entra setup steps and the run instructions. All diagrams are Mermaid and render on
GitHub, in VS Code (Markdown preview with Mermaid support) and in most wikis.

Contents

1. [Solution components](#1-solution-components)
2. [Entra objects and their relationships](#2-entra-objects-and-their-relationships)
3. [Permission model: who holds what](#3-permission-model-who-holds-what)
4. [Application runtime flows (direct API calls)](#4-application-runtime-flows-direct-api-calls)
5. [Agent runtime loop (LLM + MCP)](#5-agent-runtime-loop-llm--mcp)
6. [Browser sign-in and token minting](#6-browser-sign-in-and-token-minting)
7. [Choosing the identity: decision flow](#7-choosing-the-identity-decision-flow)
8. [Code structure of the host application](#8-code-structure-of-the-host-application)

---

## 1. Solution components

Five local processes plus Microsoft Entra. Two processes hold credentials (the host application
for its two identities, the MCP server for its own); two places make authorization decisions (the
MCP server on `Mcp.*`, the Claims API on `Claims.*`).

```mermaid
flowchart LR
    subgraph Browser["Browser"]
        UI["Web UI<br/>wwwroot (Profile, LLM, Direct API, Agent chat)"]
        PS["PowerShell test script<br/>Tests/Invoke-ClaimsIdentityTests.ps1"]
    end

    subgraph Host["Host application :5094 (ASP.NET Core)"]
        AUTH["Authentication<br/>Cookie + OIDC (sign-in)<br/>Bearer = host audience<br/>AgentBlueprint = blueprint audience"]
        DIRECT["Direct endpoints<br/>/claims/{id}/..."]
        CHAT["Chat endpoints<br/>/chat/{mode}"]
        HS["HostApplicationService"]
        AS["AgentRuntimeService"]
        LOOP["AgentLoopService<br/>(model loop + trace)"]
        MIW["Microsoft.Identity.Web<br/>+ AgentIdentities<br/>credentials: host app, blueprint"]
    end

    MCP["MCP server :5002<br/>claims-mcp/server.mjs<br/>own App Registration<br/>validates aud = itself, authorizes Mcp.*,<br/>exchanges (OBO / client credentials)"]
    API["Mock Claims API :5001<br/>claims-api/server.js<br/>validates token (JWKS, iss, tid, aud, exp),<br/>enforces roles/scp"]
    LLM["LLM :8000<br/>vLLM (OpenAI-compatible)<br/>or fake-llm stand-in"]

    subgraph Entra["Microsoft Entra ID (tenant)"]
        STS["Token service<br/>login.microsoftonline.com"]
        REG["App registrations and agent objects<br/>(see section 2)"]
    end

    UI -->|cookie session, bearer tokens| DIRECT
    UI -->|bearer tokens| CHAT
    PS -->|bearer tokens| DIRECT
    DIRECT --> HS
    DIRECT --> AS
    CHAT --> LOOP
    HS --> MIW
    AS --> MIW
    LOOP --> MIW
    MIW <-->|client credentials, OBO,<br/>agent identity FIC exchange| STS
    STS -.-> REG
    HS -->|Claims API token| API
    AS -->|Claims API token| API
    LOOP -->|chat completion with tools| LLM
    LOOP -->|MCP tools/list, tools/call<br/>+ MCP server token| MCP
    MCP <-->|OBO or client credentials<br/>with the MCP server's secret| STS
    MCP -->|exchanged Claims API token| API
```

---

## 2. Entra objects and their relationships

The five Entra objects (three App Registrations, the blueprint and the agent identity), what each
one owns, and how grants attach to them. Note the two object kinds that often get confused: the
blueprint **application** (app id = object id) and the blueprint **principal** (a service principal
with its own object id).

```mermaid
erDiagram
    TENANT ||--o{ APP_REGISTRATION : contains
    TENANT ||--o{ SERVICE_PRINCIPAL : contains
    TENANT ||--o{ AGENT_BLUEPRINT : contains
    TENANT ||--o{ USER : contains

    APP_REGISTRATION ||--|| SERVICE_PRINCIPAL : "is represented by"
    APP_REGISTRATION ||--o{ DELEGATED_SCOPE : "exposes (Expose an API)"
    APP_REGISTRATION ||--o{ APP_ROLE : "defines (App roles, member type Applications)"

    AGENT_BLUEPRINT ||--|| BLUEPRINT_PRINCIPAL : "is represented by"
    AGENT_BLUEPRINT ||--o{ AGENT_IDENTITY : "creates and mints tokens for"
    AGENT_BLUEPRINT ||--o{ CREDENTIAL : "holds (secret, certificate, FIC)"
    AGENT_BLUEPRINT ||--o{ DELEGATED_SCOPE : "exposes access_agent"
    AGENT_BLUEPRINT ||--o{ INHERITABLE_PERMISSION : "declares"

    SERVICE_PRINCIPAL ||--o{ APP_ROLE_ASSIGNMENT : "is principal of"
    SERVICE_PRINCIPAL ||--o{ OAUTH2_PERMISSION_GRANT : "is client of"
    AGENT_IDENTITY ||--o{ APP_ROLE_ASSIGNMENT : "is principal of (direct)"
    AGENT_IDENTITY ||--o{ OAUTH2_PERMISSION_GRANT : "is client of (direct)"
    BLUEPRINT_PRINCIPAL ||--o{ APP_ROLE_ASSIGNMENT : "is principal of (inherited by agents)"
    BLUEPRINT_PRINCIPAL ||--o{ OAUTH2_PERMISSION_GRANT : "is client of (inherited by agents)"

    APP_ROLE ||--o{ APP_ROLE_ASSIGNMENT : "is granted through"
    DELEGATED_SCOPE ||--o{ OAUTH2_PERMISSION_GRANT : "is granted through"
    USER ||--o{ OAUTH2_PERMISSION_GRANT : "is subject of (delegated)"

    APP_REGISTRATION {
        guid appId "client id"
        guid objectId
        string displayName "POC Claims API, POC Claims Web, POC Claims MCP Server"
        string identifierUri "api://appId"
        int requestedAccessTokenVersion "2"
    }
    SERVICE_PRINCIPAL {
        guid objectId "oid in app-only tokens"
        guid appId
    }
    AGENT_BLUEPRINT {
        guid appId "{blueprintId} (= object id)"
        string displayName "POC Claims Analysis Agent Blueprint"
        string identifierUri "api://{blueprintId}"
    }
    BLUEPRINT_PRINCIPAL {
        guid objectId "e1dd3704..."
        guid appId "{blueprintId}"
    }
    AGENT_IDENTITY {
        guid appId "{agentId} (= object id)"
        guid parentAppId "blueprint app id, xms_par_app_azp"
        string displayName "POC Claims Analysis Agent"
        string credentials "none"
    }
    CREDENTIAL {
        string type "ClientSecret in this POC"
    }
    DELEGATED_SCOPE {
        string value "Claims.Archive, Claims.Analyze, Mcp.Archive, Mcp.Analyze, access_as_user, access_agent"
        string tokenClaim "scp"
    }
    APP_ROLE {
        string value "Claims.Archive.All, Claims.Analyze.All, Mcp.Archive.All, Mcp.Analyze.All"
        string allowedMemberTypes "Application"
        string tokenClaim "roles"
    }
    APP_ROLE_ASSIGNMENT {
        guid principalId
        guid resourceId "Claims API or MCP server service principal"
        guid appRoleId
    }
    OAUTH2_PERMISSION_GRANT {
        guid clientId
        guid resourceId
        string consentType "AllPrincipals"
        string scope
    }
    INHERITABLE_PERMISSION {
        guid resourceAppId
        string inheritableScopes "allAllowed or none"
        string inheritableRoles "allAllowed or none"
    }
    USER {
        guid objectId "oid in delegated tokens"
        string upn
    }
```

Three facts the diagram encodes:

- A normal App Registration and an agent blueprint both have a service principal, but only the
  blueprint can **mint tokens for other principals** (its agent identities).
- An agent identity has **no credential**; the blueprint's credential is used on its behalf.
- Grants to an agent identity are either **direct** (rows on the agent identity) or
  **inherited** (rows on the blueprint principal **plus** an inheritable-permission declaration
  for that resource). Inherited grants are only visible in the token.
- The MCP server registration is **both a resource and a client**: it defines the `Mcp.*` scopes
  and app roles that the host app and the agent identity are granted, and its own service
  principal holds the `Claims.*` grants it uses when it exchanges tokens for the Claims API.

---

## 3. Permission model: who holds what

```mermaid
flowchart TB
    subgraph ClaimsAPI["POC Claims API (resource) defines"]
        S1["scope Claims.Archive<br/>(delegated, scp)"]
        S2["scope Claims.Analyze<br/>(delegated, scp)"]
        R1["app role Claims.Archive.All<br/>(application, roles)"]
        R2["app role Claims.Analyze.All<br/>(application, roles)"]
    end

    subgraph Blueprint["Agent blueprint exposes"]
        S4["scope access_agent<br/>(audience for scenario 4)"]
    end

    subgraph HostApp["Host app exposes"]
        S3["scope access_as_user<br/>(audience for scenario 2)"]
    end

    subgraph McpSrv["MCP server (resource) defines"]
        M1["scope Mcp.Archive (scp)"]
        M2["scope Mcp.Analyze (scp)"]
        M3["app role Mcp.Archive.All (roles)"]
        M4["app role Mcp.Analyze.All (roles)"]
    end

    HOST["Host application<br/>POC Claims Web<br/>(service principal)"]
    AGENT["Agent identity<br/>POC Claims Analysis Agent"]
    MCPSP["MCP server<br/>POC Claims MCP Server<br/>(service principal)"]

    HOST -->|"scenario 1"| R1
    HOST -->|"scenario 2 (delegated)"| S1
    HOST -->|"token to self"| S3
    HOST -->|"needed to call scenario 4"| S4
    AGENT -->|"scenario 3"| R2
    AGENT -->|"scenario 4 (delegated)"| S2

    HOST -->|"agent loop: host-app"| M3
    HOST -->|"agent loop: host-user"| M1
    AGENT -->|"agent loop: agent-app"| M4
    AGENT -->|"agent loop: agent-user"| M2
    MCPSP -->|"exchange, app-only"| R1
    MCPSP -->|"exchange, app-only"| R2
    MCPSP -->|"exchange, OBO"| S1
    MCPSP -->|"exchange, OBO"| S2

    HOST -. "never granted: negative test N2" .-> R2
    AGENT -. "never granted: negative test N1" .-> R1
    HOST -. "never granted" .-> M4
    AGENT -. "never granted" .-> M3
```

---

## 4. Application runtime flows (direct API calls)

Deterministic application code decides what to call and which identity to use. The four
sequences below are scenarios 1 to 4 of [Scenarios at a glance](scenarios.md).

### 4.1 Scenario 1: host application, application permission (no user)

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller (script or UI)
    participant H as Host app<br/>HostApplicationService
    participant E as Entra token service
    participant A as Claims API

    C->>H: POST /claims/{id}/archive (anonymous)
    H->>E: client_credentials<br/>client = host app + secret<br/>scope api://claims-api/.default
    E-->>H: access token<br/>aud = Claims API, azp = host app, oid = host SP,<br/>idtyp = app, roles = [Claims.Archive.All]
    H->>A: POST /api/claims/archive<br/>Authorization: Bearer token
    A->>A: roles contains Claims.Archive.All? yes
    A-->>H: 200 + tokenInfo (callerKind host-application app-only)
    H-->>C: 200 scenario result + downstream body
```

### 4.2 Scenario 2: host application on behalf of a signed-in user

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller with host token
    participant H as Host app<br/>Bearer scheme + HostApplicationService
    participant E as Entra token service
    participant A as Claims API

    C->>H: POST /claims/{id}/archive-as-user<br/>Bearer host token (aud = host app, scp = access_as_user)
    H->>H: validate token (aud, issuer, signature), policy requires scp access_as_user
    H->>E: on-behalf-of exchange<br/>client = host app + secret, assertion = incoming token,<br/>scope api://claims-api/.default
    E-->>H: access token<br/>aud = Claims API, azp = host app, oid = user,<br/>scp = Claims.Archive
    H->>A: POST /api/claims/archive<br/>Authorization: Bearer token
    A->>A: scp contains Claims.Archive? yes
    A-->>H: 200 + tokenInfo (user via host-application delegated)
    H-->>C: 200 scenario result + incoming user + downstream body
```

### 4.3 Scenario 3: agent identity, application permission (autonomous agent)

The blueprint's credential is used, but the token represents the agent identity.

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller (script or UI)
    participant H as Host app<br/>AgentRuntimeService
    participant W as Microsoft.Identity.Web<br/>AgentIdentities
    participant E as Entra token service
    participant A as Claims API

    C->>H: POST /claims/{id}/agent-analyze (anonymous)
    H->>W: CallApiForAppAsync("ClaimsApiAsAgent")<br/>options.WithAgentIdentity(agent client id)<br/>AuthenticationOptionsName = AgentBlueprint
    W->>E: client_credentials as blueprint (secret)<br/>for the agent identity (federated credential exchange)
    E-->>W: exchange token for blueprint
    W->>E: token request as agent identity<br/>assertion = exchange token, scope api://claims-api/.default
    E-->>W: access token<br/>aud = Claims API, azp = agent identity, oid = agent identity,<br/>idtyp = app, roles = [Claims.Analyze.All],<br/>xms_par_app_azp = blueprint (when emitted)
    W-->>H: token attached
    H->>A: POST /api/claims/analyze<br/>Authorization: Bearer token
    A->>A: roles contains Claims.Analyze.All? yes
    A-->>H: 200 + tokenInfo (agent-identity app-only)
    H-->>C: 200 scenario result + downstream body
```

### 4.4 Scenario 4: agent identity on behalf of a signed-in user (interactive agent)

The incoming token's audience must be the **blueprint**, not the host app.

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller with agent token
    participant H as Host app<br/>AgentBlueprint scheme + AgentRuntimeService
    participant W as Microsoft.Identity.Web<br/>AgentIdentities
    participant E as Entra token service
    participant A as Claims API

    C->>H: POST /claims/{id}/agent-analyze-as-user<br/>Bearer agent token (aud = blueprint, scp = access_agent)
    H->>H: validate with AgentBlueprint scheme,<br/>policy requires scp access_agent
    H->>W: CallApiForUserAsync("ClaimsApiAsAgent")<br/>WithAgentIdentity(agent client id)
    W->>E: on-behalf-of as blueprint (secret)<br/>assertion = incoming user token, for the agent identity
    E-->>W: access token<br/>aud = Claims API, azp = agent identity, oid = user,<br/>scp = Claims.Analyze, xms_par_app_azp = blueprint (when emitted)
    W-->>H: token attached
    H->>A: POST /api/claims/analyze<br/>Authorization: Bearer token
    A->>A: scp contains Claims.Analyze? yes
    A-->>H: 200 + tokenInfo (user via agent-identity delegated)
    H-->>C: 200 scenario result + incoming user + downstream body
```

### 4.5 Negative cases

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant H as Host app
    participant A as Claims API

    rect rgb(255, 243, 230)
        C->>H: POST /claims/{id}/archive-as-agent
        H->>A: POST /claims/archive as AGENT identity<br/>roles = [Claims.Analyze.All]
        A-->>H: 403 required Claims.Archive or Claims.Archive.All
        H-->>C: 403 (status propagated)
    end
    rect rgb(255, 243, 230)
        C->>H: POST /claims/{id}/analyze-as-host
        H->>A: POST /claims/analyze as HOST application<br/>roles = [Claims.Archive.All]
        A-->>H: 403 required Claims.Analyze or Claims.Analyze.All
        H-->>C: 403 (status propagated)
    end
```

---

## 5. Agent runtime loop (LLM + MCP)

The model proposes tool calls; the host application decides the identity **once per chat turn**
(fixed by the route), mints exactly one token **for the MCP server**, and every MCP call in that
turn carries it. The MCP server validates that token, enforces its own `Mcp.*` permissions per
tool, and exchanges it for a Claims API token with its own credential (on-behalf-of when a user is
present, client credentials otherwise). The inbound token is never forwarded; the Claims API sees
the MCP server as actor and makes a second allow/deny decision on `Claims.*`.

### 5.1 One chat turn

```mermaid
sequenceDiagram
    autonumber
    actor U as User (browser)
    participant UI as Web UI
    participant H as Host app<br/>/chat/{mode} + AgentLoopService
    participant E as Entra
    participant M as MCP server :5002
    participant A as Claims API :5001
    participant L as LLM (vLLM)

    U->>UI: "Analyze claim CLAIM-1001"
    UI->>H: POST /chat/agent-app {message, llm}<br/>(or /chat/agent-user with Bearer agent token)
    H->>H: IdentityMode = route (model never chooses)
    H->>E: mint ONE token for that identity, aud = MCP SERVER<br/>scope api://mcp/.default (client credentials or OBO,<br/>with or without WithAgentIdentity)
    E-->>H: access token (roles Mcp.* or scp Mcp.*)
    H->>M: initialize + tools/list<br/>Authorization: Bearer token
    M->>M: validate: signature, iss, tid, aud = MCP server, exp
    M-->>H: get_claim, get_claim_evidence, analyze_claim, archive_claim
    loop until the model answers without tool calls (max 8)
        H->>L: chat completion (messages + tool definitions)
        L-->>H: tool_calls: analyze_claim({claimId})
        H->>H: trace step: tool, args, identity, permission kind
        H->>M: tools/call analyze_claim<br/>Authorization: Bearer token
        M->>M: authorize on the inbound token:<br/>Mcp.Analyze or Mcp.Analyze.All? else 403 decidedBy mcp-server
        M->>E: exchange with the MCP server's secret:<br/>scp present -> on-behalf-of, else client credentials<br/>scope api://claims-api/.default
        E-->>M: Claims API token (azp = MCP server)
        M->>A: POST /claims/analyze<br/>Authorization: Bearer EXCHANGED token
        A->>A: enforce roles / scp
        A-->>M: 200 body + tokenInfo (or 403 + required)
        M-->>H: text result {httpStatus, decidedBy, mcpServer.saw, exchange, body}, isError on 4xx
        H->>H: trace step: decision ALLOW / DENY, who decided,<br/>claims the MCP server saw, claims the API saw
        H->>L: tool result message
        L-->>H: final answer (explains a 403 if one happened)
    end
    H-->>UI: {answer, trace[], transcript[], iterations}
    UI-->>U: chat bubble + trace panel
```

### 5.2 Where identity is decided versus where it is enforced

```mermaid
flowchart LR
    P["Model proposes<br/>tool call"] --> G{"Governance policy<br/>(optional, e.g. Agent Governance Toolkit)<br/>should this agent run this tool now?"}
    G -- deny --> X["Reject, tell the model"]
    G -- allow --> I["Host app selects identity<br/>IdentityMode from route"]
    I --> T["Mint token for that identity<br/>Microsoft.Identity.Web<br/>(WithAgentIdentity for agent modes)"]
    T --> MCPC["MCP client call<br/>Authorization: Bearer"]
    MCPC --> MCPS{"MCP server<br/>token issued for me?<br/>Mcp.* permission for this tool?"}
    MCPS -- 401 / 403 --> D
    MCPS -- allow --> X2["Exchange with the MCP server's credential<br/>OBO (user present) or client credentials"]
    X2 --> API{"Claims API<br/>can the MCP server (for this user) do this?<br/>roles / scp"}
    API -- 200 --> R["Result to model"]
    API -- 403 --> D["Denial + required permission<br/>to model and to the trace"]
```

Three independent controls answer three questions: the policy layer decides whether the agent
**should** act; the MCP server decides whether the **calling identity** may use this tool; the
Claims API decides whether the **MCP server** (on behalf of the user, when present) may call it.

### 5.3 Identity modes available to the loop

```mermaid
flowchart TB
    subgraph Modes["/chat/{mode}"]
        AA["agent-app<br/>agent identity, app-only<br/>autonomous agent<br/>token: roles"]
        AU["agent-user<br/>agent identity on behalf of user<br/>interactive agent<br/>needs Bearer agent token (aud = blueprint)<br/>token: scp + user oid"]
        HU["host-user<br/>host app on behalf of user<br/>needs Bearer host token (aud = host app)<br/>token: scp + user oid"]
        HA["host-app<br/>host app, app-only<br/>anti-pattern for agents<br/>token: roles"]
    end
    AA --> CA["MCP server sees azp = agent identity"]
    AU --> CA
    HU --> CH["MCP server sees azp = host application"]
    HA --> CH
    CA --> X["Claims API sees azp = MCP server<br/>(oid = user for the *-user modes)"]
    CH --> X
```

### 5.4 MCP server request pipeline

What `claims-mcp/server.mjs` does with every request. The inbound token is read, validated and
authorized here, and then set aside: the call to the Claims API uses a token the MCP server obtains
for itself.

```mermaid
flowchart TD
    REQ["HTTP request to /mcp"] --> HAS{"Authorization: Bearer present?"}
    HAS -- no --> C401["401 + WWW-Authenticate: Bearer<br/>resource_metadata = /.well-known/oauth-protected-resource<br/>scope = Mcp.Analyze Mcp.Archive"]
    HAS -- yes --> VAL{"jose.jwtVerify<br/>signature (tenant JWKS), iss = tenant v2.0,<br/>tid, aud = MCP client id, exp"}
    VAL -- fails --> C401B["401 invalid_token<br/>(names the token's aud and iss)"]
    VAL -- ok --> AUTHINFO["req.auth = validated claims<br/>one McpServer + transport per request (stateless)"]
    AUTHINFO --> METHOD{"JSON-RPC method"}
    METHOD -- "initialize, tools/list" --> LIST["any valid token:<br/>advertise 4 tools + claims://{claimId} resource"]
    METHOD -- "tools/call" --> PERM{"permission on the INBOUND token?<br/>get_claim: none<br/>analyze_claim, get_claim_evidence: Mcp.Analyze or Mcp.Analyze.All<br/>archive_claim: Mcp.Archive or Mcp.Archive.All"}
    PERM -- no --> DENY["tool result httpStatus 403<br/>decidedBy = mcp-server, isError<br/>inbound token never exchanged"]
    PERM -- yes --> KIND{"scp on the inbound token?"}
    KIND -- "yes (user present)" --> OBO["msal-node acquireTokenOnBehalfOf<br/>assertion = inbound token, client = MCP server secret<br/>scope api://claims-api/.default"]
    KIND -- "no (app-only)" --> CC["msal-node acquireTokenByClientCredential<br/>client = MCP server secret<br/>scope api://claims-api/.default"]
    OBO --> CALL["fetch Claims API with the NEW token<br/>aud = Claims API, azp = MCP server<br/>oid = user (OBO) or MCP server SP (client credentials)"]
    CC --> CALL
    CALL --> RES["tool result<br/>httpStatus, decidedBy = claims-api,<br/>mcpServer.saw, exchange, body"]
    OBO -. "AADSTS error" .-> XF["tool result httpStatus 502<br/>stage = token-exchange"]
    CC -. "AADSTS error" .-> XF
```

---

## 6. Browser sign-in and token minting

How the UI (and the PowerShell script) obtain the two user tokens used by the delegated
scenarios. This is a POC convenience: a real application never hands bearer tokens to a browser.

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant B as Browser (Web UI)
    participant H as Host app<br/>Cookie + OIDC
    participant E as Entra

    U->>B: click Sign in
    B->>H: GET /auth/sign-in?returnUrl=/
    H-->>B: 302 to Entra authorize<br/>client = host app, scope openid profile offline_access<br/>api://host-app/access_as_user
    B->>E: sign in, consent
    E-->>B: 302 /signin-oidc with auth code
    B->>H: GET /signin-oidc?code=...
    H->>E: redeem code (host app secret)
    E-->>H: id token, access token (aud host app), refresh token
    H-->>B: set session cookie, 302 /
    B->>H: GET /auth/token (cookie)
    H->>E: silent token for api://host-app/access_as_user (cache)
    H->>E: silent token for api://blueprint/access_agent (refresh token)
    E-->>H: two access tokens
    H-->>B: {hostToken, agentToken, powerShell line}
    Note over B: hostToken -> host-user calls<br/>agentToken -> agent-user calls
```

---

## 7. Choosing the identity: decision flow

The rule from Microsoft's guidance: the logical actor performing the operation selects the
identity, not where the code runs.

```mermaid
flowchart TD
    Q1{"Who decided this operation<br/>should happen?"}
    Q1 -- "Deterministic application code<br/>(workflow, business rule, UI action)" --> Q2{"Is a signed-in user present<br/>and should access stay within their authority?"}
    Q1 -- "An agent / model decision<br/>(tool call, autonomous task)" --> Q3{"Is a signed-in user present<br/>and should access stay within their authority?"}

    Q2 -- no --> S1["Host application<br/>+ application permission<br/>roles claim, oid = host SP<br/>scenario 1"]
    Q2 -- yes --> S2["Host application<br/>+ user-delegated permission<br/>scp claim, oid = user<br/>scenario 2"]
    Q3 -- no --> S3["Agent identity<br/>+ application permission<br/>roles claim, oid = agent identity<br/>scenario 3"]
    Q3 -- yes --> S4["Agent identity<br/>+ user-delegated permission<br/>scp claim, oid = user, azp = agent<br/>scenario 4"]

    S3 --> N1["Grant app roles directly to the agent identity<br/>or via blueprint inheritance"]
    S4 --> N2["Incoming token must have the blueprint as audience;<br/>delegated scopes granted to the agent identity"]
```

---

## 8. Code structure of the host application

```mermaid
classDiagram
    class Program {
        +AddMicrosoftIdentityWebApp(HostApplication) OIDC + Cookie
        +AddMicrosoftIdentityWebApi(HostApplication) scheme Bearer
        +AddMicrosoftIdentityWebApi(AgentBlueprint) scheme AgentBlueprint
        +AddAgentIdentities()
        +AddDownstreamApis(DownstreamApis)
        +Policies HostBearerWithScope, AgentBearerWithScope, AnyBearer, InteractiveUser
        +Endpoints /claims/.. /chat/.. /auth/.. /api/..
    }
    class HostApplicationService {
        -IDownstreamApi api
        +ArchiveAsAppAsync(claimId) DownstreamResult
        +ArchiveAsUserAsync(claimId) DownstreamResult
        +AnalyzeAsAppAsync(claimId) DownstreamResult
    }
    class AgentRuntimeService {
        -IDownstreamApi api
        -string agentIdentityClientId
        +AnalyzeAsAppAsync(claimId) DownstreamResult
        +AnalyzeAsUserAsync(claimId) DownstreamResult
        +ArchiveAsAppAsync(claimId) DownstreamResult
    }
    class AgentLoopService {
        -IAuthorizationHeaderProvider headers
        +string McpClientId
        +string McpScope
        +string McpEndpoint
        +AcquireMcpAuthorizationHeaderAsync(mode, user) string
        +ConnectMcpAsync(authorizationHeader) McpClient
        +ListToolsAsync(mode, user)
        +RunTurnAsync(mode, request, user) ChatTurnResult
    }
    class DownstreamResult {
        +int StatusCode
        +JsonElement Body
    }
    class ChatTurnResult {
        +string Answer
        +ToolCallTrace[] Trace
        +TranscriptEntry[] Transcript
    }
    class ToolCallTrace {
        +string Tool
        +string Identity
        +string Decision
        +string DecidedBy
        +JsonElement McpServerSaw
        +JsonElement Exchange
        +JsonElement TokenInfo
    }
    class DownstreamApisConfig {
        ClaimsApiAsHostApplication AuthenticationOptionsName = Bearer
        ClaimsApiAsAgent AuthenticationOptionsName = AgentBlueprint
    }
    class McpServerConfig {
        Endpoint = http://localhost:5002/mcp
        ClientId = MCP server app id
        Scope = optional, default api://ClientId/.default
    }

    Program --> HostApplicationService
    Program --> AgentRuntimeService
    Program --> AgentLoopService
    HostApplicationService --> DownstreamResult
    AgentRuntimeService --> DownstreamResult
    AgentLoopService --> ChatTurnResult
    ChatTurnResult --> ToolCallTrace
    HostApplicationService ..> DownstreamApisConfig : ClaimsApiAsHostApplication
    AgentRuntimeService ..> DownstreamApisConfig : ClaimsApiAsAgent
    AgentLoopService ..> McpServerConfig : endpoint + scope (audience = MCP server)
```

The identity selection lives in exactly two places: the `AuthenticationOptionsName` (which
credential mints the token: the direct services take it from `DownstreamApis` configuration, the
agent loop sets the scheme name itself from the `IdentityMode`) and `WithAgentIdentity(...)` (which
agent identity the token represents). Everything else is ordinary application code. The MCP server
(`claims-mcp/server.mjs`) has no identity choice to make: it validates, authorizes, and exchanges
with the one credential it owns.
