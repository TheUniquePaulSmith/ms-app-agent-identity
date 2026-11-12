using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.AI;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;

// ============================================================================
// POC: Agent Identity vs Application Identity calling a downstream API.
//
// Three Entra identities are configured (see appsettings.sample.json and README.md):
//   HostApplication  - the App Registration this web app runs as
//   AgentBlueprint   - holds the credential that mints tokens AS the agent
//   AgentIdentity    - the agent service principal the Claims API sees as caller
//
// Scheme names double as the names of the token-acquisition options, so
// "Bearer" = HostApplication credentials, "AgentBlueprint" = blueprint credentials.
// ============================================================================

const string AgentBlueprintScheme = "AgentBlueprint";

var builder = WebApplication.CreateBuilder(args);

var hostSection = builder.Configuration.GetSection("HostApplication");
var blueprintSection = builder.Configuration.GetSection("AgentBlueprint");

var hostApiScope = hostSection["ApiScope"]
    ?? throw new InvalidOperationException("HostApplication:ApiScope is missing.");
var agentApiScope = blueprintSection["ApiScope"]
    ?? throw new InvalidOperationException("AgentBlueprint:ApiScope is missing.");

var hostScopeName = hostApiScope.Split('/').Last();
var agentScopeName = agentApiScope.Split('/').Last();

// ---------------------------------------------------------------------------
// Authentication: one browser sign-in + two bearer schemes
// ---------------------------------------------------------------------------

var authentication = builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
});

// Browser sign-in as the host application. Only used by /auth/token to mint
// the two user tokens the PowerShell script pastes back in.
authentication
    .AddMicrosoftIdentityWebApp(
        hostSection,
        openIdConnectScheme: OpenIdConnectDefaults.AuthenticationScheme,
        cookieScheme: CookieAuthenticationDefaults.AuthenticationScheme)
    .EnableTokenAcquisitionToCallDownstreamApi(initialScopes: [hostApiScope])
    .AddInMemoryTokenCaches();

// Bearer scheme "Bearer": incoming tokens whose audience is the HOST APPLICATION.
// Also registers the host application credentials for app-only and OBO calls.
authentication
    .AddMicrosoftIdentityWebApi(hostSection, jwtBearerScheme: JwtBearerDefaults.AuthenticationScheme)
    .EnableTokenAcquisitionToCallDownstreamApi()
    .AddInMemoryTokenCaches();

// Bearer scheme "AgentBlueprint": incoming tokens whose audience is the BLUEPRINT
// (api://<blueprint>/access_agent). Also registers the blueprint credentials,
// which WithAgentIdentity(...) uses to mint tokens as the agent identity.
authentication
    .AddMicrosoftIdentityWebApi(blueprintSection, jwtBearerScheme: AgentBlueprintScheme)
    .EnableTokenAcquisitionToCallDownstreamApi()
    .AddInMemoryTokenCaches();

// ---------------------------------------------------------------------------
// Authorization policies
// ---------------------------------------------------------------------------

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("InteractiveUser", policy => policy
        .AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser());

    options.AddPolicy("HostBearerWithScope", policy => policy
        .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .RequireAssertion(context => HasScope(context.User, hostScopeName)));

    options.AddPolicy("AgentBearerWithScope", policy => policy
        .AddAuthenticationSchemes(AgentBlueprintScheme)
        .RequireAuthenticatedUser()
        .RequireAssertion(context => HasScope(context.User, agentScopeName)));

    options.AddPolicy("AnyBearer", policy => policy
        .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme, AgentBlueprintScheme)
        .RequireAuthenticatedUser());
});

// ---------------------------------------------------------------------------
// Token acquisition, agent identities, downstream API, app services
// ---------------------------------------------------------------------------

builder.Services.AddHttpClient();
builder.Services.AddAgentIdentities();
builder.Services.AddDownstreamApis(builder.Configuration.GetSection("DownstreamApis"));

builder.Services.AddScoped<HostApplicationService>();
builder.Services.AddScoped<AgentRuntimeService>();
builder.Services.AddScoped<AgentLoopService>();
builder.Services.AddHttpClient("claims-mcp");
builder.Services.AddHttpClient("llm-probe");
builder.Services.AddHttpClient("gateway-admin");

var app = builder.Build();

// The browser UI lives in wwwroot (index.html is served at "/").
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// ---------------------------------------------------------------------------
// Info
// ---------------------------------------------------------------------------

app.MapGet("/api/info", () => Results.Ok(new
{
    application = "POC Claims Web (host application)",
    start = "/auth/sign-in then /auth/token, then run Tests/Invoke-ClaimsIdentityTests.ps1",
    scenarios = new[]
    {
        new { scenario = "1", endpoint = "POST /claims/{id}/archive", actor = "host application", user = false, claim = "roles: Claims.Archive.All" },
        new { scenario = "2", endpoint = "POST /claims/{id}/archive-as-user", actor = "host application", user = true, claim = "scp: Claims.Archive" },
        new { scenario = "3", endpoint = "POST /claims/{id}/agent-analyze", actor = "agent identity", user = false, claim = "roles: Claims.Analyze.All" },
        new { scenario = "4", endpoint = "POST /claims/{id}/agent-analyze-as-user", actor = "agent identity", user = true, claim = "scp: Claims.Analyze" },
        new { scenario = "negative", endpoint = "POST /claims/{id}/archive-as-agent", actor = "agent identity", user = false, claim = "expects 403: agent lacks Claims.Archive.All" },
        new { scenario = "negative", endpoint = "POST /claims/{id}/analyze-as-host", actor = "host application", user = false, claim = "expects 403: host lacks Claims.Analyze.All" }
    }
}));

// ---------------------------------------------------------------------------
// Browser sign-in and POC-only token endpoint
// ---------------------------------------------------------------------------

app.MapGet("/auth/sign-in", (string? returnUrl) => Results.Challenge(
    new AuthenticationProperties { RedirectUri = string.IsNullOrEmpty(returnUrl) ? "/" : returnUrl },
    [OpenIdConnectDefaults.AuthenticationScheme]));

app.MapGet("/auth/sign-out", () => Results.SignOut(
    new AuthenticationProperties { RedirectUri = "/" },
    [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));

app.MapGet("/auth/me", (HttpContext httpContext) => Results.Ok(DescribeUser(httpContext.User)))
    .RequireAuthorization("InteractiveUser");

// Anonymous: lets the UI know whether the browser session is signed in
// without triggering a challenge redirect.
app.MapGet("/api/session", (HttpContext httpContext) => Results.Ok(new
{
    signedIn = httpContext.User.Identity?.IsAuthenticated ?? false,
    user = DescribeUser(httpContext.User),
    hostApplicationClientId = hostSection["ClientId"],
    agentBlueprintClientId = blueprintSection["ClientId"],
    agentIdentityClientId = builder.Configuration["AgentIdentity:ClientId"],
    claimsApiScope = builder.Configuration["DownstreamApis:ClaimsApiAsAgent:Scopes:0"],
    mcpEndpoint = builder.Configuration["McpServer:Endpoint"],
    mcpClientId = builder.Configuration["McpServer:ClientId"],
    mcpScope = builder.Configuration["McpServer:Scope"] is { Length: > 0 } mcpScope
        ? mcpScope
        : $"api://{builder.Configuration["McpServer:ClientId"]}/.default",
    llmDefaults = new { baseUrl = builder.Configuration["Llm:BaseUrl"], model = builder.Configuration["Llm:Model"] }
}));

// Returns two user access tokens for the signed-in browser user. POC only;
// never expose bearer tokens through a browser endpoint in a real application.
//   hostToken  : audience = host application  -> scenario 2
//   agentToken : audience = agent blueprint   -> scenario 4
app.MapGet("/auth/token", async (HttpContext httpContext, ITokenAcquisition tokenAcquisition) =>
{
    var hostToken = await tokenAcquisition.GetAccessTokenForUserAsync(
        [hostApiScope],
        authenticationScheme: OpenIdConnectDefaults.AuthenticationScheme,
        user: httpContext.User);

    string? agentToken = null;
    string? agentTokenError = null;
    try
    {
        agentToken = await tokenAcquisition.GetAccessTokenForUserAsync(
            [agentApiScope],
            authenticationScheme: OpenIdConnectDefaults.AuthenticationScheme,
            user: httpContext.User);
    }
    catch (Exception ex) when (ex is MsalException or MicrosoftIdentityWebChallengeUserException)
    {
        // Keep the page working so hostToken is still usable for scenario 2.
        var hint = ex.Message.Contains("AADSTS500011")
            ? "The blueprint has no Application ID URI / access_agent scope yet (docs/entra-setup.md 4C step 3)."
            : ex.Message.Contains("AADSTS65001") || ex is MsalUiRequiredException
                ? "The host application has not been granted access_agent on the blueprint (docs/entra-setup.md 4B; admin consent URL below)."
                : "See docs/troubleshooting.md.";
        agentTokenError = $"Could not get a token for {agentApiScope}. {hint} Error: {ex.Message}";
    }

    var tenantId = httpContext.User.FindFirst("tid")?.Value ?? "<tenant-id>";
    var hostClientId = hostSection["ClientId"];

    return Results.Ok(new
    {
        user = DescribeUser(httpContext.User),
        hostToken = new { scope = hostApiScope, accessToken = hostToken },
        agentToken = new { scope = agentApiScope, accessToken = agentToken, error = agentTokenError },
        adminConsentUrlForAgentScope =
            $"https://login.microsoftonline.com/{tenantId}/v2.0/adminconsent?client_id={hostClientId}&scope={Uri.EscapeDataString(agentApiScope)}",
        powerShell = agentToken is null
            ? $".\\Tests\\Invoke-ClaimsIdentityTests.ps1 -HostToken '{hostToken}'"
            : $".\\Tests\\Invoke-ClaimsIdentityTests.ps1 -HostToken '{hostToken}' -AgentToken '{agentToken}'"
    });
}).RequireAuthorization("InteractiveUser");

// Inspect any pasted bearer token (either audience).
app.MapGet("/auth/bearer-claims", (HttpContext httpContext) => Results.Ok(new
{
    user = DescribeUser(httpContext.User),
    claims = httpContext.User.Claims
        .Select(claim => new { claim.Type, claim.Value })
        .OrderBy(claim => claim.Type)
        .ToArray()
})).RequireAuthorization("AnyBearer");

// ---------------------------------------------------------------------------
// Scenario 1: HOST APPLICATION + APPLICATION permission (no user)
// ---------------------------------------------------------------------------
app.MapPost("/claims/{claimId}/archive", async (string claimId, HostApplicationService host) =>
    ScenarioResult(
        scenario: "1. Host application + application permission",
        claimId, actor: "host-application", mode: "application",
        requiredPermission: "Claims.Archive.All",
        result: await host.ArchiveAsAppAsync(claimId)));

// ---------------------------------------------------------------------------
// Scenario 2: HOST APPLICATION + USER-DELEGATED permission (OBO)
// ---------------------------------------------------------------------------
app.MapPost("/claims/{claimId}/archive-as-user", async (string claimId, HttpContext httpContext, HostApplicationService host) =>
    ScenarioResult(
        scenario: "2. Host application + user-delegated permission",
        claimId, actor: "host-application", mode: "delegated",
        requiredPermission: "Claims.Archive",
        result: await host.ArchiveAsUserAsync(claimId),
        incomingUser: DescribeUser(httpContext.User)))
    .RequireAuthorization("HostBearerWithScope");

// ---------------------------------------------------------------------------
// Scenario 3: AGENT IDENTITY + APPLICATION permission (autonomous agent)
// ---------------------------------------------------------------------------
app.MapPost("/claims/{claimId}/agent-analyze", async (string claimId, AgentRuntimeService agent) =>
    ScenarioResult(
        scenario: "3. Agent identity + application permission",
        claimId, actor: $"agent-identity {agent.AgentIdentityClientId}", mode: "application",
        requiredPermission: "Claims.Analyze.All",
        result: await agent.AnalyzeAsAppAsync(claimId)));

// ---------------------------------------------------------------------------
// Scenario 4: AGENT IDENTITY + USER-DELEGATED permission (interactive agent)
// Incoming token audience must be the blueprint (api://<blueprint>/access_agent).
// ---------------------------------------------------------------------------
app.MapPost("/claims/{claimId}/agent-analyze-as-user", async (string claimId, HttpContext httpContext, AgentRuntimeService agent) =>
    ScenarioResult(
        scenario: "4. Agent identity + user-delegated permission",
        claimId, actor: $"agent-identity {agent.AgentIdentityClientId}", mode: "delegated",
        requiredPermission: "Claims.Analyze",
        result: await agent.AnalyzeAsUserAsync(claimId),
        incomingUser: DescribeUser(httpContext.User)))
    .RequireAuthorization("AgentBearerWithScope");

// ---------------------------------------------------------------------------
// Negative demos: the Claims API tells the two actors apart
// ---------------------------------------------------------------------------
app.MapPost("/claims/{claimId}/archive-as-agent", async (string claimId, AgentRuntimeService agent) =>
    ScenarioResult(
        scenario: "Negative: agent identity tries Claims.Archive.All (expect 403)",
        claimId, actor: $"agent-identity {agent.AgentIdentityClientId}", mode: "application",
        requiredPermission: "Claims.Archive.All",
        result: await agent.ArchiveAsAppAsync(claimId)));

app.MapPost("/claims/{claimId}/analyze-as-host", async (string claimId, HostApplicationService host) =>
    ScenarioResult(
        scenario: "Negative: host application tries Claims.Analyze.All (expect 403)",
        claimId, actor: "host-application", mode: "application",
        requiredPermission: "Claims.Analyze.All",
        result: await host.AnalyzeAsAppAsync(claimId)));

// ===========================================================================
// AGENT RUNTIME LOOP (LLM + MCP). The identity is chosen by the route, never
// by the model:
//   /chat/host-app    host application, app-only       (what NOT to do for agents)
//   /chat/agent-app   agent identity, app-only         autonomous agent
//   /chat/host-user   host application on behalf of user
//   /chat/agent-user  agent identity on behalf of user interactive agent
// ===========================================================================

app.MapPost("/chat/host-app", (ChatRequest request, HttpContext httpContext, AgentLoopService loop) =>
    RunChatAsync(IdentityMode.HostApp, request, httpContext, loop));

app.MapPost("/chat/agent-app", (ChatRequest request, HttpContext httpContext, AgentLoopService loop) =>
    RunChatAsync(IdentityMode.AgentApp, request, httpContext, loop));

app.MapPost("/chat/host-user", (ChatRequest request, HttpContext httpContext, AgentLoopService loop) =>
    RunChatAsync(IdentityMode.HostUser, request, httpContext, loop))
    .RequireAuthorization("HostBearerWithScope");

app.MapPost("/chat/agent-user", (ChatRequest request, HttpContext httpContext, AgentLoopService loop) =>
    RunChatAsync(IdentityMode.AgentUser, request, httpContext, loop))
    .RequireAuthorization("AgentBearerWithScope");

app.MapDelete("/chat/{conversationId}", (string conversationId) =>
{
    AgentLoopService.ResetConversation(conversationId);
    return Results.NoContent();
});

// Tools the MCP server offers, discovered with an app-only token (audience: MCP server) of the chosen actor.
app.MapGet("/api/mcp/tools", async (string? mode, HttpContext httpContext, AgentLoopService loop) =>
{
    var identityMode = mode?.ToLowerInvariant() == "host-app" ? IdentityMode.HostApp : IdentityMode.AgentApp;
    try
    {
        var tools = await loop.ListToolsAsync(identityMode, null, httpContext.RequestAborted);
        return Results.Ok(new { endpoint = loop.McpEndpoint, identity = AgentLoopService.Describe(identityMode).Actor, tools });
    }
    catch (Exception ex)
    {
        return Results.Json(new { endpoint = loop.McpEndpoint, error = ex.Message }, statusCode: 502);
    }
});

// LLM connection helpers for the UI (proxied so the browser avoids CORS).
app.MapGet("/api/llm/models", async (string? baseUrl, string? apiKey, IHttpClientFactory httpClientFactory, AgentLoopService loop) =>
{
    var llm = loop.ResolveLlm(new LlmConnection(baseUrl, apiKey, null));
    try
    {
        var http = httpClientFactory.CreateClient("llm-probe");
        http.Timeout = TimeSpan.FromSeconds(10);
        using var request = new HttpRequestMessage(HttpMethod.Get, llm.BaseUrl!.TrimEnd('/') + "/models");
        if (!string.IsNullOrWhiteSpace(llm.ApiKey) && llm.ApiKey != "not-needed")
        {
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", llm.ApiKey);
        }
        using var response = await http.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        var models = new List<string>();
        try
        {
            using var document = System.Text.Json.JsonDocument.Parse(body);
            if (document.RootElement.TryGetProperty("data", out var data))
            {
                models.AddRange(data.EnumerateArray().Select(m => m.GetProperty("id").GetString() ?? ""));
            }
        }
        catch (System.Text.Json.JsonException) { }

        return Results.Json(new { baseUrl = llm.BaseUrl, status = (int)response.StatusCode, models, raw = models.Count == 0 ? body : null },
            statusCode: response.IsSuccessStatusCode ? 200 : 502);
    }
    catch (Exception ex)
    {
        return Results.Json(new { baseUrl = llm.BaseUrl, error = ex.Message }, statusCode: 502);
    }
});

app.MapPost("/api/llm/test", async (LlmConnection? connection, AgentLoopService loop) =>
{
    var llm = loop.ResolveLlm(connection);
    try
    {
        var chat = AgentLoopService.CreateChatClient(llm);
        var observed = false;
        var tool = AIFunctionFactory.Create(
            () => { observed = true; return DateTime.UtcNow.ToString("O"); },
            "get_server_time",
            "Returns the current server time in ISO 8601 format.");

        var options = new ChatOptions { Tools = [tool], ToolMode = ChatToolMode.Auto, Temperature = 0 };
        List<ChatMessage> messages =
        [
            new(ChatRole.System, "You are a connectivity probe. When asked for the time you must call the get_server_time tool."),
            new(ChatRole.User, "What time is it right now? Use the tool.")
        ];

        var first = await chat.GetResponseAsync(messages, options);
        var calls = first.Messages.SelectMany(m => m.Contents).OfType<FunctionCallContent>().ToList();
        string reply = first.Text;
        if (calls.Count > 0)
        {
            messages.AddRange(first.Messages);
            foreach (var call in calls)
            {
                var result = await tool.InvokeAsync(new AIFunctionArguments(call.Arguments));
                messages.Add(new ChatMessage(ChatRole.Tool, [new FunctionResultContent(call.CallId, result?.ToString())]));
            }
            var second = await chat.GetResponseAsync(messages, options);
            reply = second.Text;
        }

        return Results.Ok(new
        {
            ok = true,
            baseUrl = llm.BaseUrl,
            model = llm.Model,
            nativeToolCalling = observed,
            toolCallsRequested = calls.Select(c => c.Name).ToArray(),
            reply
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new { ok = false, baseUrl = llm.BaseUrl, model = llm.Model, error = ex.Message }, statusCode: 502);
    }
});

// "Local LLM & Gateway MCP" tab: same loop, MCP server behind API Management,
// a second agent identity, AuthZEN/Cedar PDP and kill switch (GatewayEndpoints.cs),
// and the PDP's entity registry in the storage account (PdpEntityEndpoints.cs).
app.MapGatewayEndpoints();
app.MapPdpEntityEndpoints();

app.Run();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static async Task<IResult> RunChatAsync(IdentityMode mode, ChatRequest request, HttpContext httpContext, AgentLoopService loop)
{
    if (string.IsNullOrWhiteSpace(request.Message))
    {
        return Results.BadRequest(new { error = "message is required" });
    }

    try
    {
        var result = await loop.RunTurnAsync(mode, request, httpContext.User, httpContext.RequestAborted);
        return Results.Ok(result);
    }
    catch (Exception ex)
    {
        var (actor, permissionKind) = AgentLoopService.Describe(mode);
        return Results.Json(new
        {
            identityMode = mode.ToString(),
            actor,
            permissionKind,
            error = ex.GetType().Name,
            message = ex.Message,
            inner = ex.InnerException?.Message
        }, statusCode: 500);
    }
}

static bool HasScope(ClaimsPrincipal user, string requiredScope) =>
    user.Claims
        .Where(claim => claim.Type is "scp" or "http://schemas.microsoft.com/identity/claims/scope")
        .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        .Contains(requiredScope, StringComparer.OrdinalIgnoreCase);

static object DescribeUser(ClaimsPrincipal user) => new
{
    authenticated = user.Identity?.IsAuthenticated ?? false,
    name = user.Identity?.Name ?? user.FindFirst("preferred_username")?.Value,
    objectId = user.FindFirst("oid")?.Value
        ?? user.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value,
    tenantId = user.FindFirst("tid")?.Value
        ?? user.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid")?.Value,
    audience = user.FindFirst("aud")?.Value,
    clientApplication = user.FindFirst("azp")?.Value ?? user.FindFirst("appid")?.Value,
    scopes = user.FindFirst("scp")?.Value ?? user.FindFirst("http://schemas.microsoft.com/identity/claims/scope")?.Value
};

static IResult ScenarioResult(
    string scenario,
    string claimId,
    string actor,
    string mode,
    string requiredPermission,
    DownstreamResult result,
    object? incomingUser = null) =>
    Results.Json(new
    {
        scenario,
        claimId,
        actor,
        authorizationMode = mode,
        permissionClaim = mode == "application" ? "roles" : "scp",
        requiredPermission,
        incomingUser,
        downstreamStatus = result.StatusCode,
        downstream = result.BodyForResponse
    }, statusCode: result.StatusCode);
