using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.Identity.Abstractions;

// ============================================================================
// "Local LLM & Gateway MCP" tab (docs/Proposal.md, layers 4 and 5).
//
// Same agent loop as /chat/*, but the MCP server is claims-mcp-azure behind
// Azure API Management, and the agent is one of the agent identities listed in
// GatewayAgentIdentities (all from the same blueprint; the request picks one with
// agentIdentityClientId, default GatewayMcp:AgentIdentityClientId). Every call is
// decided by the gateway, the MCP server and the Claims API, each asking the
// AuthZEN/Cedar PDP.
//
//   POST /gw/chat/{host-app|agent-app|host-user|agent-user}   agent loop via APIM
//   GET  /api/gw/info                                         configuration and agent list (no secrets)
//   GET  /api/gw/tools?mode=agent-app|host-app&agent=<id>     tools/list as filtered by the PDP
//   POST /api/gw/killswitch                                   kill / restore via the Logic App
//   GET  /api/gw/kills                                        kill list + audit (kill switch service)
//   GET  /api/gw/claims, POST /api/gw/claims/reset            Azure Table records (host app token)
//   GET  /api/gw/pdp/policies, POST /api/gw/pdp/evaluate      PDP playground (AuthZEN)
//   /api/gw/entities[/{kind}/{id}]                            PDP entity registry (PdpEntityEndpoints.cs)
// ============================================================================

public sealed record KillSwitchRequest(string Action, string Scope, string TargetId, string? Reason, bool DisableInEntra, string? BlueprintId, string? ExpiresAt);

public static class GatewayEndpoints
{
    public static void MapGatewayEndpoints(this WebApplication app)
    {
        var config = app.Configuration;
        string Setting(string key) => config[$"GatewayMcp:{key}"] ?? "";
        bool Configured(string key) => Setting(key) is { Length: > 0 } v && !v.StartsWith('<');

        app.MapPost("/gw/chat/host-app", (ChatRequest r, HttpContext c, AgentLoopService l) => RunAsync(IdentityMode.HostApp, r, c, l));
        app.MapPost("/gw/chat/agent-app", (ChatRequest r, HttpContext c, AgentLoopService l) => RunAsync(IdentityMode.AgentApp, r, c, l));
        app.MapPost("/gw/chat/host-user", (ChatRequest r, HttpContext c, AgentLoopService l) => RunAsync(IdentityMode.HostUser, r, c, l))
            .RequireAuthorization("HostBearerWithScope");
        app.MapPost("/gw/chat/agent-user", (ChatRequest r, HttpContext c, AgentLoopService l) => RunAsync(IdentityMode.AgentUser, r, c, l))
            .RequireAuthorization("AgentBearerWithScope");

        app.MapGet("/api/gw/info", (AgentLoopService loop) => Results.Ok(new
        {
            mcpEndpoint = Setting("Endpoint"),
            mcpScope = Configured("Scope") ? Setting("Scope") : config["McpServer:Scope"],
            gatewayAgentIdentityClientId = loop.GatewayAgents.FirstOrDefault(a => a.IsDefault)?.ClientId ?? Setting("AgentIdentityClientId"),
            agentIdentities = loop.GatewayAgents,
            localAgentIdentityClientId = config["AgentIdentity:ClientId"],
            blueprintClientId = config["AgentBlueprint:ClientId"],
            hostApplicationClientId = config["HostApplication:ClientId"],
            pdpUrl = Setting("PdpUrl"),
            killSwitchUrl = Setting("KillSwitchUrl"),
            claimsApiUrl = Setting("ClaimsApiUrl"),
            user1ObjectId = Configured("User1ObjectId") ? Setting("User1ObjectId") : null,
            user2ObjectId = Configured("User2ObjectId") ? Setting("User2ObjectId") : null,
            user3ObjectId = Configured("User3ObjectId") ? Setting("User3ObjectId") : null,
            killSwitchWorkflowConfigured = Configured("KillSwitchWorkflowUrl"),
            ready = new
            {
                endpoint = Configured("Endpoint"),
                agentIdentity = loop.GatewayAgents.Any(a => a.Configured),
                internalKey = Configured("InternalKey"),
                workflow = Configured("KillSwitchWorkflowUrl"),
                storage = Configured("StorageConnectionString")
            }
        }));

        app.MapGet("/api/gw/tools", async (string? mode, string? agent, HttpContext httpContext, AgentLoopService loop) =>
        {
            var identityMode = mode?.ToLowerInvariant() == "host-app" ? IdentityMode.HostApp : IdentityMode.AgentApp;
            try
            {
                var target = loop.GatewayTargetFor(agent);
                var tools = await loop.ListToolsAsync(identityMode, null, httpContext.RequestAborted, target);
                return Results.Ok(new
                {
                    endpoint = target.Endpoint,
                    identity = identityMode.ToString(),
                    agentIdentity = identityMode == IdentityMode.AgentApp ? target.AgentIdentityClientId : null,
                    note = "tools/list is filtered by the PDP (AuthZEN batch evaluation)",
                    tools
                });
            }
            catch (Exception ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: 502);
            }
        });

        // Kill / restore through the Logic App (publish CloudEvent, Entra backstop, confirm kill list).
        app.MapPost("/api/gw/killswitch", async (KillSwitchRequest request, HttpContext httpContext, IHttpClientFactory factory) =>
        {
            if (!Configured("KillSwitchWorkflowUrl"))
                return Results.Json(new { error = "GatewayMcp:KillSwitchWorkflowUrl is not set (run Configure/Deploy-GatewayPoc.ps1)." }, statusCode: 400);

            var user = httpContext.User.Identity?.IsAuthenticated == true
                ? httpContext.User.FindFirst("preferred_username")?.Value ?? httpContext.User.Identity?.Name
                : null;
            var payload = new
            {
                action = request.Action,
                scope = request.Scope,
                targetId = request.TargetId,
                blueprintId = request.BlueprintId,
                reason = string.IsNullOrWhiteSpace(request.Reason) ? "POC demo" : request.Reason,
                requestedBy = user ?? "poc-web (not signed in)",
                disableInEntra = request.DisableInEntra,
                expiresAt = string.IsNullOrWhiteSpace(request.ExpiresAt) ? null : request.ExpiresAt
            };
            var http = factory.CreateClient("gateway-admin");
            http.Timeout = TimeSpan.FromSeconds(100);
            var watch = Stopwatch.StartNew();
            using var response = await http.PostAsync(Setting("KillSwitchWorkflowUrl"),
                new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"), httpContext.RequestAborted);
            var body = await response.Content.ReadAsStringAsync();
            return Results.Json(new { status = (int)response.StatusCode, elapsedMs = watch.ElapsedMilliseconds, sent = payload, workflow = ParseOrRaw(body) },
                statusCode: response.IsSuccessStatusCode ? 200 : 502);
        });

        app.MapGet("/api/gw/kills", async (IHttpClientFactory factory, CancellationToken ct) =>
        {
            var kills = await InternalGetAsync(factory, $"{Setting("KillSwitchUrl")}/kills", ct);
            var audit = await InternalGetAsync(factory, $"{Setting("KillSwitchUrl")}/audit?top=25", ct);
            return Results.Ok(new { kills, audit });
        });

        app.MapGet("/api/gw/pdp/policies", async (IHttpClientFactory factory, CancellationToken ct) =>
            Results.Ok(await InternalGetAsync(factory, $"{Setting("PdpUrl")}/policies", ct)));

        app.MapPost("/api/gw/pdp/evaluate", async (JsonElement request, IHttpClientFactory factory, CancellationToken ct) =>
        {
            var path = request.TryGetProperty("evaluations", out _) ? "/access/v1/evaluations" : "/access/v1/evaluation";
            var http = factory.CreateClient("gateway-admin");
            using var message = new HttpRequestMessage(HttpMethod.Post, Setting("PdpUrl") + path)
            {
                Content = new StringContent(request.GetRawText(), Encoding.UTF8, "application/json")
            };
            message.Headers.Add("x-pdp-key", Setting("InternalKey"));
            using var response = await http.SendAsync(message, ct);
            return Results.Json(new { status = (int)response.StatusCode, endpoint = path, result = ParseOrRaw(await response.Content.ReadAsStringAsync(ct)) });
        });

        // Claim records in the Azure Table, read through the hosted Claims API with the
        // host application's app-only token (the list route needs a valid token, no PDP).
        app.MapGet("/api/gw/claims", (HttpContext c, IAuthorizationHeaderProvider headers, IHttpClientFactory factory) =>
            ClaimsApiAsync(HttpMethod.Get, "/claims", c, headers, factory));
        app.MapPost("/api/gw/claims/reset", (HttpContext c, IAuthorizationHeaderProvider headers, IHttpClientFactory factory) =>
            ClaimsApiAsync(HttpMethod.Post, "/admin/reset", c, headers, factory));

        async Task<IResult> ClaimsApiAsync(HttpMethod method, string path, HttpContext httpContext, IAuthorizationHeaderProvider headers, IHttpClientFactory factory)
        {
            try
            {
                var options = new AuthorizationHeaderProviderOptions();
                options.AcquireTokenOptions.AuthenticationOptionsName = "Bearer";
                var scope = config["DownstreamApis:ClaimsApiAsHostApplication:Scopes:0"]!;
                var header = await headers.CreateAuthorizationHeaderForAppAsync(scope, options, httpContext.RequestAborted);
                var http = factory.CreateClient("gateway-admin");
                using var message = new HttpRequestMessage(method, Setting("ClaimsApiUrl") + path);
                message.Headers.Authorization = AuthenticationHeaderValue.Parse(header);
                if (method == HttpMethod.Post) message.Content = new StringContent("{}", Encoding.UTF8, "application/json");
                using var response = await http.SendAsync(message, httpContext.RequestAborted);
                return Results.Json(ParseOrRaw(await response.Content.ReadAsStringAsync()), statusCode: (int)response.StatusCode);
            }
            catch (Exception ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: 502);
            }
        }

        async Task<object?> InternalGetAsync(IHttpClientFactory factory, string url, CancellationToken ct)
        {
            try
            {
                var http = factory.CreateClient("gateway-admin");
                using var message = new HttpRequestMessage(HttpMethod.Get, url);
                message.Headers.Add("x-pdp-key", Setting("InternalKey"));
                using var response = await http.SendAsync(message, ct);
                return ParseOrRaw(await response.Content.ReadAsStringAsync(ct));
            }
            catch (Exception ex)
            {
                return new { error = ex.Message, url };
            }
        }
    }

    private static async Task<IResult> RunAsync(IdentityMode mode, ChatRequest request, HttpContext httpContext, AgentLoopService loop)
    {
        if (string.IsNullOrWhiteSpace(request.Message))
        {
            return Results.BadRequest(new { error = "message is required" });
        }

        try
        {
            var result = await loop.RunTurnAsync(mode, request, httpContext.User, httpContext.RequestAborted, loop.GatewayTargetFor(request.AgentIdentityClientId));
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

    private static object? ParseOrRaw(string text)
    {
        try
        {
            return JsonSerializer.Deserialize<JsonElement>(text);
        }
        catch (JsonException)
        {
            return new { raw = text };
        }
    }
}
