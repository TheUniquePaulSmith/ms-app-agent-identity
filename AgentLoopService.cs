using System.Collections.Concurrent;
using System.ClientModel;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.AI;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using OpenAI;

// ============================================================================
// The agent runtime loop.
//
//   model proposes a tool call
//     -> the dispatcher decides WHICH IDENTITY performs it (this is the
//        authorization boundary the POC is about)
//     -> a token is minted for that identity, audience = the MCP SERVER
//     -> the MCP server validates it, enforces its own Mcp.* permissions,
//        then exchanges it (OBO or client credentials) for a Claims API token
//     -> the Claims API enforces roles / scp on the exchanged token
//     -> the result (both hops' decisions and claims) goes back to the model
//
// The identity is chosen per chat turn (IdentityMode), never by the model.
// ============================================================================

public enum IdentityMode
{
    HostApp,    // host application, app-only          (roles)
    AgentApp,   // agent identity, app-only            (roles)   <- autonomous agent
    HostUser,   // host application on behalf of user  (scp)
    AgentUser   // agent identity on behalf of user    (scp)     <- interactive agent
}

public sealed record LlmConnection(string? BaseUrl, string? ApiKey, string? Model);

// AgentIdentityClientId: gateway tab only, selects one of GatewayAgentIdentities.
public sealed record ChatRequest(string? ConversationId, string Message, LlmConnection? Llm, string? AgentIdentityClientId = null);

public sealed record ToolCallTrace(
    int Step,
    string Tool,
    JsonElement? Arguments,
    string Identity,
    string PermissionKind,
    int? DownstreamStatus,
    string Decision,
    JsonElement? TokenInfo,
    string? DecidedBy,
    JsonElement? McpServerSaw,
    JsonElement? Exchange,
    string ResultPreview,
    // Gateway scenario only (null for the local MCP server): which enforcement
    // point decided, and what the gateway and the PDP said at each hop.
    string? Pep = null,
    JsonElement? Gateway = null,
    JsonElement? Authzen = null,
    JsonElement? DownstreamAuthzen = null,
    JsonElement? KillList = null);

// Which MCP server a chat turn talks to, and which agent identity acts there.
//   local   : claims-mcp on localhost (the original agent identity)
//   gateway : claims-mcp-azure behind API Management (a second agent identity
//             from the same blueprint, governed by the PDP and the kill switch)
public sealed record McpTarget(string Name, string Endpoint, string Scope, string AgentIdentityClientId, bool ViaGateway);

// One selectable agent identity on the gateway tab (appsettings.json GatewayAgentIdentities).
public sealed record GatewayAgent(string Name, string ClientId, string? Note, bool Configured, bool IsDefault);

// Remembers the last refusal the API Management gateway answered with
// (decidedBy = "gateway"), so a failed MCP call can still be explained.
public sealed class GatewayRefusal
{
    public int Status { get; set; }
    public string? Body { get; set; }
}

public sealed class GatewayRefusalHandler(GatewayRefusal refusal) : DelegatingHandler(new HttpClientHandler())
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode && response.Content.Headers.ContentType?.MediaType == "application/json")
        {
            await response.Content.LoadIntoBufferAsync(cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (body.Contains("\"decidedBy\":\"gateway\"") || body.Contains("\"decidedBy\": \"gateway\""))
            {
                refusal.Status = (int)response.StatusCode;
                refusal.Body = body;
            }
        }
        return response;
    }
}

public sealed record TranscriptEntry(string Role, string? Text, IReadOnlyList<string>? ToolCalls);

public sealed record ChatTurnResult(
    string ConversationId,
    string IdentityMode,
    string Actor,
    string PermissionKind,
    string Model,
    string Answer,
    IReadOnlyList<ToolCallTrace> Trace,
    IReadOnlyList<TranscriptEntry> Transcript,
    int Iterations);

public sealed class AgentLoopService
{
    private const int MaxIterations = 8;

    private static readonly ConcurrentDictionary<string, List<ChatMessage>> Conversations = new();

    private readonly IAuthorizationHeaderProvider _headerProvider;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AgentLoopService> _logger;

    public AgentLoopService(
        IAuthorizationHeaderProvider headerProvider,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration,
        ILogger<AgentLoopService> logger)
    {
        _headerProvider = headerProvider;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _logger = logger;
    }

    public string AgentIdentityClientId =>
        _configuration["AgentIdentity:ClientId"] ?? throw new InvalidOperationException("AgentIdentity:ClientId is missing.");

    public string McpClientId =>
        _configuration["McpServer:ClientId"] is { Length: > 0 } id && !id.StartsWith('<')
            ? id
            : throw new InvalidOperationException("McpServer:ClientId is missing. Run Tests/Configure-McpEntra.ps1 and paste the app id into appsettings.json.");

    // The scope names the MCP server as the resource; Entra binds the token's audience to it.
    public string McpScope =>
        _configuration["McpServer:Scope"] is { Length: > 0 } scope ? scope : $"api://{McpClientId}/.default";

    public string McpEndpoint =>
        _configuration["McpServer:Endpoint"] ?? "http://localhost:5002/mcp";

    public McpTarget LocalTarget => new("local", McpEndpoint, McpScope, AgentIdentityClientId, ViaGateway: false);

    public McpTarget GatewayTarget => GatewayTargetFor(null);

    private static bool IsSet(string? value) => !string.IsNullOrWhiteSpace(value) && !value.StartsWith('<');

    // Agent identities the gateway tab can act as: GatewayAgentIdentities in appsettings.json
    // (all from the same blueprint), plus GatewayMcp:AgentIdentityClientId if it is not listed.
    // The default is GatewayMcp:AgentIdentityClientId, else the first configured entry.
    public IReadOnlyList<GatewayAgent> GatewayAgents
    {
        get
        {
            var defaultId = _configuration["GatewayMcp:AgentIdentityClientId"];
            var agents = _configuration.GetSection("GatewayAgentIdentities").GetChildren()
                .Select(c => (Name: c["Name"] ?? c["ClientId"] ?? "agent", ClientId: c["ClientId"] ?? "", Note: c["Note"]))
                .ToList();
            if (IsSet(defaultId) && !agents.Any(a => string.Equals(a.ClientId, defaultId, StringComparison.OrdinalIgnoreCase)))
                agents.Insert(0, ("Gateway agent (GatewayMcp:AgentIdentityClientId)", defaultId!, null));
            if (!IsSet(defaultId))
                defaultId = agents.FirstOrDefault(a => IsSet(a.ClientId)).ClientId;
            return agents
                .Select(a => new GatewayAgent(a.Name, a.ClientId, a.Note, IsSet(a.ClientId),
                    IsSet(a.ClientId) && string.Equals(a.ClientId, defaultId, StringComparison.OrdinalIgnoreCase)))
                .ToList();
        }
    }

    // agentClientId comes from the browser, so only configured agents are accepted.
    public McpTarget GatewayTargetFor(string? agentClientId)
    {
        var endpoint = _configuration["GatewayMcp:Endpoint"];
        if (!IsSet(endpoint))
            throw new InvalidOperationException("GatewayMcp:Endpoint is not set. Run Configure/Deploy-GatewayPoc.ps1.");
        var configured = GatewayAgents.Where(a => a.Configured).ToList();
        var agent = string.IsNullOrWhiteSpace(agentClientId)
            ? configured.FirstOrDefault(a => a.IsDefault) ?? configured.FirstOrDefault()
            : configured.FirstOrDefault(a => string.Equals(a.ClientId, agentClientId, StringComparison.OrdinalIgnoreCase))
              ?? throw new InvalidOperationException($"Agent identity {agentClientId} is not in GatewayAgentIdentities (appsettings.json).");
        if (agent is null)
            throw new InvalidOperationException("No gateway agent identity is configured. Run Configure/Configure-Entra.ps1 -TestAgents.");
        var scope = _configuration["GatewayMcp:Scope"] is { Length: > 0 } s ? s : McpScope;
        return new McpTarget("gateway", endpoint!, scope, agent.ClientId, ViaGateway: true);
    }

    public LlmConnection ResolveLlm(LlmConnection? requested) => new(
        BaseUrl: string.IsNullOrWhiteSpace(requested?.BaseUrl) ? _configuration["Llm:BaseUrl"] ?? "http://localhost:8000/v1" : requested.BaseUrl,
        ApiKey: string.IsNullOrWhiteSpace(requested?.ApiKey) ? _configuration["Llm:ApiKey"] ?? "not-needed" : requested.ApiKey,
        Model: string.IsNullOrWhiteSpace(requested?.Model) ? _configuration["Llm:Model"] ?? "" : requested.Model);

    public static (string Actor, string PermissionKind) Describe(IdentityMode mode) => mode switch
    {
        IdentityMode.HostApp => ("host-application", "application (roles)"),
        IdentityMode.AgentApp => ("agent-identity", "application (roles)"),
        IdentityMode.HostUser => ("host-application on behalf of user", "delegated (scp)"),
        IdentityMode.AgentUser => ("agent-identity on behalf of user", "delegated (scp)"),
        _ => throw new ArgumentOutOfRangeException(nameof(mode))
    };

    // ------------------------------------------------------------------
    // Token minting: the only place the identity decision is applied.
    // The token is for the MCP SERVER (not the Claims API): the MCP server
    // is the resource the agent talks to, and it must not forward this token.
    // ------------------------------------------------------------------
    public async Task<string> AcquireMcpAuthorizationHeaderAsync(IdentityMode mode, ClaimsPrincipal? user, CancellationToken ct = default, McpTarget? target = null)
    {
        target ??= LocalTarget;
        var options = new AuthorizationHeaderProviderOptions();
        options.AcquireTokenOptions.AuthenticationOptionsName = mode is IdentityMode.HostApp or IdentityMode.HostUser
            ? "Bearer"          // host application credentials
            : "AgentBlueprint"; // blueprint credentials, acting as the agent identity

        if (mode is IdentityMode.AgentApp or IdentityMode.AgentUser)
        {
            options.WithAgentIdentity(target.AgentIdentityClientId);
        }

        return mode switch
        {
            IdentityMode.HostApp or IdentityMode.AgentApp =>
                await _headerProvider.CreateAuthorizationHeaderForAppAsync(target.Scope, options, ct),
            _ =>
                await _headerProvider.CreateAuthorizationHeaderForUserAsync([target.Scope], options, user, ct)
        };
    }

    // ------------------------------------------------------------------
    // MCP client bound to one identity's token.
    // ------------------------------------------------------------------
    public async Task<McpClient> ConnectMcpAsync(string authorizationHeader, CancellationToken ct = default, McpTarget? target = null, GatewayRefusal? refusal = null)
    {
        target ??= LocalTarget;
        // Through the gateway, a handler records APIM's own refusals (kill list,
        // PDP, rate limit) so the trace can show why the call never reached MCP.
        var http = refusal is null ? _httpClientFactory.CreateClient("claims-mcp") : new HttpClient(new GatewayRefusalHandler(refusal));
        http.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse(authorizationHeader);

        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri(target.Endpoint),
            Name = $"claims-mcp-{target.Name}",
            TransportMode = HttpTransportMode.StreamableHttp
        }, http);

        return await McpClient.CreateAsync(transport, cancellationToken: ct);
    }

    public async Task<IReadOnlyList<object>> ListToolsAsync(IdentityMode mode, ClaimsPrincipal? user, CancellationToken ct = default, McpTarget? target = null)
    {
        var header = await AcquireMcpAuthorizationHeaderAsync(mode, user, ct, target);
        var refusal = target?.ViaGateway == true ? new GatewayRefusal() : null;
        try
        {
            await using var mcp = await ConnectMcpAsync(header, ct, target, refusal);
            var tools = await mcp.ListToolsAsync(cancellationToken: ct);
            return tools.Select(t => (object)new { name = t.Name, description = t.Description, inputSchema = t.JsonSchema }).ToList();
        }
        catch (Exception ex) when (refusal?.Body is not null)
        {
            throw new InvalidOperationException($"Gateway refused (HTTP {refusal.Status}): {refusal.Body}", ex);
        }
    }

    public static IChatClient CreateChatClient(LlmConnection llm)
    {
        if (string.IsNullOrWhiteSpace(llm.BaseUrl)) throw new InvalidOperationException("LLM base URL is missing.");
        if (string.IsNullOrWhiteSpace(llm.Model)) throw new InvalidOperationException("LLM model is missing. Use the Connection tab to pick one.");

        var client = new OpenAIClient(
            new ApiKeyCredential(string.IsNullOrWhiteSpace(llm.ApiKey) ? "not-needed" : llm.ApiKey),
            new OpenAIClientOptions { Endpoint = new Uri(llm.BaseUrl) });

        return client.GetChatClient(llm.Model).AsIChatClient();
    }

    public static void ResetConversation(string conversationId) => Conversations.TryRemove(conversationId, out _);

    // ------------------------------------------------------------------
    // One chat turn = run the loop until the model answers without tools.
    // ------------------------------------------------------------------
    public async Task<ChatTurnResult> RunTurnAsync(IdentityMode mode, ChatRequest request, ClaimsPrincipal? user, CancellationToken ct = default, McpTarget? target = null)
    {
        target ??= LocalTarget;
        var llm = ResolveLlm(request.Llm);
        var (actor, permissionKind) = Describe(mode);
        if (target.ViaGateway && mode is IdentityMode.AgentApp or IdentityMode.AgentUser)
        {
            actor = actor.Replace("agent-identity", $"agent-identity {target.AgentIdentityClientId}");
        }
        var conversationId = string.IsNullOrWhiteSpace(request.ConversationId) ? Guid.NewGuid().ToString("N") : request.ConversationId;

        // 1. Decide the identity and mint its token (audience: MCP server) BEFORE the model runs.
        var authorizationHeader = await AcquireMcpAuthorizationHeaderAsync(mode, user, ct, target);

        // 2. Discover tools from the MCP server with that identity. Through the
        //    gateway this can already be refused (kill list, PDP, rate limit).
        var refusal = target.ViaGateway ? new GatewayRefusal() : null;
        McpClient mcp;
        IList<McpClientTool> tools;
        try
        {
            mcp = await ConnectMcpAsync(authorizationHeader, ct, target, refusal);
            tools = await mcp.ListToolsAsync(cancellationToken: ct);
        }
        catch (Exception) when (refusal?.Body is not null)
        {
            var text = GatewayRefusalResult(refusal);
            var (gStatus, gDecidedBy, _, _, _, gPep, gGateway, gAuthzen, _, gKill) = ParseToolResult(text);
            var blocked = new ToolCallTrace(1, "mcp:connect (initialize / tools/list)", null, actor, permissionKind, gStatus,
                Decide(gStatus, gDecidedBy, gPep), null, gDecidedBy, null, null, text, gPep, gGateway, gAuthzen, null, gKill);
            return new ChatTurnResult(conversationId, mode.ToString(), actor, permissionKind, llm.Model ?? "",
                $"(The API Management gateway refused this identity before the model ran: HTTP {refusal.Status}.)",
                [blocked], [], 0);
        }
        await using var mcpScope = mcp;

        var chat = CreateChatClient(llm);

        var messages = Conversations.GetOrAdd(conversationId, _ =>
        [
            new ChatMessage(ChatRole.System, target.ViaGateway
                ? "You are the POC Claims Assistant. You help insurance adjusters with claims. " +
                  "Use the available tools to list, look up, analyze or archive claims when the user asks. " +
                  "Claim ids look like CLAIM-1001. Every tool call passes an API gateway and a policy decision point (PDP). " +
                  "If a tool reports a refusal (403, 429 or 503), explain it using the reason field and say which " +
                  "enforcement point refused it (decidedBy: gateway, pdp, claims-api; pep tells where the PDP was asked) " +
                  "and the policy ids. Do not retry a refused call. Keep answers short."
                : "You are the POC Claims Assistant. You help insurance adjusters with claims. " +
                  "Use the available tools to look up, analyze or archive claims when the user asks. " +
                  "Claim ids look like CLAIM-1001. If a tool reports an authorization error (403), explain that the " +
                  "current identity is not permitted to perform that operation, say which permission is required and " +
                  "whether the MCP server or the Claims API refused it (the decidedBy field). " +
                  "Keep answers short.")
        ]);

        messages.Add(new ChatMessage(ChatRole.User, request.Message));

        var options = new ChatOptions
        {
            Tools = [.. tools],
            ToolMode = ChatToolMode.Auto,
            Temperature = 0.1f
        };

        var trace = new List<ToolCallTrace>();
        var answer = "";
        var iterations = 0;

        while (iterations < MaxIterations)
        {
            iterations++;
            var response = await chat.GetResponseAsync(messages, options, ct);
            messages.AddRange(response.Messages);

            var calls = response.Messages.SelectMany(m => m.Contents).OfType<FunctionCallContent>().ToList();
            if (calls.Count == 0)
            {
                answer = response.Text;
                break;
            }

            foreach (var call in calls)
            {
                var step = trace.Count + 1;
                var tool = tools.FirstOrDefault(t => string.Equals(t.Name, call.Name, StringComparison.OrdinalIgnoreCase));
                string resultText;

                if (tool is null)
                {
                    resultText = JsonSerializer.Serialize(new { error = $"unknown tool {call.Name}" });
                }
                else
                {
                    // 3. Execute the tool AS THE CHOSEN IDENTITY. The MCP client already
                    //    carries that identity's bearer token; the MCP server validates it,
                    //    enforces Mcp.* permissions and exchanges it before calling the Claims API.
                    _logger.LogInformation("Agent loop step {Step}: tool {Tool} as {Actor}", step, call.Name, actor);
                    try
                    {
                        if (refusal is not null) refusal.Body = null;
                        var raw = await tool.InvokeAsync(new AIFunctionArguments(call.Arguments), ct);
                        _logger.LogDebug("Tool {Tool} returned {Type}: {Preview}", call.Name, raw?.GetType().FullName,
                            JsonSerializer.Serialize(raw) is var s && s.Length > 300 ? s[..300] : JsonSerializer.Serialize(raw));
                        resultText = ExtractText(raw);
                    }
                    catch (Exception ex) when (refusal?.Body is not null)
                    {
                        // Refused by API Management itself (kill list, PDP, rate limit).
                        resultText = GatewayRefusalResult(refusal);
                        _logger.LogInformation(ex, "Tool {Tool} refused at the gateway (HTTP {Status})", call.Name, refusal.Status);
                    }
                    catch (Exception ex)
                    {
                        resultText = JsonSerializer.Serialize(new { error = ex.Message });
                    }
                }

                var (status, decidedBy, mcpServerSaw, exchange, tokenInfo, pep, gateway, authzen, downstreamAuthzen, killList) = ParseToolResult(resultText);
                var decision = Decide(status, decidedBy, pep);

                trace.Add(new ToolCallTrace(
                    step, call.Name, ToJsonElement(call.Arguments), actor, permissionKind, status, decision, tokenInfo,
                    decidedBy, mcpServerSaw, exchange,
                    resultText.Length > (target.ViaGateway ? 4000 : 600) ? resultText[..(target.ViaGateway ? 4000 : 600)] + "…" : resultText,
                    pep, gateway, authzen, downstreamAuthzen, killList));

                messages.Add(new ChatMessage(ChatRole.Tool, [new FunctionResultContent(call.CallId, resultText)]));
            }
        }

        if (string.IsNullOrEmpty(answer) && iterations >= MaxIterations)
        {
            answer = "(stopped: too many tool iterations)";
        }

        return new ChatTurnResult(
            conversationId, mode.ToString(), actor, permissionKind, llm.Model ?? "", answer, trace,
            messages.Select(ToTranscript).ToList(), iterations);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    private static string ExtractText(object? raw)
    {
        switch (raw)
        {
            case null:
                return "";
            case string s:
                return s;
            case TextContent text:
                return text.Text;
            case AIContent other:
                return JsonSerializer.Serialize(other);
            case IEnumerable<AIContent> contents:
                return string.Join("\n", contents.Select(ExtractText));
            case CallToolResult result:
                return string.Join("\n", result.Content.OfType<TextContentBlock>().Select(c => c.Text));
            case JsonElement element:
                if (element.ValueKind == JsonValueKind.Object && element.TryGetProperty("content", out var content) && content.ValueKind == JsonValueKind.Array)
                {
                    var texts = content.EnumerateArray()
                        .Where(c => c.TryGetProperty("text", out _))
                        .Select(c => c.GetProperty("text").GetString() ?? "");
                    return string.Join("\n", texts);
                }
                return element.GetRawText();
            default:
                return JsonSerializer.Serialize(raw);
        }
    }

    // The MCP server returns
    //   { httpStatus, decidedBy: "mcp-server" | "claims-api",
    //     mcpServer: { saw: <claims of the inbound token>, required, decision },
    //     exchange:  { grant, actor, outboundToken: {...} }      (absent when denied at the MCP server)
    //     body:      <Claims API body, with _debug.tokenInfo>     (or the MCP server's own error body) }
    //
    // Through the gateway (claims-mcp-azure) the result also carries
    //     pep, gateway { viaGateway, decision }, authzen (PEP 2), downstreamAuthzen (PEP 3), killList
    private static (int? Status, string? DecidedBy, JsonElement? McpServerSaw, JsonElement? Exchange, JsonElement? TokenInfo,
        string? Pep, JsonElement? Gateway, JsonElement? Authzen, JsonElement? DownstreamAuthzen, JsonElement? KillList) ParseToolResult(string text)
    {
        try
        {
            using var document = JsonDocument.Parse(text);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return default;
            JsonElement? Get(string name) => root.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null ? v.Clone() : null;
            int? status = root.TryGetProperty("httpStatus", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt32() : null;
            string? decidedBy = root.TryGetProperty("decidedBy", out var d) && d.ValueKind == JsonValueKind.String ? d.GetString() : null;
            string? pep = root.TryGetProperty("pep", out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;
            JsonElement? mcpServerSaw = root.TryGetProperty("mcpServer", out var m) && m.TryGetProperty("saw", out var saw) ? saw.Clone() : null;
            JsonElement? tokenInfo = null;
            if (root.TryGetProperty("body", out var body) && body.ValueKind == JsonValueKind.Object &&
                body.TryGetProperty("_debug", out var debug) && debug.TryGetProperty("tokenInfo", out var ti))
            {
                tokenInfo = ti.Clone();
            }
            return (status, decidedBy, mcpServerSaw, Get("exchange"), tokenInfo, pep, Get("gateway"), Get("authzen"), Get("downstreamAuthzen"), Get("killList"));
        }
        catch (JsonException)
        {
            return default;
        }
    }

    private static string Decide(int? status, string? decidedBy, string? pep) => status switch
    {
        null => "unknown",
        < 300 => "ALLOW",
        403 when decidedBy is "pdp" => $"DENY (403 from PDP at {pep ?? "?"})",
        403 when decidedBy is "gateway" => "DENY (403 at API Management gateway)",
        403 => $"DENY (403 from {decidedBy ?? "downstream"})",
        429 => "RATE LIMITED (429 at gateway)",
        _ => $"HTTP {status}" + (decidedBy is "mcp-server" ? " at MCP server" : decidedBy is "gateway" ? " at gateway" : "")
    };

    // Wraps APIM's own refusal body in the same shape the MCP server uses.
    private static string GatewayRefusalResult(GatewayRefusal refusal)
    {
        using var document = JsonDocument.Parse(refusal.Body!);
        var root = document.RootElement;
        return JsonSerializer.Serialize(new
        {
            httpStatus = refusal.Status,
            decidedBy = "gateway",
            pep = "gateway",
            gateway = new { viaGateway = true, refusal = root },
            authzen = root.TryGetProperty("authzen", out var a) ? a : (JsonElement?)null,
            killList = root.TryGetProperty("killList", out var k) ? k : (JsonElement?)null,
            body = root
        });
    }

    private static JsonElement? ToJsonElement(IDictionary<string, object?>? arguments) =>
        arguments is null ? null : JsonSerializer.SerializeToElement(arguments);

    private static TranscriptEntry ToTranscript(ChatMessage message)
    {
        var toolCalls = message.Contents.OfType<FunctionCallContent>()
            .Select(c => $"{c.Name}({JsonSerializer.Serialize(c.Arguments)})").ToList();
        var toolResults = message.Contents.OfType<FunctionResultContent>()
            .Select(r => r.Result?.ToString() ?? "").ToList();

        var text = message.Role == ChatRole.Tool
            ? string.Join("\n", toolResults)
            : message.Text;

        return new TranscriptEntry(message.Role.Value, text, toolCalls.Count > 0 ? toolCalls : null);
    }
}
