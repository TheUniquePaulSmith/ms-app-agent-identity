using System.Net.Http.Json;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web;

/// <summary>
/// Calls the Claims API as the AGENT IDENTITY.
/// The blueprint's credential mints the token (configuration:
/// DownstreamApis:ClaimsApiAsAgent:AcquireTokenOptions:AuthenticationOptionsName = "AgentBlueprint"),
/// and WithAgentIdentity(...) selects which agent identity the token represents.
/// The Claims API sees the agent identity as the caller, with xms_par_app_azp naming the blueprint.
/// </summary>
public sealed class AgentRuntimeService
{
    private const string ApiName = "ClaimsApiAsAgent";
    private readonly IDownstreamApi _downstreamApi;
    private readonly string _agentIdentityClientId;

    public AgentRuntimeService(IDownstreamApi downstreamApi, IConfiguration configuration)
    {
        _downstreamApi = downstreamApi;
        _agentIdentityClientId =
            configuration["AgentIdentity:ClientId"]
            ?? throw new InvalidOperationException("AgentIdentity:ClientId is missing.");
    }

    public string AgentIdentityClientId => _agentIdentityClientId;

    /// <summary>Scenario 3: autonomous agent, app-only token. Claims API sees roles = Claims.Analyze.All, oid = agent identity.</summary>
    public async Task<DownstreamResult> AnalyzeAsAppAsync(string claimId)
    {
        // In a real agent loop this is where the model's chosen tool call lands:
        // the tool dispatcher decides WHICH agent identity acts, then calls the API.
        var response = await _downstreamApi.CallApiForAppAsync(
            ApiName,
            options =>
            {
                options.HttpMethod = HttpMethod.Post.Method;
                options.RelativePath = "/claims/analyze";
                options.WithAgentIdentity(_agentIdentityClientId);
            },
            JsonContent.Create(new { claimId, operation = "analyze", selectedTool = "analyze_claim" }));

        return await DownstreamResult.FromResponseAsync(response);
    }

    /// <summary>Scenario 4: interactive agent, on-behalf-of token. Claims API sees scp = Claims.Analyze, oid = user, azp = agent identity.</summary>
    public async Task<DownstreamResult> AnalyzeAsUserAsync(string claimId)
    {
        var response = await _downstreamApi.CallApiForUserAsync(
            ApiName,
            options =>
            {
                options.HttpMethod = HttpMethod.Post.Method;
                options.RelativePath = "/claims/analyze";
                options.WithAgentIdentity(_agentIdentityClientId);
            },
            content: JsonContent.Create(new { claimId, operation = "analyze", selectedTool = "analyze_claim" }));

        return await DownstreamResult.FromResponseAsync(response);
    }

    /// <summary>Negative demo: the agent identity was never granted Claims.Archive.All, so the Claims API should answer 403.</summary>
    public async Task<DownstreamResult> ArchiveAsAppAsync(string claimId)
    {
        var response = await _downstreamApi.CallApiForAppAsync(
            ApiName,
            options =>
            {
                options.HttpMethod = HttpMethod.Post.Method;
                options.RelativePath = "/claims/archive";
                options.WithAgentIdentity(_agentIdentityClientId);
            },
            JsonContent.Create(new { claimId, operation = "archive", selectedTool = "archive_claim" }));

        return await DownstreamResult.FromResponseAsync(response);
    }
}
