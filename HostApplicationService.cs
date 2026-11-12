using System.Net.Http.Json;
using Microsoft.Identity.Abstractions;

/// <summary>
/// Calls the Claims API as the HOST APPLICATION (the App Registration).
/// Which credential mints the token is decided by configuration:
/// DownstreamApis:ClaimsApiAsHostApplication:AcquireTokenOptions:AuthenticationOptionsName = "Bearer"
/// maps to the HostApplication section.
/// </summary>
public sealed class HostApplicationService
{
    private const string ApiName = "ClaimsApiAsHostApplication";
    private readonly IDownstreamApi _downstreamApi;

    public HostApplicationService(IDownstreamApi downstreamApi)
    {
        _downstreamApi = downstreamApi;
    }

    /// <summary>Scenario 1: app-only token. Claims API sees roles = Claims.Archive.All, oid = host app SP.</summary>
    public async Task<DownstreamResult> ArchiveAsAppAsync(string claimId)
    {
        var response = await _downstreamApi.CallApiForAppAsync(
            ApiName,
            options =>
            {
                options.HttpMethod = HttpMethod.Post.Method;
                options.RelativePath = "/claims/archive";
            },
            JsonContent.Create(new { claimId, operation = "archive" }));

        return await DownstreamResult.FromResponseAsync(response);
    }

    /// <summary>Scenario 2: on-behalf-of token. Claims API sees scp = Claims.Archive, oid = user, azp = host app.</summary>
    public async Task<DownstreamResult> ArchiveAsUserAsync(string claimId)
    {
        var response = await _downstreamApi.CallApiForUserAsync(
            ApiName,
            options =>
            {
                options.HttpMethod = HttpMethod.Post.Method;
                options.RelativePath = "/claims/archive";
            },
            content: JsonContent.Create(new { claimId, operation = "archive" }));

        return await DownstreamResult.FromResponseAsync(response);
    }

    /// <summary>Negative demo: the host app was never granted Claims.Analyze.All, so the Claims API should answer 403.</summary>
    public async Task<DownstreamResult> AnalyzeAsAppAsync(string claimId)
    {
        var response = await _downstreamApi.CallApiForAppAsync(
            ApiName,
            options =>
            {
                options.HttpMethod = HttpMethod.Post.Method;
                options.RelativePath = "/claims/analyze";
            },
            JsonContent.Create(new { claimId, operation = "analyze" }));

        return await DownstreamResult.FromResponseAsync(response);
    }
}
