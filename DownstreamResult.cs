using System.Text.Json;

/// <summary>
/// What the downstream Claims API answered. The status code is propagated to
/// the caller so a 403 from the Claims API shows up as a 403 from this app,
/// and the body (which carries the mock API's token summary) is passed through.
/// </summary>
public sealed record DownstreamResult(int StatusCode, JsonElement? Body, string? RawBody)
{
    public object? BodyForResponse => Body.HasValue ? Body.Value : RawBody;

    public static async Task<DownstreamResult> FromResponseAsync(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync();

        JsonElement? body = null;
        if (!string.IsNullOrWhiteSpace(raw))
        {
            try
            {
                using var document = JsonDocument.Parse(raw);
                body = document.RootElement.Clone();
            }
            catch (JsonException)
            {
                // Not JSON; keep the raw text.
            }
        }

        return new DownstreamResult((int)response.StatusCode, body, body is null ? raw : null);
    }
}
