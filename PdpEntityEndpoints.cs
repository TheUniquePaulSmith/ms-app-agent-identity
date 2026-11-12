using System.Text;
using System.Text.Json;
using Azure;
using Azure.Data.Tables;

// ============================================================================
// "PDP entities" sub-tab of the gateway tab: the PDP's entity registry, read and
// written straight in the storage account (table GatewayMcp:PdpEntitiesTable,
// connection string GatewayMcp:StorageConnectionString). After every change the
// PDP is asked to re-read the table (POST /admin/reload, x-pdp-key); it also
// re-reads it every 30 s on its own.
//
//   GET    /api/gw/entities                 all rows, grouped by kind
//   PUT    /api/gw/entities/{kind}/{id}     add or replace one row
//   DELETE /api/gw/entities/{kind}/{id}     remove one row
//
// PartitionKey = kind, RowKey = id. Columns per kind (claims-pdp/pdp-core.mjs reads them):
//   blueprint    displayName
//   agent        displayName, blueprint, autonomousLimit
//   application  displayName, isMcpServer
//   group        displayName, entraObjectId, region       (id as used in the Cedar policies)
//   member       groups (comma separated group ids; only for the PDP's GROUP_SOURCE=local)
// ============================================================================

public static class PdpEntityEndpoints
{
    private static readonly string[] Kinds = ["blueprint", "agent", "application", "group", "member"];

    public static void MapPdpEntityEndpoints(this WebApplication app)
    {
        var config = app.Configuration;
        string Setting(string key) => config[$"GatewayMcp:{key}"] ?? "";
        bool Configured(string key) => Setting(key) is { Length: > 0 } v && !v.StartsWith('<');
        string TableName() => Configured("PdpEntitiesTable") ? Setting("PdpEntitiesTable") : "PdpEntities";

        TableClient? Table() => Configured("StorageConnectionString")
            ? new TableClient(Setting("StorageConnectionString"), TableName())
            : null;

        IResult NotConfigured() => Results.Json(new
        {
            error = "GatewayMcp:StorageConnectionString is not set (run Configure/Deploy-GatewayPoc.ps1)."
        }, statusCode: 400);

        app.MapGet("/api/gw/entities", async (CancellationToken ct) =>
        {
            if (Table() is not { } table) return NotConfigured();
            try
            {
                var rows = new List<Dictionary<string, object?>>();
                await foreach (var e in table.QueryAsync<TableEntity>(cancellationToken: ct))
                {
                    var row = new Dictionary<string, object?> { ["kind"] = e.PartitionKey, ["id"] = e.RowKey, ["timestamp"] = e.Timestamp };
                    foreach (var (k, v) in e)
                    {
                        if (k is not ("PartitionKey" or "RowKey" or "Timestamp" or "odata.etag")) row[k] = v;
                    }
                    rows.Add(row);
                }
                return Results.Ok(new
                {
                    table = TableName(),
                    account = table.AccountName,
                    entities = Kinds.ToDictionary(k => k, k => rows.Where(r => (string?)r["kind"] == k).OrderBy(r => (string?)r["id"]).ToList()),
                    other = rows.Where(r => !Kinds.Contains((string?)r["kind"])).ToList()
                });
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                return Results.Ok(new { table = TableName(), account = table.AccountName, entities = Kinds.ToDictionary(k => k, _ => new List<object>()), note = "table does not exist yet; the first save creates it" });
            }
            catch (Exception ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: 502);
            }
        });

        app.MapPut("/api/gw/entities/{kind}/{id}", async (string kind, string id, JsonElement body, IHttpClientFactory factory, CancellationToken ct) =>
        {
            if (Table() is not { } table) return NotConfigured();
            if (!TryBuildEntity(kind, id, body, out var entity, out var problem)) return Results.BadRequest(new { error = problem });
            try
            {
                await table.CreateIfNotExistsAsync(ct);
                // Replace, not merge: a column cleared in the form is removed from the row.
                await table.UpsertEntityAsync(entity, TableUpdateMode.Replace, ct);
            }
            catch (Exception ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: 502);
            }
            return Results.Ok(new { saved = new { kind, id = entity.RowKey }, pdpReload = await ReloadPdpAsync(factory, ct) });
        });

        app.MapDelete("/api/gw/entities/{kind}/{id}", async (string kind, string id, IHttpClientFactory factory, CancellationToken ct) =>
        {
            if (Table() is not { } table) return NotConfigured();
            kind = kind.ToLowerInvariant();
            if (kind != "group") id = id.ToLowerInvariant(); // same keys as TryBuildEntity
            try
            {
                // DeleteEntity treats a missing row as success.
                await table.DeleteEntityAsync(kind, id, ETag.All, ct);
            }
            catch (Exception ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: 502);
            }
            return Results.Ok(new { deleted = new { kind, id }, pdpReload = await ReloadPdpAsync(factory, ct) });
        });

        // The PDP answers with its registry state (version, rows, lastError); a failure here does
        // not undo the write, the PDP's own 30 s refresh picks it up.
        async Task<object?> ReloadPdpAsync(IHttpClientFactory factory, CancellationToken ct)
        {
            if (!Configured("PdpUrl")) return new { error = "GatewayMcp:PdpUrl is not set" };
            try
            {
                var http = factory.CreateClient("gateway-admin");
                using var message = new HttpRequestMessage(HttpMethod.Post, $"{Setting("PdpUrl")}/admin/reload")
                {
                    Content = new StringContent("{}", Encoding.UTF8, "application/json")
                };
                message.Headers.Add("x-pdp-key", Setting("InternalKey"));
                using var response = await http.SendAsync(message, ct);
                var text = await response.Content.ReadAsStringAsync(ct);
                try
                {
                    return new { status = (int)response.StatusCode, result = JsonSerializer.Deserialize<JsonElement>(text) };
                }
                catch (JsonException)
                {
                    return new { status = (int)response.StatusCode, raw = text };
                }
            }
            catch (Exception ex)
            {
                return new { error = ex.Message, note = "saved in the table; the PDP picks it up within 30 s" };
            }
        }
    }

    // Validates one row and normalises it the way the PDP looks it up (app ids, oids and UPNs
    // lowercase; group ids as written, since the Cedar policies name them).
    private static bool TryBuildEntity(string kind, string id, JsonElement body, out TableEntity entity, out string problem)
    {
        entity = null!;
        problem = "";
        kind = kind.ToLowerInvariant();
        id = id.Trim();
        if (!Kinds.Contains(kind)) { problem = $"kind must be one of {string.Join(", ", Kinds)}"; return false; }
        if (id.Length == 0 || id.Length > 512 || id.IndexOfAny(['/', '\\', '#', '?']) >= 0 || id.Any(char.IsControl))
        {
            problem = "id must be 1-512 characters without / \\ # ? or control characters";
            return false;
        }
        if (body.ValueKind != JsonValueKind.Object) { problem = "body must be a JSON object"; return false; }

        string Text(string name) => body.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null ? (v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString()).Trim() : "";

        entity = new TableEntity(kind, kind == "group" ? id : id.ToLowerInvariant());
        entity["displayName"] = Text("displayName");
        switch (kind)
        {
            case "agent":
                var blueprint = Text("blueprint").ToLowerInvariant();
                if (blueprint.Length == 0) { problem = "an agent needs a blueprint (app id)"; return false; }
                var limitText = Text("autonomousLimit");
                if (limitText.Length == 0) limitText = "0";
                if (!int.TryParse(limitText, out var limit) || limit < 0) { problem = "autonomousLimit must be a whole number >= 0"; return false; }
                entity["blueprint"] = blueprint;
                entity["autonomousLimit"] = limit;
                break;
            case "application":
                entity["isMcpServer"] = body.TryGetProperty("isMcpServer", out var mcp) &&
                    (mcp.ValueKind == JsonValueKind.True || (mcp.ValueKind == JsonValueKind.String && bool.TryParse(mcp.GetString(), out var b) && b));
                break;
            case "group":
                entity["entraObjectId"] = Text("entraObjectId").ToLowerInvariant();
                var region = Text("region");
                if (region.Length > 0) entity["region"] = region;
                break;
            case "member":
                entity.Remove("displayName");
                var groups = body.TryGetProperty("groups", out var g) && g.ValueKind == JsonValueKind.Array
                    ? g.EnumerateArray().Select(x => x.GetString() ?? "")
                    : Text("groups").Split(',');
                entity["groups"] = string.Join(",", groups.Select(x => x.Trim()).Where(x => x.Length > 0).Distinct());
                break;
        }
        return true;
    }
}
