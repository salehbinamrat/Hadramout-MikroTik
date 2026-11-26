using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

public enum RestoreCredentialState
{
    Missing = 1,
    AvailableLocally = 2,
    Unavailable = 3
}

public sealed record RestoreCredentialStatus(Guid RouterId, RestoreCredentialState State);

/// <summary>Read-only inspection of an authenticated, trusted restore candidate.</summary>
[SupportedOSPlatform("windows")]
public static class RestoreCredentialInspector
{
    // Bound the envelope size before materializing blobs. Invalid types/sizes are unavailable.
    private const string Query = """
        SELECT r.Id, c.RouterId IS NOT NULL,
            CASE WHEN typeof(c.UsernameEnvelope)='blob' AND length(c.UsernameEnvelope) BETWEEN 1 AND $max
                THEN c.UsernameEnvelope END,
            CASE WHEN typeof(c.PasswordEnvelope)='blob' AND length(c.PasswordEnvelope) BETWEEN 1 AND $max
                THEN c.PasswordEnvelope END
        FROM routers r LEFT JOIN router_credentials c ON c.RouterId=r.Id
        """;

    public static IReadOnlyList<RestoreCredentialStatus> Inspect(string candidatePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(candidatePath);
        if (!Path.IsPathFullyQualified(candidatePath))
            throw new ArgumentException("An absolute candidate path is required.", nameof(candidatePath));
        using var connection = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(connection);
        using var cmd = connection.CreateCommand();
        cmd.CommandText = Query + " ORDER BY r.Id;";
        cmd.Parameters.AddWithValue("$max", RouterCredentialProtector.MaxEnvelopeLength);
        using var reader = cmd.ExecuteReader();
        var result = new List<RestoreCredentialStatus>();
        while (reader.Read())
            result.Add(new RestoreCredentialStatus(reader.GetGuid(0), Classify(reader)));
        return result.AsReadOnly();
    }

    internal static RestoreCredentialState ReadStatus(SqliteConnection connection, SqliteTransaction tx, Guid id)
    {
        using var cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = Query + " WHERE r.Id=$id;";
        cmd.Parameters.AddWithValue("$max", RouterCredentialProtector.MaxEnvelopeLength);
        cmd.Parameters.AddWithValue("$id", id);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) throw new InvalidOperationException("The restored router does not exist.");
        return Classify(reader);
    }

    private static RestoreCredentialState Classify(SqliteDataReader reader)
    {
        if (!reader.GetBoolean(1)) return RestoreCredentialState.Missing;
        if (reader.IsDBNull(2) || reader.IsDBNull(3)) return RestoreCredentialState.Unavailable;
        try
        {
            using var lease = RouterCredentialStore.OpenLease(reader.GetGuid(0),
                reader.GetFieldValue<byte[]>(2), reader.GetFieldValue<byte[]>(3));
            return RestoreCredentialState.AvailableLocally;
        }
        catch (CryptographicException)
        {
            // Cannot distinguish a different account/device from damage. Never log the blob.
            return RestoreCredentialState.Unavailable;
        }
    }
}
