using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

public enum AuditKind
{
    CredentialSaved = 1,
    CredentialRemoved = 2,
    BackupSnapshotCreated = 3,
    RestoreCandidatePrepared = 4
}

public sealed record AuditEvent(Guid Id, DateTimeOffset OccurredUtc, AuditKind Kind, Guid? SubjectId);

public static class AuditStore
{
    // Structured allowlist only: no free text, passwords, paths, payloads or exceptions.
    internal static void Append(SqliteConnection connection, SqliteTransaction tx, AuditKind kind, Guid? subjectId)
    {
        using var cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO audit_events(Id, OccurredUtc, Kind, SubjectId)
            VALUES($id,$utc,$kind,$subject);
            """;
        cmd.Parameters.AddWithValue("$id", Guid.NewGuid());
        cmd.Parameters.AddWithValue("$utc", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$kind", (int)kind);
        cmd.Parameters.AddWithValue("$subject", (object?)subjectId ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    public static IReadOnlyList<AuditEvent> ReadRecent(string databasePath, int limit = 100)
    {
        if (limit is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(limit));
        using var connection = DatabaseStore.Open(databasePath);
        using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT Id, OccurredUtc, Kind, SubjectId FROM audit_events
            ORDER BY OccurredUtc DESC, Id DESC LIMIT $limit;
            """;
        cmd.Parameters.AddWithValue("$limit", limit);
        using var reader = cmd.ExecuteReader();
        var result = new List<AuditEvent>();
        while (reader.Read())
        {
            result.Add(new AuditEvent(reader.GetGuid(0),
                DateTimeOffset.ParseExact(reader.GetString(1), "O", CultureInfo.InvariantCulture),
                (AuditKind)reader.GetInt32(2), reader.IsDBNull(3) ? null : reader.GetGuid(3)));
        }
        return result;
    }
}
