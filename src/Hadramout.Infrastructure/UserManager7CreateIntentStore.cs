using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

internal sealed record UserManager7CreateIntent(Guid ReservationId, Guid BackendId, Guid RouterId,
    Guid BatchId, Guid PlanId, string Username, string PlanName, string LeafSha256,
    string ProfileName, string GroupName);

// Local preparation only. Does not grant a dispatch claim or store credentials.
internal sealed class UserManager7CreateIntentStore(string databasePath)
{
    internal UserManager7CreateIntent Prepare(Guid reservationId, string profileName, string groupName)
    {
        ValidateId(reservationId);
        UserManager6Records.ValidateKey(profileName, nameof(profileName));
        UserManager6Records.ValidateKey(groupName, nameof(groupName));
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            SELECT v.Id,v.BackendId,b.RouterId,batch.Id,p.Id,v.Username,p.Name,t.LeafSha256
            FROM voucher_reservations v
            JOIN backends b ON b.Id=v.BackendId AND b.Kind=3
            JOIN voucher_batches batch ON batch.Id=v.BatchId AND batch.BackendId=v.BackendId
            JOIN plans p ON p.Id=batch.PlanId AND p.BackendId=v.BackendId
            JOIN router_targets t ON t.RouterId=b.RouterId
            WHERE v.Id=$id;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        UserManager7CreateIntent intent;
        using (var reader = cmd.ExecuteReader())
        {
            if (!reader.Read()) throw new InvalidOperationException("A bound UM7 reservation is required.");
            intent = new(reader.GetGuid(0),reader.GetGuid(1),reader.GetGuid(2),reader.GetGuid(3),
                reader.GetGuid(4),reader.GetString(5),reader.GetString(6),reader.GetString(7),profileName,groupName);
        }
        UserManager6Records.ValidateKey(intent.Username, nameof(intent.Username));
        cmd.CommandText = """
            INSERT INTO um7_create_intents(ReservationId,BackendId,RouterId,BatchId,PlanId,Username,PlanName,LeafSha256,ProfileName,GroupName)
            VALUES($id,$backend,$router,$batch,$plan,$username,$planName,$pin,$profile,$group);
            """;
        cmd.Parameters.AddWithValue("$backend", intent.BackendId);
        cmd.Parameters.AddWithValue("$router", intent.RouterId);
        cmd.Parameters.AddWithValue("$batch", intent.BatchId);
        cmd.Parameters.AddWithValue("$plan", intent.PlanId);
        cmd.Parameters.AddWithValue("$username", intent.Username);
        cmd.Parameters.AddWithValue("$planName", intent.PlanName);
        cmd.Parameters.AddWithValue("$pin", intent.LeafSha256);
        cmd.Parameters.AddWithValue("$profile", profileName);
        cmd.Parameters.AddWithValue("$group", groupName);
        cmd.ExecuteNonQuery();
        tx.Commit();
        return intent;
    }

    internal UserManager7CreateIntent? Read(Guid reservationId)
    {
        ValidateId(reservationId);
        if (!Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException("An absolute database path is required.", nameof(databasePath));
        using var c = DatabaseBackup.OpenRaw(databasePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(c);
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT ReservationId,BackendId,RouterId,BatchId,PlanId,Username,PlanName,LeafSha256,ProfileName,GroupName
            FROM um7_create_intents WHERE ReservationId=$id;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? new(reader.GetGuid(0),reader.GetGuid(1),reader.GetGuid(2),reader.GetGuid(3),
            reader.GetGuid(4),reader.GetString(5),reader.GetString(6),reader.GetString(7),
            reader.GetString(8),reader.GetString(9)) : null;
    }

    // Caller holds exclusive managed generation gate. Compare every retained
    // intent and its current local relationships; never hide inconsistent rows.
    internal static void RequireEquivalentForRestore(string currentPath, string candidatePath)
    {
        using var current = DatabaseBackup.OpenRaw(currentPath, SqliteOpenMode.ReadOnly);
        using var candidate = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(current);
        DatabaseBackup.RequireIdentity(candidate);
        using var left = current.CreateCommand();
        using var right = candidate.CreateCommand();
        const string query = """
            SELECT i.ReservationId,i.BackendId,i.RouterId,i.BatchId,i.PlanId,i.Username,i.PlanName,
                   i.LeafSha256,i.ProfileName,i.GroupName,r.SiteId,r.Name,s.Name,
                   CASE WHEN v.Id IS NOT NULL AND v.BackendId=i.BackendId AND v.Username=i.Username AND v.BatchId=i.BatchId
                       AND b.Kind=3 AND b.RouterId=i.RouterId AND batch.BackendId=i.BackendId AND batch.PlanId=i.PlanId
                       AND p.BackendId=i.BackendId AND p.Name=i.PlanName AND t.LeafSha256=i.LeafSha256
                       AND r.Id IS NOT NULL AND s.Id IS NOT NULL
                       AND NOT EXISTS (SELECT 1 FROM um6_create_journal j WHERE j.ReservationId=i.ReservationId)
                       THEN 1 ELSE 0 END
            FROM um7_create_intents i
            LEFT JOIN voucher_reservations v ON v.Id=i.ReservationId
            LEFT JOIN backends b ON b.Id=i.BackendId
            LEFT JOIN voucher_batches batch ON batch.Id=i.BatchId
            LEFT JOIN plans p ON p.Id=i.PlanId
            LEFT JOIN router_targets t ON t.RouterId=i.RouterId
            LEFT JOIN routers r ON r.Id=i.RouterId
            LEFT JOIN sites s ON s.Id=r.SiteId
            ORDER BY i.ReservationId COLLATE BINARY;
            """;
        left.CommandText = query;
        right.CommandText = query;
        using var a = left.ExecuteReader();
        using var b = right.ExecuteReader();
        while (true)
        {
            bool hasA = a.Read(), hasB = b.Read();
            if (hasA != hasB) throw RestoreConflict();
            if (!hasA) return;
            if (a.GetInt32(13) != 1 || b.GetInt32(13) != 1) throw RestoreConflict();
            for (int i = 0; i < 13; i++)
                if (a.IsDBNull(i) || b.IsDBNull(i) || !Equals(a.GetValue(i), b.GetValue(i)))
                    throw RestoreConflict();
        }
    }

    private static InvalidOperationException RestoreConflict() =>
        new("Restoring this database would change or lose UM7 creation intent evidence.");

    private static void ValidateId(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("Reservation identity required.", nameof(id));
    }
}
