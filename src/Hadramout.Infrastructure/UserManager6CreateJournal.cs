using Microsoft.Data.Sqlite;
using System.Runtime.Versioning;

namespace Hadramout.Infrastructure;

internal enum UserManager6CreateState { Prepared = 1, DispatchStarted = 2, Indeterminate = 3, Acknowledged = 4 }

internal sealed record UserManager6CreateEntry(Guid ReservationId, Guid BackendId, Guid RouterId,
    string Customer, string Username, UserManager6CreateState State);

internal sealed record UserManager6CreateIntent(Guid ReservationId, Guid BatchId, Guid PlanId,
    string PlanName, string LeafSha256, string ProfileOwner, string ProfileName);

internal sealed record UserManager6CreationReviewRow(UserManager6CreateEntry Entry, bool LocalIdentityMatches);
internal sealed record UserManager6CreationReviewPage(IReadOnlyList<UserManager6CreationReviewRow> Rows,
    Guid? NextAfterReservationId);
internal sealed record UserManager6CreationCounts(long Prepared, long DispatchStarted, long Indeterminate,
    long Acknowledged)
{
    // Acknowledged operations also require verification; none are printable.
    internal long RequiresReview => checked(DispatchStarted + Indeterminate + Acknowledged);
}

// Local foundation only. No network I/O, passwords, or automatic resend.
// A claim is committed before any future caller may attempt remote dispatch.
internal sealed class UserManager6CreateJournal(string databasePath)
{
    internal UserManager6CreateEntry Prepare(Guid reservationId, string customer)
    {
        ValidateId(reservationId);
        UserManager6Records.ValidateKey(customer, nameof(customer));
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            SELECT v.BackendId,b.RouterId,v.Username FROM voucher_reservations v
            JOIN backends b ON b.Id=v.BackendId WHERE v.Id=$id AND b.Kind=2;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        Guid backend, router;
        string username;
        using (var reader = cmd.ExecuteReader())
        {
            if (!reader.Read()) throw new InvalidOperationException("A local UM6 reservation is required.");
            backend = reader.GetGuid(0);
            router = reader.GetGuid(1);
            username = reader.GetString(2);
        }
        UserManager6Records.ValidateKey(username, nameof(username));
        cmd.CommandText = """
            INSERT INTO um6_create_journal(ReservationId,BackendId,RouterId,Customer,Username,State)
            VALUES($id,$backend,$router,$customer,$username,1);
            """;
        cmd.Parameters.AddWithValue("$backend", backend);
        cmd.Parameters.AddWithValue("$router", router);
        cmd.Parameters.AddWithValue("$customer", customer);
        cmd.Parameters.AddWithValue("$username", username);
        cmd.ExecuteNonQuery();
        tx.Commit();
        return new(reservationId, backend, router, customer, username, UserManager6CreateState.Prepared);
    }

    internal UserManager6CreateEntry? Read(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = OpenReadOnly();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT BackendId,RouterId,Customer,Username,State FROM um6_create_journal WHERE ReservationId=$id;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? new(reservationId, reader.GetGuid(0), reader.GetGuid(1),
            reader.GetString(2), reader.GetString(3), (UserManager6CreateState)reader.GetInt32(4)) : null;
    }

    // Read-only local evidence. A claimed operation stays uncertain after a crash.
    // No network requests or inferred remote state; caller must not use this as dispatch authorization.
    internal UserManager6CreationReviewPage ReadReviewPage(Guid routerId,
        Guid? afterReservationId = null, int pageSize = 100)
    {
        ValidateId(routerId);
        if (afterReservationId.HasValue) ValidateId(afterReservationId.Value);
        if (pageSize is < 1 or > 500) throw new ArgumentOutOfRangeException(nameof(pageSize));
        using var c = OpenReadOnly();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT j.ReservationId,j.BackendId,j.RouterId,j.Customer,j.Username,j.State,
                   CASE WHEN v.Id IS NOT NULL AND v.BackendId=j.BackendId AND v.Username=j.Username
                        AND b.Kind=2 AND b.RouterId=j.RouterId
                        AND batch.BackendId=j.BackendId AND p.BackendId=j.BackendId
                        AND r.Id IS NOT NULL AND s.Id IS NOT NULL THEN 1 ELSE 0 END
            FROM um6_create_journal j
            LEFT JOIN voucher_reservations v ON v.Id=j.ReservationId
            LEFT JOIN backends b ON b.Id=j.BackendId
            LEFT JOIN voucher_batches batch ON batch.Id=v.BatchId
            LEFT JOIN plans p ON p.Id=batch.PlanId
            LEFT JOIN routers r ON r.Id=j.RouterId
            LEFT JOIN sites s ON s.Id=r.SiteId
            WHERE j.RouterId=$router AND j.State IN (2,3,4)
              AND ($after IS NULL OR j.ReservationId COLLATE BINARY > $after)
            ORDER BY j.ReservationId COLLATE BINARY LIMIT $limit;
            """;
        cmd.Parameters.AddWithValue("$router", routerId);
        cmd.Parameters.AddWithValue("$after", (object?)afterReservationId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$limit", pageSize + 1);
        using var reader = cmd.ExecuteReader();
        var rows = new List<UserManager6CreationReviewRow>(pageSize);
        bool hasMore = false;
        while (reader.Read())
        {
            if (rows.Count == pageSize) { hasMore = true; break; }
            var entry = new UserManager6CreateEntry(reader.GetGuid(0), reader.GetGuid(1), reader.GetGuid(2),
                reader.GetString(3), reader.GetString(4), (UserManager6CreateState)reader.GetInt32(5));
            rows.Add(new(entry, reader.GetInt32(6) == 1));
        }
        return new(rows.AsReadOnly(), hasMore ? rows[^1].Entry.ReservationId : null);
    }

    internal UserManager6CreationCounts ReadCounts(Guid routerId)
    {
        ValidateId(routerId);
        using var c = OpenReadOnly();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT count(CASE WHEN State=1 THEN 1 END),count(CASE WHEN State=2 THEN 1 END),
                   count(CASE WHEN State=3 THEN 1 END),count(CASE WHEN State=4 THEN 1 END)
            FROM um6_create_journal WHERE RouterId=$router;
            """;
        cmd.Parameters.AddWithValue("$router", routerId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) throw new InvalidDataException("Missing creation counts.");
        return new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3));
    }

    private SqliteConnection OpenReadOnly()
    {
        if (!Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException("An absolute database path is required.", nameof(databasePath));
        var connection = DatabaseBackup.OpenRaw(databasePath, SqliteOpenMode.ReadOnly);
        try
        {
            DatabaseBackup.RequireIdentity(connection);
            return connection;
        }
        catch { connection.Dispose(); throw; }
    }

    // Attach an explicitly selected remote profile to a still-prepared local journal row.
    // No remote proof or password is stored, and no command is sent.
    internal void PrepareBoundIntent(Guid reservationId, string profileOwner, string profileName)
    {
        ValidateId(reservationId);
        UserManager6Records.ValidateKey(profileOwner, nameof(profileOwner));
        UserManager6Records.ValidateKey(profileName, nameof(profileName));
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO um6_create_intents(ReservationId,BatchId,PlanId,PlanName,LeafSha256,ProfileOwner,ProfileName)
            SELECT j.ReservationId,batch.Id,p.Id,p.Name,t.LeafSha256,$owner,$profile
            FROM um6_create_journal j
            JOIN voucher_reservations v ON v.Id=j.ReservationId AND v.BackendId=j.BackendId AND v.Username=j.Username
            JOIN backends b ON b.Id=j.BackendId AND b.RouterId=j.RouterId AND b.Kind=2
            JOIN voucher_batches batch ON batch.Id=v.BatchId AND batch.BackendId=j.BackendId
            JOIN plans p ON p.Id=batch.PlanId AND p.BackendId=j.BackendId
            JOIN router_targets t ON t.RouterId=j.RouterId
            WHERE j.ReservationId=$id AND j.State=1;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        cmd.Parameters.AddWithValue("$owner", profileOwner);
        cmd.Parameters.AddWithValue("$profile", profileName);
        if (cmd.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("A prepared journal and enrolled matching target are required.");
        tx.Commit();
    }

    internal UserManager6CreateIntent? ReadBoundIntent(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = OpenReadOnly();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT BatchId,PlanId,PlanName,LeafSha256,ProfileOwner,ProfileName
            FROM um6_create_intents WHERE ReservationId=$id;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? new(reservationId, reader.GetGuid(0), reader.GetGuid(1),
            reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5)) : null;
    }

    // A local claim only. Never use the legacy unbound claim for remote dispatch.
    internal bool TryBeginDispatch(Guid reservationId) =>
        Transition(reservationId, UserManager6CreateState.Prepared, UserManager6CreateState.DispatchStarted);

    // Compare immutable intent with current local relationships atomically before claiming.
    // Remote checks, protected voucher credentials and authorization are still required.
    [SupportedOSPlatform("windows")]
    internal bool TryBeginBoundDispatch(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            UPDATE um6_create_journal SET State=2 WHERE ReservationId=$id AND State=1
            AND EXISTS (
                SELECT 1 FROM um6_create_intents i
                JOIN voucher_reservations v ON v.Id=i.ReservationId
                JOIN backends b ON b.Id=v.BackendId
                JOIN voucher_batches batch ON batch.Id=v.BatchId
                JOIN plans p ON p.Id=batch.PlanId
                JOIN router_targets t ON t.RouterId=b.RouterId
                WHERE i.ReservationId=um6_create_journal.ReservationId
                  AND v.BackendId=um6_create_journal.BackendId AND v.Username=um6_create_journal.Username
                  AND b.RouterId=um6_create_journal.RouterId AND b.Kind=2
                  AND batch.Id=i.BatchId AND batch.BackendId=v.BackendId
                  AND p.Id=i.PlanId AND p.BackendId=v.BackendId AND p.Name=i.PlanName
                  AND t.LeafSha256=i.LeafSha256);
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        if (cmd.ExecuteNonQuery() != 1) return false;
        // The update is still uncommitted. A missing or invalid secret rolls it back.
        using var secret = UserManager6VoucherSecretStore.Load(c, tx, reservationId);
        if (secret is null) return false;
        tx.Commit();
        return true;
    }

    internal bool TryMarkIndeterminate(Guid reservationId) =>
        Transition(reservationId, UserManager6CreateState.DispatchStarted, UserManager6CreateState.Indeterminate);

    internal bool TryMarkAcknowledged(Guid reservationId) =>
        Transition(reservationId, UserManager6CreateState.DispatchStarted, UserManager6CreateState.Acknowledged);

    private bool Transition(Guid reservationId, UserManager6CreateState expected, UserManager6CreateState next)
    {
        ValidateId(reservationId);
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            UPDATE um6_create_journal SET State=$next WHERE ReservationId=$id AND State=$expected
              AND ($expected<>1 OR NOT EXISTS (SELECT 1 FROM um6_create_intents i WHERE i.ReservationId=um6_create_journal.ReservationId))
              AND EXISTS (SELECT 1 FROM voucher_reservations v JOIN backends b ON b.Id=v.BackendId
                WHERE v.Id=um6_create_journal.ReservationId AND v.BackendId=um6_create_journal.BackendId
                  AND b.RouterId=um6_create_journal.RouterId AND b.Kind=2 AND v.Username=um6_create_journal.Username);
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        cmd.Parameters.AddWithValue("$expected", (int)expected);
        cmd.Parameters.AddWithValue("$next", (int)next);
        bool changed = cmd.ExecuteNonQuery() == 1;
        tx.Commit();
        return changed;
    }

    private static void ValidateId(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("A reservation identity is required.", nameof(id));
    }

    // Conservative cross-generation reconciliation: only identical creation histories
    // with matching local target relationships may switch generations. No union or replay.
    // Caller must hold the exclusive managed gate and quiesce all writers.
    internal static void RequireEquivalentForRestore(string currentPath, string candidatePath)
    {
        using var current = DatabaseBackup.OpenRaw(currentPath, SqliteOpenMode.ReadOnly);
        using var candidate = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(current);
        DatabaseBackup.RequireIdentity(candidate);
        using var left = current.CreateCommand();
        using var right = candidate.CreateCommand();
        // LEFT JOIN is intentional: an inconsistent relationship must not hide a journal row.
        const string query = """
            SELECT j.ReservationId,j.BackendId,j.RouterId,j.Customer,j.Username,j.State,
                   v.BatchId,p.Id,p.Name,r.SiteId,r.Name,s.Name,
                   CASE WHEN v.Id IS NOT NULL AND v.BackendId=j.BackendId AND v.Username=j.Username
                       AND b.Kind=2 AND b.RouterId=j.RouterId
                       AND batch.Id IS NOT NULL AND batch.BackendId=j.BackendId
                       AND p.Id IS NOT NULL AND p.BackendId=j.BackendId
                       AND r.Id IS NOT NULL AND s.Id IS NOT NULL THEN 1 ELSE 0 END
            FROM um6_create_journal j
            LEFT JOIN voucher_reservations v ON v.Id=j.ReservationId
            LEFT JOIN backends b ON b.Id=j.BackendId
            LEFT JOIN voucher_batches batch ON batch.Id=v.BatchId
            LEFT JOIN plans p ON p.Id=batch.PlanId
            LEFT JOIN routers r ON r.Id=j.RouterId
            LEFT JOIN sites s ON s.Id=r.SiteId
            ORDER BY j.ReservationId COLLATE BINARY;
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
            if (a.GetInt32(12) != 1 || b.GetInt32(12) != 1) throw RestoreConflict();
            for (int i = 0; i < 12; i++)
                if (a.IsDBNull(i) || b.IsDBNull(i) || !Equals(a.GetValue(i), b.GetValue(i)))
                    throw RestoreConflict();
        }
    }

    // Preserve exact immutable intent evidence, even on still-prepared rows.
    internal static void RequireEquivalentIntentsForRestore(string currentPath, string candidatePath)
    {
        using var current = DatabaseBackup.OpenRaw(currentPath, SqliteOpenMode.ReadOnly);
        using var candidate = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(current);
        DatabaseBackup.RequireIdentity(candidate);
        using var a = current.CreateCommand();
        using var b = candidate.CreateCommand();
        const string query = """
            SELECT ReservationId,BatchId,PlanId,PlanName,LeafSha256,ProfileOwner,ProfileName
            FROM um6_create_intents ORDER BY ReservationId COLLATE BINARY;
            """;
        a.CommandText = query;
        b.CommandText = query;
        using var left = a.ExecuteReader();
        using var right = b.ExecuteReader();
        while (true)
        {
            bool hasLeft = left.Read(), hasRight = right.Read();
            if (hasLeft != hasRight) throw RestoreConflict();
            if (!hasLeft) return;
            for (int i = 0; i < 7; i++)
                if (left.IsDBNull(i) || right.IsDBNull(i) || !Equals(left.GetValue(i), right.GetValue(i)))
                    throw RestoreConflict();
        }
    }

    private static InvalidOperationException RestoreConflict() =>
        new("UM6 creation evidence or its local target differs; restore requires explicit reconciliation.");
}
