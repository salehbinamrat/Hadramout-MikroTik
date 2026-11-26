using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

internal enum UserManager6CreateState { Prepared = 1, DispatchStarted = 2, Indeterminate = 3, Acknowledged = 4 }

internal sealed record UserManager6CreateEntry(Guid ReservationId, Guid BackendId, Guid RouterId,
    string Customer, string Username, UserManager6CreateState State);

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
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT BackendId,RouterId,Customer,Username,State FROM um6_create_journal WHERE ReservationId=$id;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? new(reservationId, reader.GetGuid(0), reader.GetGuid(1),
            reader.GetString(2), reader.GetString(3), (UserManager6CreateState)reader.GetInt32(4)) : null;
    }

    // True grants the one-shot local dispatch claim. False never authorizes a remote send.
    internal bool TryBeginDispatch(Guid reservationId) =>
        Transition(reservationId, UserManager6CreateState.Prepared, UserManager6CreateState.DispatchStarted);

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

    private static InvalidOperationException RestoreConflict() =>
        new("UM6 creation evidence or its local target differs; restore requires explicit reconciliation.");
}
