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

    // Until durable reconciliation across generations is implemented, no journal
    // may be lost or reintroduced by switching the active database.
    internal static void RequireEmptyForRestore(string path)
    {
        using var c = DatabaseBackup.OpenRaw(path, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(c);
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT EXISTS(SELECT 1 FROM um6_create_journal);";
        if ((long)cmd.ExecuteScalar()! != 0)
            throw new InvalidOperationException("UM6 creation evidence requires reconciliation before restore activation.");
    }
}
