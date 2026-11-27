using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

internal enum UserManager7CreateClaimState { DispatchStarted = 2, Indeterminate = 3 }

// Local qualification primitive only. No network I/O, no authorization or proof
// of remote execution. An exclusive managed-generation lease is required for
// future production integration.
internal sealed class UserManager7CreateClaimStore(string databasePath)
{
    [SupportedOSPlatform("windows")]
    internal UserManager6VoucherSecretLease? TryClaimForQualification(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT State FROM um7_create_claims WHERE ReservationId=$id;";
        cmd.Parameters.AddWithValue("$id", reservationId);
        if (cmd.ExecuteScalar() is not null) return null;
        // Validation is in the same write transaction as the insert. No lease
        // escapes on missing secret, invalid scope, decrypt or commit failure.
        var secret = UserManager7VoucherSecretStore.Load(c, tx, reservationId);
        if (secret is null) return null;
        try
        {
            cmd.CommandText = "INSERT INTO um7_create_claims(ReservationId,State) VALUES($id,2);";
            cmd.ExecuteNonQuery();
            tx.Commit();
            return secret;
        }
        catch { secret.Dispose(); throw; }
    }

    internal UserManager7CreateClaimState? Read(Guid reservationId)
    {
        ValidateId(reservationId);
        if (!Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException("Absolute database path required.", nameof(databasePath));
        using var c = DatabaseBackup.OpenRaw(databasePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(c);
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT State FROM um7_create_claims WHERE ReservationId=$id;";
        cmd.Parameters.AddWithValue("$id", reservationId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return reader.GetInt32(0) switch
        {
            2 => UserManager7CreateClaimState.DispatchStarted,
            3 => UserManager7CreateClaimState.Indeterminate,
            _ => throw new InvalidDataException("Invalid UM7 creation claim state.")
        };
    }

    internal bool TryMarkIndeterminate(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "UPDATE um7_create_claims SET State=3 WHERE ReservationId=$id AND State=2;";
        cmd.Parameters.AddWithValue("$id", reservationId);
        bool changed = cmd.ExecuteNonQuery() == 1;
        tx.Commit();
        return changed;
    }

    // Caller holds the managed restore gate; the intent and ciphertext are
    // compared independently before this exact claim comparison.
    internal static void RequireEquivalentForRestore(string currentPath, string candidatePath)
    {
        using var current = DatabaseBackup.OpenRaw(currentPath, SqliteOpenMode.ReadOnly);
        using var candidate = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(current);
        DatabaseBackup.RequireIdentity(candidate);
        using var left = current.CreateCommand();
        using var right = candidate.CreateCommand();
        const string query = "SELECT ReservationId,State FROM um7_create_claims ORDER BY ReservationId COLLATE BINARY;";
        left.CommandText = query;
        right.CommandText = query;
        using var a = left.ExecuteReader();
        using var b = right.ExecuteReader();
        while (true)
        {
            bool hasA = a.Read(), hasB = b.Read();
            if (hasA != hasB) throw Conflict();
            if (!hasA) return;
            if (a.GetString(0) != b.GetString(0) || a.GetInt32(1) is not (2 or 3) ||
                a.GetInt32(1) != b.GetInt32(1)) throw Conflict();
        }
    }

    private static void ValidateId(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("Reservation identity required.", nameof(id));
    }

    private static InvalidOperationException Conflict() =>
        new("UM7 creation claim evidence differs; reconciliation required.");
}
