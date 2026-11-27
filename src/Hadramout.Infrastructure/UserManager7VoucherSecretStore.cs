using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

// Local storage only. No send permission or claim. Reuse the existing protector
// and disposable zeroing lease; UM7 uses a disjoint authenticated purpose.
internal sealed class UserManager7VoucherSecretStore(string databasePath)
{
    private const string Purpose = "um7-voucher-password/v1";

    [SupportedOSPlatform("windows")]
    internal void Save(Guid reservationId, ReadOnlySpan<byte> password)
    {
        ValidateId(reservationId);
        UserManager6CreateWire.ValidatePassword(password);
        byte[] envelope = RouterCredentialProtector.Protect(reservationId, Purpose, password);
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO um7_voucher_secrets(ReservationId,PasswordEnvelope) VALUES($id,$password);";
        cmd.Parameters.AddWithValue("$id", reservationId);
        cmd.Parameters.Add("$password", SqliteType.Blob).Value = envelope;
        cmd.ExecuteNonQuery();
        tx.Commit();
    }

    [SupportedOSPlatform("windows")]
    internal UserManager6VoucherSecretLease? Load(Guid reservationId)
    {
        ValidateId(reservationId);
        if (!Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException("Absolute database path required.", nameof(databasePath));
        using var c = DatabaseBackup.OpenRaw(databasePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(c);
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT CASE WHEN typeof(s.PasswordEnvelope)='blob' AND length(s.PasswordEnvelope) BETWEEN 1 AND $max
                       THEN s.PasswordEnvelope END,
                   CASE WHEN EXISTS (
            SELECT 1 FROM um7_create_intents i
            JOIN voucher_reservations v ON v.Id=i.ReservationId AND v.BackendId=i.BackendId AND v.BatchId=i.BatchId AND v.Username=i.Username
            JOIN backends b ON b.Id=i.BackendId AND b.Kind=3 AND b.RouterId=i.RouterId
            JOIN voucher_batches batch ON batch.Id=i.BatchId AND batch.BackendId=i.BackendId AND batch.PlanId=i.PlanId
            JOIN plans p ON p.Id=i.PlanId AND p.BackendId=i.BackendId AND p.Name=i.PlanName
            JOIN router_targets t ON t.RouterId=i.RouterId AND t.LeafSha256=i.LeafSha256
                       WHERE i.ReservationId=s.ReservationId
                         AND NOT EXISTS (SELECT 1 FROM um6_create_journal j WHERE j.ReservationId=i.ReservationId)
                   ) THEN 1 ELSE 0 END
            FROM um7_voucher_secrets s WHERE s.ReservationId=$id;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        cmd.Parameters.AddWithValue("$max", RouterCredentialProtector.MaxEnvelopeLength);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        if (reader.GetInt32(1) != 1)
            throw new InvalidOperationException("UM7 creation intent no longer matches local scope.");
        if (reader.IsDBNull(0)) throw Failure();
        byte[]? clear = null;
        try
        {
            clear = RouterCredentialProtector.Unprotect(reservationId, Purpose, reader.GetFieldValue<byte[]>(0));
            UserManager6CreateWire.ValidatePassword(clear);
            var lease = new UserManager6VoucherSecretLease(clear);
            clear = null; // ownership transferred
            return lease;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            throw Failure();
        }
        finally
        {
            if (clear is not null) CryptographicOperations.ZeroMemory(clear);
        }
    }

    // The managed restore gate also compares the retained intent and target.
    internal static void RequireEquivalentForRestore(string currentPath, string candidatePath)
    {
        using var current = DatabaseBackup.OpenRaw(currentPath, SqliteOpenMode.ReadOnly);
        using var candidate = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(current);
        DatabaseBackup.RequireIdentity(candidate);
        using var a = current.CreateCommand();
        using var b = candidate.CreateCommand();
        const string query = """
            SELECT ReservationId, CASE WHEN typeof(PasswordEnvelope)='blob'
                AND length(PasswordEnvelope) BETWEEN 1 AND 20513 THEN PasswordEnvelope END
            FROM um7_voucher_secrets ORDER BY ReservationId COLLATE BINARY;
            """;
        a.CommandText = query;
        b.CommandText = query;
        using var left = a.ExecuteReader();
        using var right = b.ExecuteReader();
        while (true)
        {
            bool hasLeft = left.Read(), hasRight = right.Read();
            if (hasLeft != hasRight) throw Conflict();
            if (!hasLeft) return;
            if (left.GetString(0) != right.GetString(0) || left.IsDBNull(1) || right.IsDBNull(1) ||
                !left.GetFieldValue<byte[]>(1).AsSpan().SequenceEqual(right.GetFieldValue<byte[]>(1)))
                throw Conflict();
        }
    }

    private static void ValidateId(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("Reservation identity required.", nameof(id));
    }
    private static CryptographicException Failure() => new("Stored UM7 voucher password is unavailable or invalid.");
    private static InvalidOperationException Conflict() => new("UM7 voucher secret evidence differs; reconciliation required.");
}
