using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

// The caller owns this lease. No plaintext strings or copies are produced here.
internal sealed class UserManager6VoucherSecretLease(byte[] clear) : IDisposable
{
    private byte[]? value = clear;
    internal ReadOnlyMemory<byte> Password => value ?? throw new ObjectDisposedException(nameof(UserManager6VoucherSecretLease));
    public void Dispose()
    {
        var bytes = Interlocked.Exchange(ref value, null);
        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
    }
}

internal sealed class UserManager6VoucherSecretStore(string databasePath)
{
    // Existing authenticated envelope format, disjoint field purpose and reservation identity.
    private const string Purpose = "um6-voucher-password/v1";

    [SupportedOSPlatform("windows")]
    internal void Save(Guid reservationId, ReadOnlySpan<byte> password)
    {
        ValidateId(reservationId);
        if (password.Length > RouterCredentialProtector.MaxSecretLength)
            throw new ArgumentException("Voucher password exceeds supported length.", nameof(password));
        byte[] envelope = RouterCredentialProtector.Protect(reservationId, Purpose, password);
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO um6_voucher_secrets(ReservationId,PasswordEnvelope) VALUES($id,$password);
            """;
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
        return Load(c, null, reservationId);
    }

    [SupportedOSPlatform("windows")]
    internal static UserManager6VoucherSecretLease? Load(SqliteConnection c, SqliteTransaction? tx, Guid reservationId)
    {
        ValidateId(reservationId);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            SELECT CASE WHEN typeof(PasswordEnvelope)='blob' AND length(PasswordEnvelope) BETWEEN 1 AND $max
                THEN PasswordEnvelope END FROM um6_voucher_secrets WHERE ReservationId=$id;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        cmd.Parameters.AddWithValue("$max", RouterCredentialProtector.MaxEnvelopeLength);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        if (reader.IsDBNull(0)) throw Failure();
        try { return new(RouterCredentialProtector.Unprotect(reservationId, Purpose, reader.GetFieldValue<byte[]>(0))); }
        catch (CryptographicException) { throw Failure(); }
    }

    private static CryptographicException Failure() => new("Stored voucher password is unavailable or invalid.");
    private static void ValidateId(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("Reservation identity required.", nameof(id));
    }

    // Compare ciphertext exactly, without decrypting or replacing it.
    // A missing or different record must never be reintroduced by restoring a backup.
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
            FROM um6_voucher_secrets ORDER BY ReservationId COLLATE BINARY;
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

    private static InvalidOperationException Conflict() =>
        new("Voucher secret evidence differs; explicit reconciliation is required.");
}
