using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

// Caller owns and must dispose the plaintext lease. No string or logging representation.
public sealed class RouterCredentialLease : IDisposable
{
    private byte[]? username;
    private byte[]? password;

    internal RouterCredentialLease(byte[] username, byte[] password)
    {
        this.username = username;
        this.password = password;
    }

    public ReadOnlySpan<byte> Username => username ?? throw new ObjectDisposedException(nameof(RouterCredentialLease));
    public ReadOnlySpan<byte> Password => password ?? throw new ObjectDisposedException(nameof(RouterCredentialLease));

    // Async transport borrows these buffers only while the owning lease is alive.
    internal ReadOnlyMemory<byte> UsernameMemory => username ?? throw new ObjectDisposedException(nameof(RouterCredentialLease));
    internal ReadOnlyMemory<byte> PasswordMemory => password ?? throw new ObjectDisposedException(nameof(RouterCredentialLease));

    public void Dispose()
    {
        if (username is not null) CryptographicOperations.ZeroMemory(username);
        if (password is not null) CryptographicOperations.ZeroMemory(password);
        username = null;
        password = null;
    }
}

/// <summary>Local per-Windows-user router credential storage; only ciphertext is sent to SQLite.</summary>
[SupportedOSPlatform("windows")]
public sealed class RouterCredentialStore(string databasePath)
{
    public void Save(Guid routerId, ReadOnlySpan<byte> username, ReadOnlySpan<byte> password)
    {
        ValidateInput(routerId, username, password);
        using var connection = DatabaseStore.Open(databasePath);
        using var tx = connection.BeginTransaction(deferred: false);
        WriteCredentials(connection, tx, routerId, username, password);
        tx.Commit();
    }

    // Explicit re-entry for a trusted restored candidate only. Readable or absent records
    // cannot be replaced by this recovery API. Check and replace in the same transaction.
    public void ReenterUnavailable(Guid routerId, ReadOnlySpan<byte> username, ReadOnlySpan<byte> password)
    {
        ValidateInput(routerId, username, password);
        using var connection = DatabaseStore.OpenExisting(databasePath);
        using var tx = connection.BeginTransaction(deferred: false);
        if (RestoreCredentialInspector.ReadStatus(connection, tx, routerId) != RestoreCredentialState.Unavailable)
            throw new InvalidOperationException("Only unavailable restored credentials may be re-entered.");
        WriteCredentials(connection, tx, routerId, username, password);
        tx.Commit();
    }

    private static void ValidateInput(Guid routerId, ReadOnlySpan<byte> username, ReadOnlySpan<byte> password)
    {
        ValidateId(routerId);
        if (username.IsEmpty) throw new ArgumentException("Username is required.", nameof(username));
        if (username.Length > RouterCredentialProtector.MaxSecretLength ||
            password.Length > RouterCredentialProtector.MaxSecretLength)
            throw new ArgumentException("Credential exceeds the supported length.");
    }

    private static void WriteCredentials(SqliteConnection connection, SqliteTransaction tx, Guid routerId,
        ReadOnlySpan<byte> username, ReadOnlySpan<byte> password)
    {
        byte[] userEnvelope = RouterCredentialProtector.Protect(routerId, "username", username);
        byte[] passEnvelope = RouterCredentialProtector.Protect(routerId, "password", password);
        using var cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO router_credentials(RouterId, UsernameEnvelope, PasswordEnvelope)
            VALUES($id, $username, $password)
            ON CONFLICT(RouterId) DO UPDATE SET
              UsernameEnvelope=excluded.UsernameEnvelope, PasswordEnvelope=excluded.PasswordEnvelope;
            """;
        cmd.Parameters.AddWithValue("$id", routerId);
        cmd.Parameters.Add("$username", SqliteType.Blob).Value = userEnvelope;
        cmd.Parameters.Add("$password", SqliteType.Blob).Value = passEnvelope;
        cmd.ExecuteNonQuery();
        AuditStore.Append(connection, tx, AuditKind.CredentialSaved, routerId);
    }

    public RouterCredentialLease? Load(Guid routerId)
    {
        ValidateId(routerId);
        using var connection = DatabaseStore.Open(databasePath);
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT UsernameEnvelope, PasswordEnvelope FROM router_credentials WHERE RouterId=$id;";
        cmd.Parameters.AddWithValue("$id", routerId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return OpenLease(routerId, reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1));
    }

    // Bound operations must not initialize or migrate a database during a read.
    // Bound blob sizes before materializing them, including on a damaged database.
    internal RouterCredentialLease? LoadReadOnly(Guid routerId)
    {
        ValidateId(routerId);
        if (!Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException("Absolute database path required.", nameof(databasePath));
        using var c = DatabaseBackup.OpenRaw(databasePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(c);
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT CASE WHEN typeof(UsernameEnvelope)='blob' AND length(UsernameEnvelope) BETWEEN 1 AND $max
                         THEN UsernameEnvelope END,
                   CASE WHEN typeof(PasswordEnvelope)='blob' AND length(PasswordEnvelope) BETWEEN 1 AND $max
                         THEN PasswordEnvelope END
            FROM router_credentials WHERE RouterId=$id;
            """;
        cmd.Parameters.AddWithValue("$id", routerId);
        cmd.Parameters.AddWithValue("$max", RouterCredentialProtector.MaxEnvelopeLength);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        if (reader.IsDBNull(0) || reader.IsDBNull(1))
            throw new CryptographicException("Stored router credential is unavailable or invalid.");
        return OpenLease(routerId, reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1));
    }

    internal static RouterCredentialLease OpenLease(Guid routerId, byte[] usernameEnvelope, byte[] passwordEnvelope)
    {
        byte[] user = RouterCredentialProtector.Unprotect(routerId, "username", usernameEnvelope);
        try
        {
            if (user.Length == 0) throw new CryptographicException("Stored router credential is unavailable or invalid.");
            byte[] pass = RouterCredentialProtector.Unprotect(routerId, "password", passwordEnvelope);
            return new RouterCredentialLease(user, pass);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(user);
            throw;
        }
    }

    public bool Remove(Guid routerId)
    {
        ValidateId(routerId);
        using var connection = DatabaseStore.Open(databasePath);
        using var tx = connection.BeginTransaction(deferred: false);
        using var cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "DELETE FROM router_credentials WHERE RouterId=$id;";
        cmd.Parameters.AddWithValue("$id", routerId);
        bool removed = cmd.ExecuteNonQuery() == 1;
        if (removed) AuditStore.Append(connection, tx, AuditKind.CredentialRemoved, routerId);
        tx.Commit();
        return removed;
    }

    private static void ValidateId(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("A router identity is required.", nameof(id));
    }
}
