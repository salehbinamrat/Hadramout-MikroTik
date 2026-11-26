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
        ValidateId(routerId);
        if (username.IsEmpty) throw new ArgumentException("Username is required.", nameof(username));
        if (username.Length > RouterCredentialProtector.MaxSecretLength ||
            password.Length > RouterCredentialProtector.MaxSecretLength)
            throw new ArgumentException("Credential exceeds the supported length.");

        byte[] userEnvelope = RouterCredentialProtector.Protect(routerId, "username", username);
        byte[] passEnvelope = RouterCredentialProtector.Protect(routerId, "password", password);
        using var connection = DatabaseStore.Open(databasePath);
        using var tx = connection.BeginTransaction(deferred: false);
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
        tx.Commit();
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
        byte[] user = RouterCredentialProtector.Unprotect(routerId, "username", reader.GetFieldValue<byte[]>(0));
        try
        {
            byte[] pass = RouterCredentialProtector.Unprotect(routerId, "password", reader.GetFieldValue<byte[]>(1));
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
