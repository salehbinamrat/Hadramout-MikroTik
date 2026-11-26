using System.Security.Cryptography.X509Certificates;
using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

internal sealed record RouterTarget(Guid RouterId, string Host, int Port,
    string CertificateName, string LeafSha256, byte[] TrustedRootDer);

// Local configuration only. Enrollment is not proof of contact with a device.
// Caller must provision the CA and fingerprint independently; no network discovery/TOFU.
internal sealed class RouterTargetStore(string databasePath)
{
    internal void Enroll(Guid routerId, string host, int port, string certificateName,
        string leafSha256, ReadOnlySpan<byte> trustedRootDer)
    {
        var target = Validate(routerId, host, port, certificateName, leafSha256, trustedRootDer);
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO router_targets(RouterId,Host,Port,CertificateName,LeafSha256,TrustedRootDer)
            VALUES($id,$host,$port,$name,$pin,$root);
            """;
        cmd.Parameters.AddWithValue("$id", target.RouterId);
        cmd.Parameters.AddWithValue("$host", target.Host);
        cmd.Parameters.AddWithValue("$port", target.Port);
        cmd.Parameters.AddWithValue("$name", target.CertificateName);
        cmd.Parameters.AddWithValue("$pin", target.LeafSha256);
        cmd.Parameters.Add("$root", SqliteType.Blob).Value = target.TrustedRootDer;
        cmd.ExecuteNonQuery();
        tx.Commit();
    }

    internal RouterTarget? Read(Guid routerId)
    {
        if (routerId == Guid.Empty) throw new ArgumentException("Router identity required.", nameof(routerId));
        if (!Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException("Absolute database path required.", nameof(databasePath));
        using var c = DatabaseBackup.OpenRaw(databasePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(c);
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT Host,Port,CertificateName,LeafSha256,
                CASE WHEN typeof(TrustedRootDer)='blob' AND length(TrustedRootDer) BETWEEN 1 AND 65536
                     THEN TrustedRootDer END
            FROM router_targets WHERE RouterId=$id;
            """;
        cmd.Parameters.AddWithValue("$id", routerId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        if (reader.IsDBNull(4)) throw new InvalidDataException("Invalid stored router target trust anchor.");
        var target = Validate(routerId, reader.GetString(0), reader.GetInt32(1),
            reader.GetString(2), reader.GetString(3), reader.GetFieldValue<byte[]>(4));
        if (target.Host != reader.GetString(0) || target.CertificateName != reader.GetString(2) ||
            target.LeafSha256 != reader.GetString(3))
            throw new InvalidDataException("Noncanonical stored router target.");
        return target;
    }

    private static RouterTarget Validate(Guid id, string host, int port, string name,
        string pin, ReadOnlySpan<byte> rootDer)
    {
        if (id == Guid.Empty) throw new ArgumentException("Router identity required.", nameof(id));
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        host = RouterOsReadAdmission.NormalizeHost(host);
        name = RouterOsReadAdmission.NormalizeHost(name);
        if (host.Length is < 1 or > 253 || name.Length is < 1 or > 253)
            throw new ArgumentException("Invalid target name length.");
        pin = Convert.ToHexString(RouterOsTlsTransport.ParseLeafPin(pin));
        if (rootDer.Length is < 1 or > 65536)
            throw new ArgumentException("Explicit private CA DER required.", nameof(rootDer));
        using var root = X509CertificateLoader.LoadCertificate(rootDer);
        if (!root.RawData.AsSpan().SequenceEqual(rootDer) ||
            !root.Extensions.OfType<X509BasicConstraintsExtension>().Any(x => x.CertificateAuthority))
            throw new ArgumentException("An exact DER CA certificate is required.", nameof(rootDer));
        return new(id, host, port, name, pin, rootDer.ToArray());
    }

    // Compare all provisioned trust records, including routers without creation history.
    // No implicit trust change by backup rollback. Caller holds exclusive managed gate.
    internal static void RequireEquivalentForRestore(string currentPath, string candidatePath)
    {
        using var current = DatabaseBackup.OpenRaw(currentPath, SqliteOpenMode.ReadOnly);
        using var candidate = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(current);
        DatabaseBackup.RequireIdentity(candidate);
        using var a = current.CreateCommand();
        using var b = candidate.CreateCommand();
        const string query = """
            SELECT RouterId,Host,Port,CertificateName,LeafSha256,TrustedRootDer
            FROM router_targets ORDER BY RouterId COLLATE BINARY;
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
            for (int i = 0; i < 5; i++)
                if (!Equals(left.GetValue(i), right.GetValue(i))) throw Conflict();
            if (!left.GetFieldValue<byte[]>(5).AsSpan().SequenceEqual(right.GetFieldValue<byte[]>(5)))
                throw Conflict();
        }
    }

    private static InvalidOperationException Conflict() =>
        new("Router trust configuration differs; explicit enrollment reconciliation is required.");
}
