using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

public sealed record BackupReceipt(string Sha256, long Bytes);

/// <summary>Local trusted-source snapshots. Restores to a new candidate, never replaces a live database.</summary>
public static class DatabaseBackup
{
    public static BackupReceipt Create(string sourcePath, string backupPath)
    {
        ValidatePaths(sourcePath, backupPath);
        return Stage(backupPath, staged =>
        {
            using (var source = OpenRaw(sourcePath, SqliteOpenMode.ReadOnly))
            {
                RequireIdentity(source);
                using var target = OpenRaw(staged, SqliteOpenMode.ReadWriteCreate);
                source.BackupDatabase(target);
            }
            using (var target = DatabaseStore.Open(staged))
            {
                using var tx = target.BeginTransaction(deferred: false);
                AuditStore.Append(target, tx, AuditKind.BackupSnapshotCreated, null);
                tx.Commit();
                MakeStandalone(target);
            }
            ValidateSnapshot(staged);
        });
    }

    /// <summary>Expected SHA-256 must come from a trusted separate receipt. No active file is overwritten.</summary>
    public static BackupReceipt PrepareRestore(string backupPath, string newDatabasePath, string expectedSha256)
    {
        ValidatePaths(backupPath, newDatabasePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);
        byte[] expected = Convert.FromHexString(expectedSha256);
        if (expected.Length != 32) throw new ArgumentException("Expected SHA-256 digest.", nameof(expectedSha256));
        EnsureStandalone(backupPath);
        return Stage(newDatabasePath, staged =>
        {
            // Copy first, verify the exact bytes staged, then open the verified copy only.
            using (var source = new FileStream(backupPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var destination = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                source.CopyTo(destination);
                destination.Flush(flushToDisk: true);
            }
            using (var input = File.OpenRead(staged))
            {
                if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(input), expected))
                    throw new InvalidDataException("Backup digest does not match.");
            }
            ValidateSnapshot(staged);
            using (var target = DatabaseStore.Open(staged))
            {
                using var tx = target.BeginTransaction(deferred: false);
                AuditStore.Append(target, tx, AuditKind.RestoreCandidatePrepared, null);
                tx.Commit();
                MakeStandalone(target);
            }
            ValidateSnapshot(staged);
        });
    }

    private static BackupReceipt Stage(string destination, Action<string> create)
    {
        string parent = Path.GetDirectoryName(destination)!;
        string stageDirectory = Path.Combine(parent, ".hadramout-stage-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stageDirectory);
        string staged = Path.Combine(stageDirectory, "snapshot.db");
        try
        {
            create(staged);
            EnsureStandalone(staged);
            string hash;
            long bytes;
            using (var input = File.OpenRead(staged))
            {
                bytes = input.Length;
                hash = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
            }
            EnsureDestinationAbsent(destination);
            File.Move(staged, destination, overwrite: false);
            return new BackupReceipt(hash, bytes);
        }
        finally { Directory.Delete(stageDirectory, recursive: true); }
    }

    private static void ValidatePaths(string source, string destination)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);
        if (!Path.IsPathFullyQualified(source) || !Path.IsPathFullyQualified(destination))
            throw new ArgumentException("Absolute local paths are required.");
        if (string.Equals(Path.GetFullPath(source), Path.GetFullPath(destination),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new IOException("Source and destination must differ.");
        if (!File.Exists(source)) throw new FileNotFoundException("Database source is missing.");
        if (!Directory.Exists(Path.GetDirectoryName(destination))) throw new DirectoryNotFoundException("Destination directory is missing.");
        EnsureDestinationAbsent(destination);
    }

    private static void EnsureDestinationAbsent(string path)
    {
        if (File.Exists(path) || Directory.Exists(path)) throw new IOException("Destination already exists.");
        EnsureStandalone(path);
    }

    private static void EnsureStandalone(string path)
    {
        foreach (string suffix in new[] { "-wal", "-shm", "-journal" })
            if (File.Exists(path + suffix) || Directory.Exists(path + suffix))
                throw new IOException("Unexpected SQLite sidecar; a standalone snapshot is required.");
    }

    private static SqliteConnection OpenRaw(string path, SqliteOpenMode mode)
    {
        var c = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Mode = mode, ForeignKeys = true, Pooling = false, DefaultTimeout = 10
        }.ToString());
        try { c.Open(); return c; }
        catch { c.Dispose(); throw; }
    }

    private static void RequireIdentity(SqliteConnection c)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA application_id;";
        if ((long)cmd.ExecuteScalar()! != DatabaseStore.ApplicationId)
            throw new InvalidDataException("Backup belongs to another application.");
        cmd.CommandText = "PRAGMA user_version;";
        if ((long)cmd.ExecuteScalar()! != DatabaseStore.CurrentSchemaVersion)
            throw new InvalidDataException("Backup schema version is not supported by this release.");
    }

    private static void ValidateSnapshot(string path)
    {
        EnsureStandalone(path);
        using var c = OpenRaw(path, SqliteOpenMode.ReadOnly);
        RequireIdentity(c);
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA integrity_check;";
        using (var r = cmd.ExecuteReader())
        {
            if (!r.Read() || r.GetString(0) != "ok" || r.Read())
                throw new InvalidDataException("Backup integrity check failed.");
        }
        cmd.CommandText = "PRAGMA foreign_key_check;";
        using (var r = cmd.ExecuteReader())
            if (r.Read()) throw new InvalidDataException("Backup contains broken relationships.");
        cmd.CommandText = """
            SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN
            ('sites','routers','backends','plans','voucher_batches','voucher_reservations','router_credentials','audit_events');
            """;
        if ((long)cmd.ExecuteScalar()! != 8)
            throw new InvalidDataException("Backup is missing required tables.");
    }

    private static void MakeStandalone(SqliteConnection c)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
        using (var r = cmd.ExecuteReader())
            if (!r.Read() || r.GetInt32(0) != 0) throw new IOException("Snapshot checkpoint failed.");
        cmd.CommandText = "PRAGMA journal_mode=DELETE;";
        if (!string.Equals(cmd.ExecuteScalar() as string, "delete", StringComparison.OrdinalIgnoreCase))
            throw new IOException("Snapshot cannot be made standalone.");
    }
}
