using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
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
            // Verify a supported legacy snapshot before upgrading the authenticated copy.
            ValidateSnapshot(staged, allowLegacyVersion: true);
            using (var target = DatabaseStore.OpenExisting(staged))
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
        string stageDirectory = CreatePrivateWorkspace(parent, ".hadramout-stage-");
        string staged = Path.Combine(stageDirectory, "snapshot.db");
        try
        {
            create(staged);
            return PublishStandalone(staged, destination);
        }
        finally { Directory.Delete(stageDirectory, recursive: true); }
    }

    // A trusted local parent is still required. Do not create plaintext until the
    // workspace's access policy is verified. No permissive fallback.
    internal static string CreatePrivateWorkspace(string parent, string prefix = ".hmk-private-")
    {
        string path = Path.Combine(parent, prefix + Guid.NewGuid().ToString("N"));
        if (Directory.Exists(path) || File.Exists(path))
            throw new IOException("Temporary workspace already exists.");

        if (OperatingSystem.IsWindows())
        {
            EnsurePrivateWindowsDirectory(path);
        }
        else
        {
            const UnixFileMode permissions = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            DirectoryInfo directory = Directory.CreateDirectory(path, permissions);
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0 ||
                File.GetUnixFileMode(path) != permissions)
                throw new UnauthorizedAccessException("Private workspace permissions could not be verified.");
        }
        return path;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static void EnsurePrivateWindowsDirectory(string path)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new UnauthorizedAccessException("Windows user identity unavailable.");
        var policy = new DirectorySecurity();
        policy.SetOwner(user);
        policy.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        policy.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        // Supply the ACL to the creation call rather than hardening after creation.
        DirectoryInfo directory = Directory.Exists(path) ? new DirectoryInfo(path) : policy.CreateDirectory(path);
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Temporary workspace is a reparse point.");
        var actual = directory.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        var rules = actual.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToArray();
        if (!actual.AreAccessRulesProtected || !user.Equals(actual.GetOwner(typeof(SecurityIdentifier))) ||
            rules.Length != 1 || !user.Equals(rules[0].IdentityReference) ||
            rules[0].AccessControlType != AccessControlType.Allow ||
            (rules[0].FileSystemRights & FileSystemRights.FullControl) != FileSystemRights.FullControl ||
            (rules[0].InheritanceFlags & (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit)) !=
                (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) ||
            rules[0].PropagationFlags != PropagationFlags.None || rules[0].IsInherited)
            throw new UnauthorizedAccessException("Private workspace permissions could not be verified.");
    }

    internal static BackupReceipt PublishStandalone(string staged, string destination)
    {
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

    internal static void ValidatePaths(string source, string destination)
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

    internal static SqliteConnection OpenRaw(string path, SqliteOpenMode mode)
    {
        var c = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Mode = mode, ForeignKeys = true, Pooling = false, DefaultTimeout = 10
        }.ToString());
        try { c.Open(); return c; }
        catch { c.Dispose(); throw; }
    }

    internal static void RequireIdentity(SqliteConnection c, bool allowLegacyVersion = false)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA application_id;";
        if ((long)cmd.ExecuteScalar()! != DatabaseStore.ApplicationId)
            throw new InvalidDataException("Backup belongs to another application.");
        cmd.CommandText = "PRAGMA user_version;";
        long version = (long)cmd.ExecuteScalar()!;
        if (version != DatabaseStore.CurrentSchemaVersion && !(allowLegacyVersion && version is 4 or 5 or 6 or 7 or 8 or 9 or 10 or 11 or 12 or 13 or 14))
            throw new InvalidDataException("Backup schema version is not supported by this release.");
    }

    internal static void ValidateSnapshot(string path, bool allowLegacyVersion = false)
    {
        EnsureStandalone(path);
        using var c = OpenRaw(path, SqliteOpenMode.ReadOnly);
        ValidateConnection(c, fullIntegrityCheck: true, allowLegacyVersion);
    }

    // A live DB can legitimately have a WAL; do not require standalone mode at startup.
    internal static void ValidateConnection(SqliteConnection c, bool fullIntegrityCheck, bool allowLegacyVersion = false)
    {
        RequireIdentity(c, allowLegacyVersion);
        using var cmd = c.CreateCommand();
        cmd.CommandText = fullIntegrityCheck ? "PRAGMA integrity_check;" : "PRAGMA quick_check;";
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
        cmd.CommandText = "PRAGMA user_version;";
        long version = (long)cmd.ExecuteScalar()!;
        if (version >= 5)
        {
            cmd.CommandText = """
                SELECT count(*) FROM sqlite_schema WHERE
                    (type='table' AND name='um6_create_journal') OR
                    (type='trigger' AND name IN ('um6_create_insert_guard','um6_create_update_guard','um6_create_no_delete'));
                """;
            if ((long)cmd.ExecuteScalar()! != 4)
                throw new InvalidDataException("Backup is missing UM6 creation journal objects.");
        }
        if (version >= 6)
        {
            cmd.CommandText = """
                SELECT count(*) FROM sqlite_schema WHERE
                    (type='table' AND name='router_targets') OR
                    (type='trigger' AND name IN ('router_target_no_update','router_target_no_delete'));
                """;
            if ((long)cmd.ExecuteScalar()! != 3)
                throw new InvalidDataException("Backup is missing router target objects.");
        }
        if (version >= 7)
        {
            cmd.CommandText = """
                SELECT count(*) FROM sqlite_schema WHERE
                    (type='table' AND name='um6_create_intents') OR
                    (type='trigger' AND name IN ('um6_intent_insert_guard','um6_intent_no_update','um6_intent_no_delete'));
                """;
            if ((long)cmd.ExecuteScalar()! != 4)
                throw new InvalidDataException("Backup is missing UM6 creation intent objects.");
        }
        if (version >= 8)
        {
            cmd.CommandText = """
                SELECT count(*) FROM sqlite_schema WHERE
                    (type='table' AND name='um6_voucher_secrets') OR
                    (type='trigger' AND name IN ('um6_secret_insert_guard','um6_secret_no_update','um6_secret_no_delete'));
                """;
            if ((long)cmd.ExecuteScalar()! != 4)
                throw new InvalidDataException("Backup is missing UM6 voucher secret objects.");
        }
        if (version >= 9)
        {
            cmd.CommandText = """
                SELECT count(*) FROM sqlite_schema WHERE
                    (type='table' AND name='um6_create_evidence') OR
                    (type='trigger' AND name IN ('um6_evidence_insert_guard','um6_evidence_no_update','um6_evidence_no_delete'));
                """;
            if ((long)cmd.ExecuteScalar()! != 4)
                throw new InvalidDataException("Backup is missing UM6 creation evidence objects.");
        }
        if (version >= 10)
        {
            cmd.CommandText = """
                SELECT count(*) FROM sqlite_schema WHERE
                    (type='table' AND name='um6_recovery_evidence') OR
                    (type='trigger' AND name IN ('um6_recovery_insert_guard','um6_recovery_no_update',
                        'um6_recovery_no_delete','um6_recovery_consistency_guard'));
                """;
            if ((long)cmd.ExecuteScalar()! != 5)
                throw new InvalidDataException("Backup is missing UM6 recovery evidence objects.");
        }
        if (version >= 11)
        {
            cmd.CommandText = """
                SELECT count(*) FROM sqlite_schema WHERE
                    (type='table' AND name='um6_profile_link_journal') OR
                    (type='trigger' AND name IN ('um6_profile_link_insert_guard',
                        'um6_profile_link_update_guard','um6_profile_link_no_delete'));
                """;
            if ((long)cmd.ExecuteScalar()! != 4)
                throw new InvalidDataException("Backup is missing UM6 profile link journal objects.");
        }
        if (version >= 12)
        {
            cmd.CommandText = """
                SELECT count(*) FROM sqlite_schema WHERE
                    (type='table' AND name='um7_create_intents') OR
                    (type='trigger' AND name IN ('um7_intent_insert_guard','um7_intent_no_update',
                        'um7_intent_no_delete','um7_intent_exclude_um6'));
                """;
            if ((long)cmd.ExecuteScalar()! != 5)
                throw new InvalidDataException("Backup is missing UM7 creation intent objects.");
        }
        if (version >= 13)
        {
            cmd.CommandText = """
                SELECT count(*) FROM sqlite_schema WHERE
                    (type='table' AND name='um7_voucher_secrets') OR
                    (type='trigger' AND name IN ('um7_secret_insert_guard','um7_secret_no_update','um7_secret_no_delete'));
                """;
            if ((long)cmd.ExecuteScalar()! != 4)
                throw new InvalidDataException("Backup is missing UM7 voucher secret objects.");
        }
        if (version >= 14)
        {
            cmd.CommandText = """
                SELECT count(*) FROM sqlite_schema WHERE
                    (type='table' AND name='um7_create_claims') OR
                    (type='trigger' AND name IN ('um7_claim_insert_guard','um7_claim_update_guard','um7_claim_no_delete'));
                """;
            if ((long)cmd.ExecuteScalar()! != 4)
                throw new InvalidDataException("Backup is missing UM7 creation claim objects.");
        }
        if (version >= 15)
        {
            cmd.CommandText = """
                SELECT count(*) FROM sqlite_schema WHERE
                    (type='table' AND name='um7_create_acknowledgements') OR
                    (type='trigger' AND name IN ('um7_ack_insert_guard','um7_ack_no_update',
                        'um7_ack_no_delete','um7_ack_exclude_indeterminate'));
                """;
            if ((long)cmd.ExecuteScalar()! != 5)
                throw new InvalidDataException("Backup is missing UM7 acknowledgement objects.");
        }
    }

    internal static void MakeStandalone(SqliteConnection c)
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
