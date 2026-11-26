using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

public sealed record ProtectedRestoreReceipt(BackupReceipt Precaution, BackupReceipt Candidate);

/// <summary>Authenticated local backups. Restore prepares a new database, never overwrites live data.</summary>
public static class EncryptedDatabaseBackup
{
    public const long MaximumSnapshotBytes = 16L * 1024 * 1024 * 1024;

    // Workspace parents must be trusted private local storage.
    public static BackupReceipt Create(string sourcePath, string encryptedPath, ReadOnlySpan<byte> password)
    {
        ValidatePassword(password);
        DatabaseBackup.ValidatePaths(sourcePath, encryptedPath);
        string workspace = CreateWorkspace(Path.GetDirectoryName(sourcePath)!);
        try
        {
            string snapshot = Path.Combine(workspace, "snapshot.db");
            DatabaseBackup.Create(sourcePath, snapshot);
            return EncryptSnapshot(snapshot, encryptedPath, password, verify: false);
        }
        finally { Directory.Delete(workspace, recursive: true); }
    }

    private static BackupReceipt EncryptSnapshot(string snapshot, string encryptedPath,
        ReadOnlySpan<byte> password, bool verify)
    {
        string temporaryOutput = Path.Combine(Path.GetDirectoryName(encryptedPath)!,
            ".hmk-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var input = new FileStream(snapshot, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var output = new FileStream(temporaryOutput, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                BackupEnvelope.Write(input, output, password);
                output.Flush(flushToDisk: true);
            }
            if (verify)
            {
                // Independently read the encrypted stream before publishing the safety copy.
                using var input = File.OpenRead(temporaryOutput);
                BackupEnvelope.Read(input, Stream.Null, password);
            }
            return DatabaseBackup.PublishStandalone(temporaryOutput, encryptedPath);
        }
        finally { File.Delete(temporaryOutput); }
    }

    public static BackupReceipt PrepareRestore(string encryptedPath, string candidatePath, ReadOnlySpan<byte> password)
    {
        ValidatePassword(password);
        DatabaseBackup.ValidatePaths(encryptedPath, candidatePath);
        string workspace = CreateWorkspace(Path.GetDirectoryName(candidatePath)!);
        try
        {
            string snapshot = Path.Combine(workspace, "snapshot.db");
            using (var input = new FileStream(encryptedPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var output = new FileStream(snapshot, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                // Only authenticated chunks reach the private staging file; never open SQLite
                // or publish a candidate until the entire envelope has been verified.
                BackupEnvelope.Read(input, output, password);
                output.Flush(flushToDisk: true);
            }
            string digest;
            using (var input = File.OpenRead(snapshot))
                digest = Convert.ToHexString(SHA256.HashData(input));
            return DatabaseBackup.PrepareRestore(snapshot, candidatePath, digest);
        }
        finally { Directory.Delete(workspace, recursive: true); }
    }

    /// <summary>
    /// Prepares a candidate and verified precaution from the same current-history snapshot.
    /// Caller must quiesce current writers for activation; this method never activates or replaces data.
    /// A published precaution is deliberately retained even when candidate preparation later fails.
    /// </summary>
    public static ProtectedRestoreReceipt PrepareWithPrecaution(string currentPath, string encryptedPath,
        string candidatePath, string precautionPath, ReadOnlySpan<byte> backupPassword,
        ReadOnlySpan<byte> precautionPassword)
    {
        ValidatePassword(backupPassword);
        ValidatePassword(precautionPassword);
        DatabaseBackup.ValidatePaths(currentPath, precautionPath);
        DatabaseBackup.ValidatePaths(encryptedPath, candidatePath);
        // Validate all destinations against both sources and each other before creating anything.
        DatabaseBackup.ValidatePaths(currentPath, candidatePath);
        DatabaseBackup.ValidatePaths(encryptedPath, precautionPath);
        if (string.Equals(Path.GetFullPath(candidatePath), Path.GetFullPath(precautionPath),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new IOException("Candidate and precaution destinations must differ.");

        string candidateWorkspace = CreateWorkspace(Path.GetDirectoryName(candidatePath)!);
        try
        {
            string staged = Path.Combine(candidateWorkspace, "candidate.db");
            // Authenticate incoming backup before creating a safety copy or opening its SQLite data.
            PrepareRestore(encryptedPath, staged, backupPassword);
            string currentWorkspace = CreateWorkspace(Path.GetDirectoryName(currentPath)!);
            try
            {
                string history = Path.Combine(currentWorkspace, "current.db");
                DatabaseBackup.Create(currentPath, history);
                var precaution = EncryptSnapshot(history, precautionPath, precautionPassword, verify: true);
                using (var source = DatabaseBackup.OpenRaw(history, SqliteOpenMode.ReadOnly))
                using (var target = DatabaseStore.OpenExisting(staged))
                {
                    using (var tx = target.BeginTransaction(deferred: false))
                    {
                        AuditStore.MergeHistory(source, target, tx);
                        tx.Commit();
                    }
                    DatabaseBackup.MakeStandalone(target);
                }
                DatabaseBackup.ValidateSnapshot(staged);
                var candidate = DatabaseBackup.PublishStandalone(staged, candidatePath);
                return new ProtectedRestoreReceipt(precaution, candidate);
            }
            finally { Directory.Delete(currentWorkspace, recursive: true); }
        }
        finally { Directory.Delete(candidateWorkspace, recursive: true); }
    }

    private static string CreateWorkspace(string parent)
    {
        string path = Path.Combine(parent, ".hmk-private-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void ValidatePassword(ReadOnlySpan<byte> password)
    {
        if (password.Length is < 12 or > 1024)
            throw new ArgumentException("Backup password must contain 12 to 1024 UTF-8 bytes.", nameof(password));
    }
}
