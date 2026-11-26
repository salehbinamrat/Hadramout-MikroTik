using System.Security.Cryptography;

namespace Hadramout.Infrastructure;

/// <summary>Authenticated local backups. Restore prepares a new database, never overwrites live data.</summary>
public static class EncryptedDatabaseBackup
{
    public const long MaximumSnapshotBytes = 16L * 1024 * 1024 * 1024;

    // Both workspace parent directories must be trusted private local storage.
    public static BackupReceipt Create(string sourcePath, string encryptedPath, ReadOnlySpan<byte> password)
    {
        ValidatePassword(password);
        ValidatePaths(sourcePath, encryptedPath);
        string workspace = CreateWorkspace(Path.GetDirectoryName(sourcePath)!);
        string temporaryOutput = Path.Combine(Path.GetDirectoryName(encryptedPath)!, ".hmk-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            string snapshot = Path.Combine(workspace, "snapshot.db");
            DatabaseBackup.Create(sourcePath, snapshot);
            using (var input = new FileStream(snapshot, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var output = new FileStream(temporaryOutput, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                BackupEnvelope.Write(input, output, password);
                output.Flush(flushToDisk: true);
            }
            BackupReceipt receipt;
            using (var output = File.OpenRead(temporaryOutput))
                receipt = new BackupReceipt(Convert.ToHexString(SHA256.HashData(output)).ToLowerInvariant(), output.Length);
            File.Move(temporaryOutput, encryptedPath, overwrite: false);
            return receipt;
        }
        finally
        {
            try { File.Delete(temporaryOutput); }
            finally { Directory.Delete(workspace, recursive: true); }
        }
    }

    public static BackupReceipt PrepareRestore(string encryptedPath, string candidatePath, ReadOnlySpan<byte> password)
    {
        ValidatePassword(password);
        ValidatePaths(encryptedPath, candidatePath);
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

    private static void ValidatePaths(string source, string destination)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);
        if (!Path.IsPathFullyQualified(source) || !Path.IsPathFullyQualified(destination))
            throw new ArgumentException("Absolute paths are required.");
        if (string.Equals(Path.GetFullPath(source), Path.GetFullPath(destination),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new IOException("Source and destination must differ.");
        if (!File.Exists(source)) throw new FileNotFoundException("Backup source is missing.");
        if (!Directory.Exists(Path.GetDirectoryName(destination)))
            throw new DirectoryNotFoundException("Destination directory is missing.");
        if (File.Exists(destination) || Directory.Exists(destination))
            throw new IOException("Destination already exists.");
    }

}
