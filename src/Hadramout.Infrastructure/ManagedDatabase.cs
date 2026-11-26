using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Hadramout.Infrastructure;

/// <summary>
/// Owns the exclusive application database session. All application access must finish
/// before disposal; callers must not retain connections, background tasks or paths for later writes.
/// </summary>
public sealed class ManagedDatabaseSession : IDisposable
{
    private FileStream? gate;
    public Guid Generation { get; }
    public string DatabasePath { get; }

    internal ManagedDatabaseSession(FileStream gate, Guid generation, string path)
    {
        this.gate = gate;
        Generation = generation;
        DatabasePath = path;
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref gate, null)?.Dispose();
    }
}

public sealed record ManagedRestoreResult(Guid Generation, ProtectedRestoreReceipt Receipts,
    IReadOnlyList<RestoreCredentialStatus> Credentials);

/// <summary>
/// Windows local managed database generations. Never overwrites or deletes an existing DB.
/// The exclusive gate is cooperative: all live application access must use OpenSession.
/// Not intended for shared/network paths or direct writers outside the managed application.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ManagedDatabase
{
    private const string PointerName = "active-generation";
    private const string GateName = "database-session.lock";

    public static ManagedDatabaseSession OpenApplicationSession()
    {
        string parent = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(parent))
            throw new InvalidOperationException("Local application data directory is unavailable.");
        return OpenApplicationSessionAt(parent);
    }

    // Also used by isolated startup tests; production uses the Windows known folder.
    internal static ManagedDatabaseSession OpenApplicationSessionAt(string parent)
    {
        parent = ValidateRoot(parent);
        string volume = Path.GetPathRoot(parent) ?? throw new IOException("Managed storage volume is unavailable.");
        if (new DriveInfo(volume).DriveType != DriveType.Fixed)
            throw new IOException("Managed storage requires a local fixed drive.");
        for (DirectoryInfo? directory = new DirectoryInfo(parent); directory is not null; directory = directory.Parent)
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Managed storage must not traverse a reparse point.");

        string root = Path.Combine(parent, "HadramoutMikroTik.Data");
        DatabaseBackup.EnsurePrivateWindowsDirectory(root);
        return OpenSession(root);
    }

    public static ManagedDatabaseSession OpenSession(string root)
    {
        root = ValidateRoot(root);
        var gate = Acquire(root);
        try
        {
            string pointer = Path.Combine(root, PointerName);
            Guid id;
            if (File.Exists(pointer))
                id = ReadPointer(root);
            else
            {
                // Never silently initialize over an interrupted setup or missing pointer.
                if (Directory.Exists(pointer) || Directory.EnumerateFileSystemEntries(root, "generation-*.db").Any())
                    throw new InvalidDataException("Active database pointer is missing; explicit recovery is required.");
                id = Guid.NewGuid();
                string path = GenerationPath(root, id);
                string workspace = DatabaseBackup.CreatePrivateWorkspace(root);
                try
                {
                    string staged = Path.Combine(workspace, "initial.db");
                    using (var c = DatabaseStore.Open(staged))
                        DatabaseBackup.MakeStandalone(c);
                    DatabaseBackup.ValidateSnapshot(staged);
                    DatabaseBackup.PublishStandalone(staged, path);
                    WritePointer(root, id, replace: false);
                }
                finally { Directory.Delete(workspace, recursive: true); }
            }
            string active = GenerationPath(root, id);
            RequireRegularFile(active);
            using (var c = DatabaseBackup.OpenRaw(active, Microsoft.Data.Sqlite.SqliteOpenMode.ReadOnly))
                DatabaseBackup.ValidateConnection(c, fullIntegrityCheck: false, allowVersionFour: true);
            using (var c = DatabaseStore.OpenExisting(active))
                DatabaseBackup.ValidateConnection(c, fullIntegrityCheck: false);
            return new ManagedDatabaseSession(gate, id, active);
        }
        catch
        {
            gate.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Requires a closed managed session, explicit expected generation, trusted backup,
    /// and a verified fresh precaution. No active generation file is overwritten.
    /// </summary>
    public static ManagedRestoreResult ActivateRestore(string root, Guid expectedGeneration,
        string encryptedPath, string precautionPath, ReadOnlySpan<byte> backupPassword,
        ReadOnlySpan<byte> precautionPassword, bool allowUnavailableCredentials)
    {
        root = ValidateRoot(root);
        using var gate = Acquire(root);
        Guid current = ReadPointer(root);
        if (current != expectedGeneration)
            throw new InvalidOperationException("The active database generation changed; review the restore request again.");

        string currentPath = GenerationPath(root, current);
        RequireRegularFile(currentPath);
        Guid next = Guid.NewGuid();
        string candidate = GenerationPath(root, next);

        // Current history and the precaution are captured under the same exclusive managed gate.
        var receipts = EncryptedDatabaseBackup.PrepareWithPrecaution(currentPath, encryptedPath,
            candidate, precautionPath, backupPassword, precautionPassword);
        UserManager6CreateJournal.RequireEquivalentForRestore(currentPath, candidate);
        var statuses = RestoreCredentialInspector.Inspect(candidate);
        if (!allowUnavailableCredentials && statuses.Any(s => s.State == RestoreCredentialState.Unavailable))
            throw new InvalidOperationException("Restored credentials require explicit review before activation.");

        DatabaseBackup.ValidateSnapshot(candidate);
        using (var stream = File.OpenRead(candidate))
        {
            if (stream.Length != receipts.Candidate.Bytes ||
                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(stream),
                    Convert.FromHexString(receipts.Candidate.Sha256)))
                throw new InvalidDataException("Prepared database changed before activation.");
        }

        // Only the small pointer is replaced. Failed/uncertain operations retain both DBs.
        WritePointer(root, next, replace: true);
        return new ManagedRestoreResult(next, receipts, statuses);
    }

    private static string ValidateRoot(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        if (!Path.IsPathFullyQualified(root)) throw new ArgumentException("Absolute managed root required.", nameof(root));
        root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException("Managed database root does not exist.");
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Managed root must not be a reparse point.");
        return root;
    }

    private static FileStream Acquire(string root)
    {
        string path = Path.Combine(root, GateName);
        if (File.Exists(path)) RequireRegularFile(path);
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    private static string GenerationPath(string root, Guid id) =>
        Path.Combine(root, "generation-" + id.ToString("N") + ".db");

    private static Guid ReadPointer(string root)
    {
        string path = Path.Combine(root, PointerName);
        RequireRegularFile(path);
        using var input = File.OpenRead(path);
        if (input.Length != 32) throw new InvalidDataException("Invalid active database pointer.");
        Span<byte> bytes = stackalloc byte[32];
        input.ReadExactly(bytes);
        string text = Encoding.ASCII.GetString(bytes);
        if (!Guid.TryParseExact(text, "N", out var id) || id == Guid.Empty || text != id.ToString("N"))
            throw new InvalidDataException("Invalid active database pointer.");
        return id;
    }

    private static void WritePointer(string root, Guid id, bool replace)
    {
        string pointer = Path.Combine(root, PointerName);
        string workspace = DatabaseBackup.CreatePrivateWorkspace(root);
        string staged = Path.Combine(workspace, "pointer.tmp");
        try
        {
            using (var stream = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(Encoding.ASCII.GetBytes(id.ToString("N")));
                stream.Flush(flushToDisk: true);
            }
            if (replace)
            {
                RequireRegularFile(pointer);
                File.Replace(staged, pointer, null);
            }
            else File.Move(staged, pointer, overwrite: false);
        }
        finally { Directory.Delete(workspace, recursive: true); }
    }

    private static void RequireRegularFile(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Required managed database file is missing.");
        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new IOException("Managed database file must be a regular file.");
    }
}
