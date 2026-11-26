using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Hadramout.Infrastructure;

/// <summary>Authenticated, password-protected local backup files. Restore only prepares a new database.</summary>
public static class EncryptedDatabaseBackup
{
    // Fixed v1 format: magic, salt, nonce, length, ciphertext, tag.
    // A strict size ceiling bounds allocation on x86; larger backups need a separately reviewed format.
    public const int MaximumSnapshotBytes = 64 * 1024 * 1024;
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private const int Iterations = 600_000;
    private const int LengthOffset = 8 + SaltSize + NonceSize;
    private const int HeaderSize = LengthOffset + 4;
    private static ReadOnlySpan<byte> Magic => "HMKBACK1"u8;

    // source and restore directories must be trusted, private local storage.
    public static BackupReceipt Create(string sourcePath, string encryptedPath, ReadOnlySpan<byte> password)
    {
        ValidatePassword(password);
        ValidatePaths(sourcePath, encryptedPath);
        var workspace = CreateWorkspace(Path.GetDirectoryName(sourcePath)!);
        string temporaryOutput = Path.Combine(Path.GetDirectoryName(encryptedPath)!, ".hmk-" + Guid.NewGuid().ToString("N") + ".tmp");
        byte[]? clear = null;
        byte[]? key = null;
        try
        {
            string snapshot = Path.Combine(workspace, "snapshot.db");
            DatabaseBackup.Create(sourcePath, snapshot);
            using (var input = new FileStream(snapshot, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (input.Length is < 1 or > MaximumSnapshotBytes)
                    throw new InvalidDataException("Snapshot exceeds the supported encrypted backup size.");
                clear = new byte[checked((int)input.Length)];
                input.ReadExactly(clear);
                if (input.ReadByte() != -1) throw new InvalidDataException("Snapshot size changed.");
            }

            var header = new byte[HeaderSize];
            Magic.CopyTo(header);
            RandomNumberGenerator.Fill(header.AsSpan(8, SaltSize));
            RandomNumberGenerator.Fill(header.AsSpan(8 + SaltSize, NonceSize));
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(LengthOffset), clear.Length);
            key = Rfc2898DeriveBytes.Pbkdf2(password, header.AsSpan(8, SaltSize), Iterations,
                HashAlgorithmName.SHA256, KeySize);
            var ciphertext = new byte[clear.Length];
            var tag = new byte[TagSize];
            using (var aes = new AesGcm(key, TagSize))
                aes.Encrypt(header.AsSpan(8 + SaltSize, NonceSize), clear, ciphertext, tag, header);
            using (var output = new FileStream(temporaryOutput, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                output.Write(header);
                output.Write(ciphertext);
                output.Write(tag);
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
            if (clear is not null) CryptographicOperations.ZeroMemory(clear);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            try { File.Delete(temporaryOutput); }
            finally { Directory.Delete(workspace, recursive: true); }
        }
    }

    public static BackupReceipt PrepareRestore(string encryptedPath, string candidatePath, ReadOnlySpan<byte> password)
    {
        ValidatePassword(password);
        ValidatePaths(encryptedPath, candidatePath);
        byte[]? clear = null;
        byte[]? key = null;
        string? workspace = null;
        try
        {
            using (var input = new FileStream(encryptedPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (input.Length < HeaderSize + TagSize + 1 ||
                    input.Length > (long)HeaderSize + TagSize + MaximumSnapshotBytes)
                    throw InvalidFormat();
                byte[] header = new byte[HeaderSize];
                input.ReadExactly(header);
                if (!header.AsSpan(0, 8).SequenceEqual(Magic)) throw InvalidFormat();
                int length = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(LengthOffset));
                if (length is < 1 or > MaximumSnapshotBytes ||
                    input.Length != (long)HeaderSize + length + TagSize)
                    throw InvalidFormat();
                byte[] ciphertext = new byte[length];
                byte[] tag = new byte[TagSize];
                input.ReadExactly(ciphertext);
                input.ReadExactly(tag);
                if (input.ReadByte() != -1) throw InvalidFormat();
                clear = new byte[length];
                key = Rfc2898DeriveBytes.Pbkdf2(password, header.AsSpan(8, SaltSize), Iterations,
                    HashAlgorithmName.SHA256, KeySize);
                try
                {
                    using var aes = new AesGcm(key, TagSize);
                    aes.Decrypt(header.AsSpan(8 + SaltSize, NonceSize), ciphertext, tag, clear, header);
                }
                catch (CryptographicException)
                {
                    // Deliberately avoid distinguishing wrong password from tampering.
                    throw new CryptographicException("Backup authentication failed.");
                }
            }

            // Do not open SQLite or write plaintext until authentication has succeeded.
            workspace = CreateWorkspace(Path.GetDirectoryName(candidatePath)!);
            string snapshot = Path.Combine(workspace, "snapshot.db");
            string digest = Convert.ToHexString(SHA256.HashData(clear));
            using (var output = new FileStream(snapshot, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                output.Write(clear);
                output.Flush(flushToDisk: true);
            }
            return DatabaseBackup.PrepareRestore(snapshot, candidatePath, digest);
        }
        finally
        {
            if (clear is not null) CryptographicOperations.ZeroMemory(clear);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (workspace is not null) Directory.Delete(workspace, recursive: true);
        }
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

    private static InvalidDataException InvalidFormat() => new("Unsupported or malformed encrypted backup.");
}
