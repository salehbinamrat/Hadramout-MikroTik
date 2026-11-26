using System.Security.Cryptography;
using Hadramout.Core;
using Hadramout.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Hadramout.Core.Tests;

public sealed class EncryptedBackupTests
{
    private static ReadOnlySpan<byte> Password => "synthetic-backup-password"u8;

    [Fact]
    public void PublishedProbeRoundTrips() => Assert.True(EncryptedBackupProbe.Verify());

    [Fact]
    public void BackupIsEncryptedAndReceiptMatches()
    {
        using var f = new Fixture();
        var receipt = EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        byte[] bytes = File.ReadAllBytes(f.Encrypted);
        Assert.True(bytes.AsSpan(0, 8).SequenceEqual("HMKBACK2"u8));
        Assert.Equal(-1, bytes.AsSpan().IndexOf("SQLite format 3"u8));
        Assert.Equal(-1, bytes.AsSpan().IndexOf("synthetic-private-site"u8));
        Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), receipt.Sha256);
        Assert.Equal((long)bytes.Length, receipt.Bytes);
        f.AssertClean();
    }

    [Fact]
    public void RandomSaltAndNonceProduceDifferentBackups()
    {
        using var f = new Fixture();
        string other = Path.Combine(f.Root, "other.hmk");
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        EncryptedDatabaseBackup.Create(f.Source, other, Password);
        byte[] a = File.ReadAllBytes(f.Encrypted);
        byte[] b = File.ReadAllBytes(other);
        Assert.False(a.AsSpan(8, 16).SequenceEqual(b.AsSpan(8, 16)));
        Assert.False(a.AsSpan(24, 8).SequenceEqual(b.AsSpan(24, 8)));
        f.AssertClean();
    }

    [Fact]
    public void WrongPasswordFailsWithoutCandidate()
    {
        using var f = new Fixture();
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        Assert.Throws<CryptographicException>(() =>
            EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Candidate, "wrong-backup-password"u8));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    [Theory]
    [InlineData(8)]
    [InlineData(24)]
    [InlineData(40)]
    [InlineData(-1)]
    public void AlteredSaltNonceCiphertextOrTagIsRejected(int offset)
    {
        using var f = new Fixture();
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        byte[] bytes = File.ReadAllBytes(f.Encrypted);
        bytes[offset < 0 ? bytes.Length - 1 : offset] ^= 1;
        File.WriteAllBytes(f.Encrypted, bytes);
        Assert.Throws<CryptographicException>(() =>
            EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Candidate, Password));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    [Fact]
    public void OversizedOrForgedHeaderLengthIsRejectedBeforeAllocation()
    {
        using var f = new Fixture();
        var bytes = new byte[57];
        "HMKBACK1"u8.CopyTo(bytes);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(36, 4), int.MaxValue);
        File.WriteAllBytes(f.Encrypted, bytes);
        Assert.Throws<InvalidDataException>(() =>
            EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Candidate, Password));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    [Fact]
    public void TruncatedBackupIsRejected()
    {
        using var f = new Fixture();
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        using (var stream = new FileStream(f.Encrypted, FileMode.Open, FileAccess.Write))
            stream.SetLength(stream.Length - 1);
        Assert.Throws<InvalidDataException>(() =>
            EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Candidate, Password));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    [Fact]
    public void RestoreDoesNotOverwriteExistingData()
    {
        using var f = new Fixture();
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        byte[] before = File.ReadAllBytes(f.Source);
        Assert.Throws<IOException>(() => EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password));
        Assert.Throws<IOException>(() => EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Source, Password));
        Assert.True(before.AsSpan().SequenceEqual(File.ReadAllBytes(f.Source)));
        f.AssertClean();
    }

    [Fact]
    public void RejectsShortPasswords()
    {
        using var f = new Fixture();
        Assert.Throws<ArgumentException>(() => EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, "short"u8));
        Assert.False(File.Exists(f.Encrypted));
        f.AssertClean();
    }

    [Fact]
    public void ReadsLegacyV1Fixture()
    {
        using var f = new Fixture();
        string snapshot = Path.Combine(f.Root, "legacy.db");
        DatabaseBackup.Create(f.Source, snapshot);
        byte[] clear = File.ReadAllBytes(snapshot);
        byte[] header = new byte[40];
        "HMKBACK1"u8.CopyTo(header);
        RandomNumberGenerator.Fill(header.AsSpan(8, 28));
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(36), clear.Length);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(Password, header.AsSpan(8, 16), 600_000, HashAlgorithmName.SHA256, 32);
        byte[] cipher = new byte[clear.Length];
        byte[] tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(header.AsSpan(24, 12), clear, cipher, tag, header);
            using var output = File.Create(f.Encrypted);
            output.Write(header);
            output.Write(cipher);
            output.Write(tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clear);
            CryptographicOperations.ZeroMemory(key);
        }
        EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Candidate, Password);
        using var connection = DatabaseStore.Open(f.Candidate);
        using var db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(connection).Options);
        Assert.Equal("synthetic-private-site", db.Sites.Single().Name);
        f.AssertClean();
    }

    [Fact]
    public void LargerThanLegacyLimitRoundTrips()
    {
        using var f = new Fixture();
        const int length = 70 * 1024 * 1024;
        AddPayload(f.Source, length);
        var receipt = EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        Assert.True(receipt.Bytes > 64L * 1024 * 1024);
        EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Candidate, Password);
        using var c = DatabaseStore.Open(f.Candidate);
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT length(Data) FROM test_payload;";
        Assert.Equal((long)length, (long)cmd.ExecuteScalar()!);
        f.AssertClean();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReorderedOrDuplicatedChunksFailWithoutCandidate(bool duplicate)
    {
        using var f = new Fixture();
        AddPayload(f.Source, 3 * 1024 * 1024);
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        byte[] bytes = File.ReadAllBytes(f.Encrypted);
        const int record = 1024 * 1024 + 16;
        byte[] first = bytes.AsSpan(40, record).ToArray();
        if (!duplicate) bytes.AsSpan(40 + record, record).CopyTo(bytes.AsSpan(40, record));
        first.CopyTo(bytes, 40 + record);
        File.WriteAllBytes(f.Encrypted, bytes);
        Assert.Throws<CryptographicException>(() =>
            EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Candidate, Password));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    [Fact]
    public void LateChunkTamperingRemovesPartialPlaintext()
    {
        using var f = new Fixture();
        AddPayload(f.Source, 3 * 1024 * 1024);
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        byte[] bytes = File.ReadAllBytes(f.Encrypted);
        bytes[^1] ^= 1;
        File.WriteAllBytes(f.Encrypted, bytes);
        Assert.Throws<CryptographicException>(() =>
            EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Candidate, Password));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    [Fact]
    public void ForgedV2LengthAndTrailingBytesAreRejected()
    {
        using var f = new Fixture();
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        byte[] bytes = File.ReadAllBytes(f.Encrypted);
        byte[] forged = (byte[])bytes.Clone();
        System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(forged.AsSpan(32), long.MaxValue);
        File.WriteAllBytes(f.Encrypted, forged);
        Assert.Throws<InvalidDataException>(() =>
            EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Candidate, Password));
        File.WriteAllBytes(f.Encrypted, [.. bytes, 0]);
        Assert.Throws<InvalidDataException>(() =>
            EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Candidate, Password));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    [Fact]
    public void ChunkFromAnotherBackupFailsAuthentication()
    {
        using var f = new Fixture();
        AddPayload(f.Source, 3 * 1024 * 1024);
        string other = Path.Combine(f.Root, "other.hmk");
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        EncryptedDatabaseBackup.Create(f.Source, other, Password);
        byte[] first = File.ReadAllBytes(f.Encrypted);
        byte[] second = File.ReadAllBytes(other);
        const int record = 1024 * 1024 + 16;
        second.AsSpan(40 + record, record).CopyTo(first.AsSpan(40 + record, record));
        File.WriteAllBytes(f.Encrypted, first);
        Assert.Throws<CryptographicException>(() =>
            EncryptedDatabaseBackup.PrepareRestore(f.Encrypted, f.Candidate, Password));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    private static void AddPayload(string path, int size)
    {
        using var c = DatabaseStore.Open(path);
        using var cmd = c.CreateCommand();
        cmd.CommandText = "CREATE TABLE test_payload(Data BLOB NOT NULL); INSERT INTO test_payload VALUES(zeroblob($size));";
        cmd.Parameters.AddWithValue("$size", size);
        cmd.ExecuteNonQuery();
    }

    private sealed class Fixture : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("hadramout-encrypted-test-");
        public string Root => directory.FullName;
        public string Source => Path.Combine(Root, "source.db");
        public string Encrypted => Path.Combine(Root, "backup.hmk");
        public string Candidate => Path.Combine(Root, "candidate.db");

        public Fixture()
        {
            using var c = DatabaseStore.Open(Source);
            using var db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c).Options);
            db.Sites.Add(new Site { Name = "synthetic-private-site" });
            db.SaveChanges();
        }

        public void AssertClean()
        {
            Assert.Empty(Directory.GetDirectories(Root, ".hmk-private-*"));
            Assert.Empty(Directory.GetFiles(Root, ".hmk-*.tmp"));
            Assert.Empty(Directory.GetDirectories(Root, ".hadramout-stage-*"));
        }

        public void Dispose() => directory.Delete(recursive: true);
    }
}
