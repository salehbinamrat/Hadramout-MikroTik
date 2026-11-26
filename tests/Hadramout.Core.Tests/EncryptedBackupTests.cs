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
        Assert.True(bytes.AsSpan(0, 8).SequenceEqual("HMKBACK1"u8));
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
        Assert.False(a.AsSpan(24, 12).SequenceEqual(b.AsSpan(24, 12)));
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
