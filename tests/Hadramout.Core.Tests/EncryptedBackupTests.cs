using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
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

    [Fact]
    public void ProtectedRestorePreservesBothHistoriesAndVerifiedPrecaution()
    {
        using var f = new Fixture();
        Guid shared = Guid.NewGuid();
        Guid currentOnly = Guid.NewGuid();
        AppendAudit(f.Source, shared, "2026-01-01T00:00:00.0000000+00:00");
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        AppendAudit(f.Source, currentOnly, "2026-01-02T00:00:00.0000000+00:00");
        using (var c = DatabaseStore.Open(f.Source))
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "INSERT INTO sites VALUES('11111111-1111-1111-1111-111111111111','new-current');";
            cmd.ExecuteNonQuery();
        }
        string precaution = Path.Combine(f.Root, "precaution.hmk");
        string recovered = Path.Combine(f.Root, "precaution-recovered.db");
        byte[] before = SHA256.HashData(File.ReadAllBytes(f.Source));
        var receipt = EncryptedDatabaseBackup.PrepareWithPrecaution(f.Source, f.Encrypted, f.Candidate,
            precaution, Password, "synthetic-precaution-password"u8);
        Assert.True(before.AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(f.Source))));
        Assert.Equal(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(precaution))).ToLowerInvariant(),
            receipt.Precaution.Sha256);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f.Candidate))).ToLowerInvariant(),
            receipt.Candidate.Sha256);
        var events = AuditStore.ReadRecent(f.Candidate);
        Assert.Single(events, x => x.Id == shared);
        Assert.Single(events, x => x.Id == currentOnly);
        Assert.Contains(events, x => x.Kind == AuditKind.RestoreCandidatePrepared);
        EncryptedDatabaseBackup.PrepareRestore(precaution, recovered, "synthetic-precaution-password"u8);
        Assert.Contains(AuditStore.ReadRecent(recovered), x => x.Id == currentOnly);
        using var c1 = DatabaseStore.Open(f.Candidate);
        using var db1 = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c1).Options);
        Assert.Single(db1.Sites);
        using var c2 = DatabaseStore.Open(recovered);
        using var db2 = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c2).Options);
        Assert.Equal(2, db2.Sites.Count());
        f.AssertClean();
    }

    [Fact]
    public void ProtectedRestoreWrongPasswordDoesNotPublishAnything()
    {
        using var f = new Fixture();
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        string precaution = Path.Combine(f.Root, "precaution.hmk");
        Assert.Throws<CryptographicException>(() =>
            EncryptedDatabaseBackup.PrepareWithPrecaution(f.Source, f.Encrypted, f.Candidate,
                precaution, "incorrect-password"u8, Password));
        Assert.False(File.Exists(precaution));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    [Fact]
    public void ProtectedRestoreRejectsConflictingHistoryAndRetainsSafetyCopy()
    {
        using var f = new Fixture();
        Guid conflict = Guid.NewGuid();
        AppendAudit(f.Source, conflict, "2026-01-01T00:00:00.0000000+00:00");
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        // Simulate conflicting history in an independently edited trusted database fixture.
        using (var c = DatabaseStore.Open(f.Source))
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = """
                DROP TRIGGER audit_no_update;
                UPDATE audit_events SET OccurredUtc='2026-01-02T00:00:00.0000000+00:00';
                CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
                    BEGIN SELECT RAISE(ABORT, 'Audit events are append-only'); END;
                """;
            cmd.ExecuteNonQuery();
        }
        string precaution = Path.Combine(f.Root, "precaution.hmk");
        Assert.Throws<InvalidDataException>(() =>
            EncryptedDatabaseBackup.PrepareWithPrecaution(f.Source, f.Encrypted, f.Candidate,
                precaution, Password, Password));
        Assert.True(File.Exists(precaution));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    [Fact]
    public void ProtectedRestoreRequiresSeparateUnusedDestinations()
    {
        using var f = new Fixture();
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        Assert.Throws<IOException>(() =>
            EncryptedDatabaseBackup.PrepareWithPrecaution(f.Source, f.Encrypted, f.Candidate,
                f.Candidate, Password, Password));
        Assert.Throws<IOException>(() =>
            EncryptedDatabaseBackup.PrepareWithPrecaution(f.Source, f.Encrypted, f.Candidate,
                f.Encrypted, Password, Password));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    [Fact]
    public void FailedPrecautionCreationCannotPublishCandidate()
    {
        using var f = new Fixture();
        EncryptedDatabaseBackup.Create(f.Source, f.Encrypted, Password);
        using (var c = DatabaseStore.Open(f.Source))
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "PRAGMA user_version=999;";
            cmd.ExecuteNonQuery();
        }
        string precaution = Path.Combine(f.Root, "precaution.hmk");
        Assert.Throws<InvalidDataException>(() =>
            EncryptedDatabaseBackup.PrepareWithPrecaution(f.Source, f.Encrypted, f.Candidate,
                precaution, Password, Password));
        Assert.False(File.Exists(precaution));
        Assert.False(File.Exists(f.Candidate));
        f.AssertClean();
    }

    private static void AppendAudit(string path, Guid id, string utc)
    {
        using var c = DatabaseStore.Open(path);
        using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO audit_events(Id,OccurredUtc,Kind,SubjectId) VALUES($id,$utc,3,NULL);";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$utc", utc);
        cmd.ExecuteNonQuery();
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void PrivateWorkspaceHasRestrictedInheritedAccessBeforeWritingData()
    {
        using var f = new Fixture();
        string path = DatabaseBackup.CreatePrivateWorkspace(f.Root);
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var user = identity.User;
            Assert.NotNull(user);
            var acl = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            Assert.True(acl.AreAccessRulesProtected);
            Assert.Equal(user, acl.GetOwner(typeof(SecurityIdentifier)));
            var rule = Assert.Single(acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>());
            Assert.Equal(user, rule.IdentityReference);
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.False(rule.IsInherited);
            Assert.Equal(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, rule.InheritanceFlags);
            string child = Path.Combine(path, "test.db");
            File.WriteAllText(child, "synthetic-only");
            var childRules = new FileInfo(child).GetAccessControl(AccessControlSections.Access)
                .GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>();
            Assert.All(childRules, item => Assert.Equal(user, item.IdentityReference));
            Assert.NotEmpty(childRules);
        }
        finally { Directory.Delete(path, recursive: true); }
        f.AssertClean();
    }

    [Fact]
    public void ParallelPrivateWorkspacesAreDistinctAndDoNotTouchExistingFiles()
    {
        using var f = new Fixture();
        string existing = Path.Combine(f.Root, ".hmk-private-existing");
        Directory.CreateDirectory(existing);
        string sentinel = Path.Combine(existing, "keep.txt");
        File.WriteAllText(sentinel, "keep");
        var created = new System.Collections.Concurrent.ConcurrentBag<string>();
        try
        {
            Parallel.For(0, 4, _ => created.Add(DatabaseBackup.CreatePrivateWorkspace(f.Root)));
            Assert.Equal(4, created.Distinct().Count());
            Assert.All(created, path => Assert.True(Directory.Exists(path)));
            Assert.Equal("keep", File.ReadAllText(sentinel));
        }
        finally
        {
            foreach (string path in created) Directory.Delete(path, recursive: true);
            Directory.Delete(existing, recursive: true);
        }
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
