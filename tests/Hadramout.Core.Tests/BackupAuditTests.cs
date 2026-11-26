using System.Runtime.Versioning;
using System.Security.Cryptography;
using Hadramout.Core;
using Hadramout.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Hadramout.Core.Tests;

public sealed class BackupAuditTests
{
    [Fact]
    public void PublishedBackupProbeWorks() => Assert.True(BackupProbe.Verify());

    [Fact]
    public void SnapshotIncludesCommittedWalButNotLaterWrites()
    {
        using var f = new Fixture();
        using var c = DatabaseStore.Open(f.Source);
        Execute(c, "INSERT INTO sites VALUES ('11111111-1111-1111-1111-111111111111','before');");
        var receipt = DatabaseBackup.Create(f.Source, f.Backup);
        Execute(c, "INSERT INTO sites VALUES ('22222222-2222-2222-2222-222222222222','after');");
        Assert.Equal(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f.Backup))).ToLowerInvariant(), receipt.Sha256);
        Assert.Equal(new FileInfo(f.Backup).Length, receipt.Bytes);
        var restored = DatabaseBackup.PrepareRestore(f.Backup, f.Candidate, receipt.Sha256);
        Assert.NotEqual(receipt.Sha256, restored.Sha256);
        using var candidate = DatabaseStore.Open(f.Candidate);
        Assert.Equal(2L, Scalar(candidate, "SELECT count(*) FROM sites;"));
        Assert.Equal(0L, Scalar(candidate, "SELECT count(*) FROM sites WHERE Name='after';"));
        Assert.Equal(3L, Scalar(c, "SELECT count(*) FROM sites;"));
        var events = AuditStore.ReadRecent(f.Candidate);
        Assert.Contains(events, x => x.Kind == AuditKind.BackupSnapshotCreated);
        Assert.Contains(events, x => x.Kind == AuditKind.RestoreCandidatePrepared);
    }

    [Fact]
    public void RestoreRejectsWrongDigestWithoutPublishing()
    {
        using var f = new Fixture();
        DatabaseBackup.Create(f.Source, f.Backup);
        Assert.Throws<InvalidDataException>(() => DatabaseBackup.PrepareRestore(f.Backup, f.Candidate, new string('0', 64)));
        Assert.False(File.Exists(f.Candidate));
        Assert.Empty(Directory.GetDirectories(f.Root, ".hadramout-stage-*"));
    }

    [Fact]
    public void RestoreRejectsCorruptionEvenWithMatchingDigest()
    {
        using var f = new Fixture();
        File.WriteAllBytes(f.Backup, "not-a-database"u8.ToArray());
        string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f.Backup)));
        var error = Record.Exception(() => DatabaseBackup.PrepareRestore(f.Backup, f.Candidate, hash));
        Assert.True(error is SqliteException or InvalidDataException);
        Assert.False(File.Exists(f.Candidate));
        Assert.Empty(Directory.GetDirectories(f.Root, ".hadramout-stage-*"));
    }

    [Fact]
    public void ExistingFilesAreNeverOverwritten()
    {
        using var f = new Fixture();
        var receipt = DatabaseBackup.Create(f.Source, f.Backup);
        Assert.Throws<IOException>(() => DatabaseBackup.Create(f.Source, f.Backup));
        Assert.Throws<IOException>(() => DatabaseBackup.PrepareRestore(f.Backup, f.Source, receipt.Sha256));
        Assert.Equal(receipt.Sha256, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f.Backup))).ToLowerInvariant());
    }

    [Fact]
    public void RestoreRejectsUnexpectedSidecars()
    {
        using var f = new Fixture();
        var receipt = DatabaseBackup.Create(f.Source, f.Backup);
        File.WriteAllText(f.Backup + "-wal", "unexpected");
        Assert.Throws<IOException>(() => DatabaseBackup.PrepareRestore(f.Backup, f.Candidate, receipt.Sha256));
        Assert.False(File.Exists(f.Candidate));
    }

    [Fact]
    public void RejectsUnsupportedSnapshotVersion()
    {
        using var f = new Fixture();
        using (var c = DatabaseStore.Open(f.Source)) Execute(c, "PRAGMA user_version=999;");
        Assert.Throws<InvalidDataException>(() => DatabaseBackup.Create(f.Source, f.Backup));
        Assert.False(File.Exists(f.Backup));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void CredentialsRemainEncryptedAndSameUserCanRecover()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Source);
        store.Save(f.RouterId, "test-user"u8, "test-password"u8);
        var receipt = DatabaseBackup.Create(f.Source, f.Backup);
        DatabaseBackup.PrepareRestore(f.Backup, f.Candidate, receipt.Sha256);
        using var lease = new RouterCredentialStore(f.Candidate).Load(f.RouterId);
        Assert.NotNull(lease);
        Assert.True(lease.Password.SequenceEqual("test-password"u8));
        Assert.Contains(AuditStore.ReadRecent(f.Candidate), x => x.Kind == AuditKind.CredentialSaved);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void CredentialChangesAndAuditAreAtomic()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Source);
        store.Save(f.RouterId, "user"u8, "old"u8);
        Assert.Single(AuditStore.ReadRecent(f.Source));
        using (var c = DatabaseStore.Open(f.Source))
            Execute(c, "CREATE TRIGGER simulate_audit_failure BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'test'); END;");
        Assert.Throws<SqliteException>(() => store.Save(f.RouterId, "user"u8, "new"u8));
        Assert.Throws<SqliteException>(() => store.Remove(f.RouterId));
        using var lease = store.Load(f.RouterId);
        Assert.NotNull(lease);
        Assert.True(lease.Password.SequenceEqual("old"u8));
        Assert.Single(AuditStore.ReadRecent(f.Source));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void AuditIsAppendOnlyAndNoOpRemovalDoesNotLog()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Source);
        store.Save(f.RouterId, "user"u8, "password"u8);
        Assert.True(store.Remove(f.RouterId));
        Assert.False(store.Remove(f.RouterId));
        using var c = DatabaseStore.Open(f.Source);
        Assert.Throws<SqliteException>(() => Execute(c, "DELETE FROM audit_events;"));
        Assert.Throws<SqliteException>(() => Execute(c, "UPDATE audit_events SET Kind=4;"));
        var events = AuditStore.ReadRecent(f.Source);
        Assert.Equal(2, events.Count);
        Assert.All(events, x => Assert.Equal(f.RouterId, x.SubjectId));
        Assert.Contains(events, x => x.Kind == AuditKind.CredentialRemoved);
    }

    [Fact]
    public void VersionThreeMigratesWithoutLosingExistingRows()
    {
        using var f = new Fixture();
        using (var c = DatabaseStore.Open(f.Source))
            Execute(c, "DROP TABLE audit_events; PRAGMA user_version=3;");
        using var upgraded = DatabaseStore.Open(f.Source);
        Assert.Equal(4L, Scalar(upgraded, "PRAGMA user_version;"));
        Assert.Equal(1L, Scalar(upgraded, "SELECT count(*) FROM routers;"));
        Assert.Empty(AuditStore.ReadRecent(f.Source));
    }

    private static object Scalar(SqliteConnection c, string sql)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        return cmd.ExecuteScalar()!;
    }

    private static void Execute(SqliteConnection c, string sql)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private sealed class Fixture : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("hadramout-backup-test-");
        public string Root => directory.FullName;
        public string Source => Path.Combine(Root, "source.db");
        public string Backup => Path.Combine(Root, "backup.db");
        public string Candidate => Path.Combine(Root, "candidate.db");
        public Guid RouterId { get; }
        public Fixture()
        {
            using var c = DatabaseStore.Open(Source);
            using var db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c).Options);
            var site = new Site { Name = "initial" };
            var router = new Router { Name = "test", SiteId = site.Id };
            db.AddRange(site, router);
            db.SaveChanges();
            RouterId = router.Id;
        }
        public void Dispose() => directory.Delete(recursive: true);
    }
}
