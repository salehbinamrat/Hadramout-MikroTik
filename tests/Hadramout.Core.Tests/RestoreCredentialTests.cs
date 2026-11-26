using System.Runtime.Versioning;
using System.Security.Cryptography;
using Hadramout.Core;
using Hadramout.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Hadramout.Core.Tests;

[SupportedOSPlatform("windows")]
public sealed class RestoreCredentialTests
{
    [Fact]
    public void PublishedProbeWorks() => Assert.True(RestoreCredentialProbe.Verify());

    [Fact]
    public void InspectReportsAvailableMissingAndUnavailableWithoutChangingDatabase()
    {
        using var f = new Fixture();
        f.MakeUnavailable();
        byte[] before = SHA256.HashData(File.ReadAllBytes(f.Path));
        var status = RestoreCredentialInspector.Inspect(f.Path);
        Assert.Equal(3, status.Count);
        Assert.Equal(RestoreCredentialState.AvailableLocally, status.Single(x => x.RouterId == f.Available).State);
        Assert.Equal(RestoreCredentialState.Unavailable, status.Single(x => x.RouterId == f.Unavailable).State);
        Assert.Equal(RestoreCredentialState.Missing, status.Single(x => x.RouterId == f.Missing).State);
        Assert.True(before.AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(f.Path))));
    }

    [Fact]
    public void ReentryChangesOnlyUnavailableRouterAndRecordsAudit()
    {
        using var f = new Fixture();
        f.MakeUnavailable();
        var store = new RouterCredentialStore(f.Path);
        store.ReenterUnavailable(f.Unavailable, "new-user"u8, "new-password"u8);
        using var changed = store.Load(f.Unavailable);
        Assert.NotNull(changed);
        Assert.True(changed.Username.SequenceEqual("new-user"u8));
        Assert.True(changed.Password.SequenceEqual("new-password"u8));
        using var original = store.Load(f.Available);
        Assert.NotNull(original);
        Assert.True(original.Password.SequenceEqual("original-password"u8));
        Assert.Null(store.Load(f.Missing));
        Assert.Equal(3, AuditStore.ReadRecent(f.Path).Count);
        Assert.Equal(RestoreCredentialState.AvailableLocally,
            RestoreCredentialInspector.Inspect(f.Path).Single(x => x.RouterId == f.Unavailable).State);
    }

    [Fact]
    public void ReentryRejectsReadableAbsentAndUnknownRouter()
    {
        using var f = new Fixture();
        var store = new RouterCredentialStore(f.Path);
        foreach (var id in new[] { f.Available, f.Missing, Guid.NewGuid() })
            Assert.Throws<InvalidOperationException>(() => store.ReenterUnavailable(id, "user"u8, "password"u8));
        Assert.Equal(2, AuditStore.ReadRecent(f.Path).Count);
    }

    [Fact]
    public void ReentryIsAtomicIfAuditFails()
    {
        using var f = new Fixture();
        f.MakeUnavailable();
        using (var c = DatabaseStore.Open(f.Path))
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'test'); END;";
            cmd.ExecuteNonQuery();
        }
        Assert.Throws<SqliteException>(() =>
            new RouterCredentialStore(f.Path).ReenterUnavailable(f.Unavailable, "new-user"u8, "new-password"u8));
        Assert.Equal(RestoreCredentialState.Unavailable,
            RestoreCredentialInspector.Inspect(f.Path).Single(x => x.RouterId == f.Unavailable).State);
        Assert.Equal(2, AuditStore.ReadRecent(f.Path).Count);
    }

    [Fact]
    public void OversizedEnvelopeIsUnavailableWithoutMaterializingIt()
    {
        using var f = new Fixture();
        using (var c = DatabaseStore.Open(f.Path))
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "UPDATE router_credentials SET PasswordEnvelope=zeroblob(1000000) WHERE RouterId=$id;";
            cmd.Parameters.AddWithValue("$id", f.Unavailable);
            cmd.ExecuteNonQuery();
        }
        Assert.Equal(RestoreCredentialState.Unavailable,
            RestoreCredentialInspector.Inspect(f.Path).Single(x => x.RouterId == f.Unavailable).State);
    }

    [Fact]
    public void MissingDatabaseIsNotCreatedByInspectionOrReentry()
    {
        using var f = new Fixture();
        string missing = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(f.Path)!, "missing.db");
        Assert.Throws<SqliteException>(() => RestoreCredentialInspector.Inspect(missing));
        Assert.Throws<SqliteException>(() =>
            new RouterCredentialStore(missing).ReenterUnavailable(f.Unavailable, "user"u8, "password"u8));
        Assert.False(File.Exists(missing));
    }

    [Fact]
    public void UnknownSchemaIsRejectedByInspection()
    {
        using var f = new Fixture();
        using (var c = DatabaseStore.Open(f.Path))
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "PRAGMA user_version=999;";
            cmd.ExecuteNonQuery();
        }
        Assert.Throws<InvalidDataException>(() => RestoreCredentialInspector.Inspect(f.Path));
    }

    [Fact]
    public void ConcurrentReentryCannotOverwriteFirstSuccessfulReplacement()
    {
        using var f = new Fixture();
        f.MakeUnavailable();
        var results = new System.Collections.Concurrent.ConcurrentBag<bool>();
        Parallel.For(0, 2, _ =>
        {
            try
            {
                new RouterCredentialStore(f.Path).ReenterUnavailable(f.Unavailable, "new-user"u8, "new-password"u8);
                results.Add(true);
            }
            catch (InvalidOperationException) { results.Add(false); }
        });
        Assert.Equal(2, results.Count);
        Assert.Single(results.Where(x => x));
        Assert.Single(results.Where(x => !x));
        Assert.Equal(3, AuditStore.ReadRecent(f.Path).Count);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("hadramout-restore-credentials-");
        public string Path => System.IO.Path.Combine(directory.FullName, "candidate.db");
        public Guid Available { get; }
        public Guid Unavailable { get; }
        public Guid Missing { get; }
        public Fixture()
        {
            var site = new Site { Name = "test" };
            var first = new Router { SiteId = site.Id, Name = "first" };
            var second = new Router { SiteId = site.Id, Name = "second" };
            var third = new Router { SiteId = site.Id, Name = "third" };
            using (var c = DatabaseStore.Open(Path))
            using (var db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c).Options))
            {
                db.AddRange(site, first, second, third);
                db.SaveChanges();
            }
            Available = first.Id;
            Unavailable = second.Id;
            Missing = third.Id;
            var store = new RouterCredentialStore(Path);
            store.Save(Available, "original-user"u8, "original-password"u8);
            store.Save(Unavailable, "old-user"u8, "old-password"u8);
        }
        public void MakeUnavailable()
        {
            using var c = DatabaseStore.Open(Path);
            using var cmd = c.CreateCommand();
            cmd.CommandText = "UPDATE router_credentials SET PasswordEnvelope=X'01' WHERE RouterId=$id;";
            cmd.Parameters.AddWithValue("$id", Unavailable);
            cmd.ExecuteNonQuery();
        }
        public void Dispose() => directory.Delete(recursive: true);
    }
}
