using Hadramout.Core;
using Hadramout.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Hadramout.Core.Tests;

public sealed class NetworkDbTests
{
    [Fact]
    public void NativeProviderProbeSucceeds() => Assert.True(DatabaseProbe.Verify());

    [Fact]
    public void SameBackendRejectsDuplicateUsername()
    {
        using var store = new TestStore();
        var a = Seed(store.Db, BackendKind.Hotspot);
        store.Db.Reservations.Add(Reserve(a, "001"));
        store.Db.SaveChanges();
        store.Db.Reservations.Add(Reserve(a, "001"));
        Assert.Throws<DbUpdateException>(() => store.Db.SaveChanges());
    }

    [Fact]
    public void SeparateBackendsAllowSameUsername()
    {
        using var store = new TestStore();
        var a = Seed(store.Db, BackendKind.Hotspot);
        var b = Seed(store.Db, BackendKind.UserManager6);
        store.Db.Reservations.AddRange(Reserve(a, "001"), Reserve(b, "001"));
        store.Db.SaveChanges();
        Assert.Equal(2, store.Db.Reservations.Count());
    }

    [Fact]
    public void CannotReserveAgainstBatchFromOtherBackend()
    {
        using var store = new TestStore();
        var a = Seed(store.Db, BackendKind.Hotspot);
        var b = Seed(store.Db, BackendKind.UserManager7);
        store.Db.Reservations.Add(new VoucherReservation { BackendId = a.BackendId, BatchId = b.Id, Username = "001" });
        Assert.Throws<DbUpdateException>(() => store.Db.SaveChanges());
    }

    [Fact]
    public void CannotBatchAgainstPlanFromOtherBackend()
    {
        using var store = new TestStore();
        var a = Seed(store.Db, BackendKind.Hotspot);
        var b = Seed(store.Db, BackendKind.UserManager6);
        store.Db.Batches.Add(new VoucherBatch { BackendId = a.BackendId, PlanId = b.PlanId });
        Assert.Throws<DbUpdateException>(() => store.Db.SaveChanges());
    }

    [Fact]
    public void MissingParentIsRejected()
    {
        using var store = new TestStore();
        store.Db.Routers.Add(new Router { SiteId = Guid.NewGuid(), Name = "orphan" });
        Assert.Throws<DbUpdateException>(() => store.Db.SaveChanges());
    }

    [Fact]
    public void BlankUsernameIsRejected()
    {
        using var store = new TestStore();
        var a = Seed(store.Db, BackendKind.Hotspot);
        store.Db.Reservations.Add(Reserve(a, " "));
        Assert.Throws<DbUpdateException>(() => store.Db.SaveChanges());
    }

    [Fact]
    public void TransactionRollbackLeavesNoReservation()
    {
        using var store = new TestStore();
        var a = Seed(store.Db, BackendKind.Hotspot);
        using (var tx = store.Db.Database.BeginTransaction())
        {
            store.Db.Reservations.Add(Reserve(a, "001"));
            store.Db.SaveChanges();
            tx.Rollback();
        }
        store.Db.ChangeTracker.Clear();
        Assert.Empty(store.Db.Reservations);
    }

    [Fact]
    public void RecordsPersistAcrossConnections()
    {
        var path = Path.Combine(Path.GetTempPath(), $"hadramout-test-{Guid.NewGuid():N}.db");
        var cs = new SqliteConnectionStringBuilder { DataSource = path, ForeignKeys = true, Pooling = false }.ToString();
        try
        {
            using (var store = new TestStore(cs))
            {
                var a = Seed(store.Db, BackendKind.UserManager6);
                store.Db.Reservations.Add(Reserve(a, "001"));
                store.Db.SaveChanges();
            }
            using var reopened = new TestStore(cs);
            Assert.Equal("001", reopened.Db.Reservations.Single().Username);
        }
        finally { File.Delete(path); }
    }

    private static VoucherReservation Reserve(VoucherBatch batch, string username) =>
        new() { BackendId = batch.BackendId, BatchId = batch.Id, Username = username };

    private static VoucherBatch Seed(NetworkDbContext db, BackendKind kind)
    {
        var site = new Site { Name = Guid.NewGuid().ToString("N") };
        var router = new Router { SiteId = site.Id, Name = "test-router" };
        var backend = new Backend { RouterId = router.Id, Kind = kind };
        var plan = new Plan { BackendId = backend.Id, Name = "test-plan" };
        var batch = new VoucherBatch { BackendId = backend.Id, PlanId = plan.Id };
        db.AddRange(site, router, backend, plan, batch);
        db.SaveChanges();
        return batch;
    }

    private sealed class TestStore : IDisposable
    {
        private readonly SqliteConnection connection;
        public NetworkDbContext Db { get; }
        public TestStore(string cs = "Data Source=:memory:;Foreign Keys=True;Pooling=False")
        {
            connection = new SqliteConnection(cs);
            connection.Open();
            Db = new NetworkDbContext(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(connection).Options);
            Db.Database.EnsureCreated();
        }
        public void Dispose()
        {
            Db.Dispose();
            connection.Dispose();
        }
    }
}
