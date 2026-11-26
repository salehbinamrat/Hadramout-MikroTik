using Hadramout.Core;
using Hadramout.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Hadramout.Core.Tests;

public sealed class DatabaseDurabilityTests
{
    [Fact]
    public void NewDatabaseHasIdentityVersionAndDurabilitySettings()
    {
        using var file = new TestFile();
        using var c = DatabaseStore.Open(file.Path);
        Assert.Equal((long)DatabaseStore.ApplicationId, Scalar(c, "PRAGMA application_id"));
        Assert.Equal((long)DatabaseStore.CurrentSchemaVersion, Scalar(c, "PRAGMA user_version"));
        Assert.Equal(1L, Scalar(c, "PRAGMA foreign_keys"));
        Assert.Equal(2L, Scalar(c, "PRAGMA synchronous"));
        Assert.Equal("wal", Scalar(c, "PRAGMA journal_mode"));
        Assert.Equal("ok", Scalar(c, "PRAGMA quick_check"));
    }

    [Fact]
    public void VersionOneUpgradePreservesRowsAndAddsIndexes()
    {
        using var file = new TestFile();
        Guid id;
        using (var c = DatabaseStore.Open(file.Path))
        {
            using var db = Context(c);
            var site = new Site { Name = "retained" };
            id = site.Id;
            db.Sites.Add(site);
            db.SaveChanges();
            RecreateV1Fixture(c);
        }
        using var upgraded = DatabaseStore.Open(file.Path);
        using var read = Context(upgraded);
        Assert.Equal(id, read.Sites.Single().Id);
        Assert.Equal(2L, Scalar(upgraded, "PRAGMA user_version"));
        Assert.Equal(2L, Scalar(upgraded, """
            SELECT count(*) FROM sqlite_schema WHERE type='index'
            AND name IN ('IX_voucher_batches_BackendId_PlanId','IX_voucher_reservations_BackendId_BatchId')
            """));
    }

    [Fact]
    public void FailedMigrationRollsBackSchemaAndVersion()
    {
        using var file = new TestFile();
        using (var c = DatabaseStore.Open(file.Path))
        {
            RecreateV1Fixture(c);
            // Force failure at the second DDL statement without changing the original migration.
            Execute(c, "CREATE INDEX IX_voucher_reservations_BackendId_BatchId ON sites(Name);");
        }
        Assert.Throws<SqliteException>(() => DatabaseStore.Open(file.Path));
        using var raw = file.OpenRaw();
        Assert.Equal(1L, Scalar(raw, "PRAGMA user_version"));
        Assert.Equal(0L, Scalar(raw, "SELECT count(*) FROM sqlite_schema WHERE name='IX_voucher_batches_BackendId_PlanId'"));
        Assert.Equal("ok", Scalar(raw, "PRAGMA quick_check"));
    }

    [Fact]
    public void ForeignUnversionedDatabaseIsRejectedWithoutRemovingData()
    {
        using var file = new TestFile();
        using (var raw = file.OpenRaw())
            Execute(raw, "CREATE TABLE foreign_data (value TEXT); INSERT INTO foreign_data VALUES ('keep');");
        Assert.Throws<InvalidOperationException>(() => DatabaseStore.Open(file.Path));
        using var reopened = file.OpenRaw();
        Assert.Equal("keep", Scalar(reopened, "SELECT value FROM foreign_data"));
        Assert.Equal(0L, Scalar(reopened, "PRAGMA user_version"));
    }

    [Fact]
    public void FutureSchemaIsRejectedWithoutDowngrade()
    {
        using var file = new TestFile();
        using (var c = DatabaseStore.Open(file.Path))
            Execute(c, "PRAGMA user_version=999;");
        Assert.Throws<InvalidOperationException>(() => DatabaseStore.Open(file.Path));
        using var raw = file.OpenRaw();
        Assert.Equal(999L, Scalar(raw, "PRAGMA user_version"));
    }

    [Fact]
    public void WrongApplicationIdentityIsRejected()
    {
        using var file = new TestFile();
        using (var c = DatabaseStore.Open(file.Path))
            Execute(c, "PRAGMA application_id=123;");
        Assert.Throws<InvalidOperationException>(() => DatabaseStore.Open(file.Path));
        using var raw = file.OpenRaw();
        Assert.Equal(123L, Scalar(raw, "PRAGMA application_id"));
    }

    [Fact]
    public void DisposedUncommittedTransactionDoesNotAffectCommittedRows()
    {
        using var file = new TestFile();
        using (var c = DatabaseStore.Open(file.Path))
        using (var db = Context(c))
        {
            db.Sites.Add(new Site { Name = "committed" });
            db.SaveChanges();
            using var tx = db.Database.BeginTransaction();
            db.Sites.Add(new Site { Name = "uncommitted" });
            db.SaveChanges();
            // Dispose without commit simulates rollback on connection shutdown, not power loss.
        }
        using var reopened = DatabaseStore.Open(file.Path);
        using var read = Context(reopened);
        Assert.Equal("committed", read.Sites.Single().Name);
    }

    [Fact]
    public void ConcurrentInitializersAgreeOnVersion()
    {
        using var file = new TestFile();
        Parallel.For(0, 4, _ =>
        {
            using var c = DatabaseStore.Open(file.Path);
            Assert.Equal(2L, Scalar(c, "PRAGMA user_version"));
        });
        using var final = DatabaseStore.Open(file.Path);
        Assert.Equal("ok", Scalar(final, "PRAGMA quick_check"));
    }

    [Fact]
    public void MigrationSchemaEnforcesCrossBackendAndDuplicateConstraints()
    {
        using var file = new TestFile();
        using var c = DatabaseStore.Open(file.Path);
        using var db = Context(c);
        var site = new Site { Name = "site" };
        var router = new Router { SiteId = site.Id, Name = "router" };
        var first = new Backend { RouterId = router.Id, Kind = BackendKind.Hotspot };
        var second = new Backend { RouterId = router.Id, Kind = BackendKind.UserManager6 };
        var plan = new Plan { BackendId = first.Id, Name = "plan" };
        var batch = new VoucherBatch { BackendId = first.Id, PlanId = plan.Id };
        db.AddRange(site, router, first, second, plan, batch);
        db.SaveChanges();
        db.Reservations.Add(new VoucherReservation { BackendId = first.Id, BatchId = batch.Id, Username = "001" });
        db.SaveChanges();
        db.Reservations.Add(new VoucherReservation { BackendId = first.Id, BatchId = batch.Id, Username = "001" });
        Assert.Throws<DbUpdateException>(() => db.SaveChanges());
        db.ChangeTracker.Clear();
        db.Reservations.Add(new VoucherReservation { BackendId = second.Id, BatchId = batch.Id, Username = "002" });
        Assert.Throws<DbUpdateException>(() => db.SaveChanges());
    }

    private static NetworkDbContext Context(SqliteConnection c) =>
        new(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c).Options);

    // Synthetic exact v1 fixture: v2 is solely the two named indexes.
    private static void RecreateV1Fixture(SqliteConnection c) =>
        Execute(c, """
            DROP INDEX IX_voucher_batches_BackendId_PlanId;
            DROP INDEX IX_voucher_reservations_BackendId_BatchId;
            PRAGMA user_version=1;
            """);

    private static object Scalar(SqliteConnection c, string sql)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        return cmd.ExecuteScalar() ?? throw new InvalidOperationException("Expected a scalar.");
    }

    private static void Execute(SqliteConnection c, string sql)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private sealed class TestFile : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("hadramout-db-test-");
        public string Path => System.IO.Path.Combine(directory.FullName, "test.db");
        public SqliteConnection OpenRaw()
        {
            var c = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = Path, Pooling = false, ForeignKeys = true }.ToString());
            c.Open();
            return c;
        }
        public void Dispose() => directory.Delete(recursive: true);
    }
}
