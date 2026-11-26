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
        Assert.Equal((long)DatabaseStore.CurrentSchemaVersion, Scalar(upgraded, "PRAGMA user_version"));
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
            Assert.Equal((long)DatabaseStore.CurrentSchemaVersion, Scalar(c, "PRAGMA user_version"));
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

    [Fact]
    public void JournalPersistsOneShotClaimAcrossReopenAndNeverRearms()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        var entry = journal.Prepare(id, "admin");
        Assert.Equal("001", entry.Username);
        Assert.Equal(UserManager6CreateState.Prepared, entry.State);
        Assert.False(journal.TryMarkAcknowledged(id));
        Assert.True(journal.TryBeginDispatch(id));
        var reopened = new UserManager6CreateJournal(file.Path);
        Assert.Equal(UserManager6CreateState.DispatchStarted, reopened.Read(id)!.State);
        Assert.False(reopened.TryBeginDispatch(id));
        Assert.True(reopened.TryMarkIndeterminate(id));
        Assert.False(reopened.TryBeginDispatch(id));
        Assert.False(reopened.TryMarkAcknowledged(id));
        Assert.Equal(UserManager6CreateState.Indeterminate, reopened.Read(id)!.State);
    }

    [Fact]
    public void JournalAcknowledgementIsTerminalAndCannotBeReplayed()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        journal.Prepare(id, "admin");
        Assert.True(journal.TryBeginDispatch(id));
        Assert.True(journal.TryMarkAcknowledged(id));
        Assert.False(journal.TryBeginDispatch(id));
        Assert.False(journal.TryMarkIndeterminate(id));
        Assert.Equal(UserManager6CreateState.Acknowledged, journal.Read(id)!.State);
        Assert.Throws<SqliteException>(() => journal.Prepare(id, "admin"));
    }

    [Fact]
    public void ConcurrentDispatchClaimsHaveExactlyOneWinner()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        journal.Prepare(id, "admin");
        int winners = 0;
        Parallel.For(0, 8, _ =>
        {
            if (new UserManager6CreateJournal(file.Path).TryBeginDispatch(id))
                Interlocked.Increment(ref winners);
        });
        Assert.Equal(1, winners);
        Assert.Equal(UserManager6CreateState.DispatchStarted, journal.Read(id)!.State);
    }

    [Theory]
    [InlineData(BackendKind.Hotspot)]
    [InlineData(BackendKind.UserManager7)]
    [InlineData(BackendKind.Pppoe)]
    public void JournalRejectsOtherBackendReservations(BackendKind kind)
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, kind);
        var journal = new UserManager6CreateJournal(file.Path);
        Assert.Throws<InvalidOperationException>(() => journal.Prepare(id, "admin"));
        Assert.Null(journal.Read(id));
        Assert.False(journal.TryBeginDispatch(id));
    }

    [Fact]
    public void JournalRejectsRewrittenIdentityAndDirectRearmOrDeletion()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        journal.Prepare(id, "admin");
        using var c = DatabaseStore.Open(file.Path);
        Execute(c, "UPDATE voucher_reservations SET Username='002';");
        Assert.False(journal.TryBeginDispatch(id));
        Execute(c, "UPDATE voucher_reservations SET Username='001';");
        Assert.True(journal.TryBeginDispatch(id));
        Assert.Throws<SqliteException>(() => Execute(c, "UPDATE um6_create_journal SET State=1;"));
        Assert.Throws<SqliteException>(() => Execute(c, "UPDATE um6_create_journal SET Customer='other', State=3;"));
        Assert.Throws<SqliteException>(() => Execute(c, "DELETE FROM um6_create_journal;"));
        Assert.Throws<SqliteException>(() => Execute(c, """
            INSERT OR REPLACE INTO um6_create_journal SELECT ReservationId,BackendId,RouterId,Customer,Username,1
            FROM um6_create_journal;
            """));
        Assert.Equal(UserManager6CreateState.DispatchStarted, journal.Read(id)!.State);
    }

    [Fact]
    public void JournalRestoreGuardNeverAllowsLossOfPreparedOrClaimedEvidence()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        UserManager6CreateJournal.RequireEmptyForRestore(file.Path);
        var journal = new UserManager6CreateJournal(file.Path);
        journal.Prepare(id, "admin");
        Assert.Throws<InvalidOperationException>(() => UserManager6CreateJournal.RequireEmptyForRestore(file.Path));
        Assert.True(journal.TryBeginDispatch(id));
        Assert.Throws<InvalidOperationException>(() => UserManager6CreateJournal.RequireEmptyForRestore(file.Path));
    }

    [Fact]
    public void VersionFourMigrationPreservesReservationAndCreatesEmptyJournal()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        using (var c = DatabaseStore.Open(file.Path))
            Execute(c, "DROP TABLE um6_create_journal; PRAGMA user_version=4;");
        using var upgraded = DatabaseStore.OpenExisting(file.Path);
        Assert.Equal(5L, Scalar(upgraded, "PRAGMA user_version;"));
        Assert.Equal(1L, Scalar(upgraded, "SELECT count(*) FROM voucher_reservations;"));
        Assert.Equal(0L, Scalar(upgraded, "SELECT count(*) FROM um6_create_journal;"));
        Assert.Equal("001", new UserManager6CreateJournal(file.Path).Prepare(id, "admin").Username);
    }

    [Fact]
    public void OpenExistingCannotInitializeAnUnownedEmptyFile()
    {
        using var file = new TestFile();
        using (var raw = file.OpenRaw()) Execute(raw, "PRAGMA user_version=0;");
        Assert.Throws<InvalidOperationException>(() => DatabaseStore.OpenExisting(file.Path));
        using var reopened = file.OpenRaw();
        Assert.Equal(0L, Scalar(reopened, "PRAGMA application_id;"));
        Assert.Equal(0L, Scalar(reopened, "PRAGMA user_version;"));
    }

    internal static Guid SeedReservation(string path, BackendKind kind)
    {
        using var c = DatabaseStore.Open(path);
        using var db = Context(c);
        var site = new Site { Name = "journal-site" };
        var router = new Router { SiteId = site.Id, Name = "journal-router" };
        var backend = new Backend { RouterId = router.Id, Kind = kind };
        var plan = new Plan { BackendId = backend.Id, Name = "day" };
        var batch = new VoucherBatch { BackendId = backend.Id, PlanId = plan.Id };
        var reservation = new VoucherReservation { BackendId = backend.Id, BatchId = batch.Id, Username = "001" };
        db.AddRange(site, router, backend, plan, batch, reservation);
        db.SaveChanges();
        return reservation.Id;
    }

    private static NetworkDbContext Context(SqliteConnection c) =>
        new(new DbContextOptionsBuilder<NetworkDbContext>().UseSqlite(c).Options);

    // Synthetic v1 fixture: remove the v3 table and both v2 indexes.
    private static void RecreateV1Fixture(SqliteConnection c) =>
        Execute(c, """
            DROP TABLE um6_create_journal;
            DROP TABLE audit_events;
            DROP TABLE router_credentials;
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
