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
            RecreateLegacyFixture(c, 1);
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
            RecreateLegacyFixture(c, 1);
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
        using var candidate = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        using (var c = DatabaseStore.Open(candidate.Path)) { }
        UserManager6CreateJournal.RequireEquivalentForRestore(file.Path, candidate.Path);
        var journal = new UserManager6CreateJournal(file.Path);
        journal.Prepare(id, "admin");
        Assert.Throws<InvalidOperationException>(() =>
            UserManager6CreateJournal.RequireEquivalentForRestore(file.Path, candidate.Path));
        Assert.Throws<InvalidOperationException>(() =>
            UserManager6CreateJournal.RequireEquivalentForRestore(candidate.Path, file.Path));
        Assert.True(journal.TryBeginDispatch(id));
        Assert.Throws<InvalidOperationException>(() =>
            UserManager6CreateJournal.RequireEquivalentForRestore(file.Path, candidate.Path));
    }

    [Theory]
    [InlineData("prepared")]
    [InlineData("started")]
    [InlineData("indeterminate")]
    [InlineData("acknowledged")]
    public void JournalRestoreAcceptsExactHistoryWithoutRearming(string state)
    {
        using var file = new TestFile();
        using var candidate = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        journal.Prepare(id, "admin");
        if (state != "prepared") Assert.True(journal.TryBeginDispatch(id));
        if (state == "indeterminate") Assert.True(journal.TryMarkIndeterminate(id));
        if (state == "acknowledged") Assert.True(journal.TryMarkAcknowledged(id));
        DatabaseBackup.Create(file.Path, candidate.Path);
        UserManager6CreateJournal.RequireEquivalentForRestore(file.Path, candidate.Path);
        var restored = new UserManager6CreateJournal(candidate.Path);
        Assert.Equal(journal.Read(id), restored.Read(id));
        if (state != "prepared") Assert.False(restored.TryBeginDispatch(id));
    }

    [Theory]
    [InlineData("stale-state")]
    [InlineData("newer-state")]
    [InlineData("username")]
    [InlineData("plan")]
    [InlineData("router")]
    [InlineData("site")]
    public void JournalRestoreRejectsChangedStateOrTarget(string condition)
    {
        using var file = new TestFile();
        using var candidate = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        journal.Prepare(id, "admin");
        DatabaseBackup.Create(file.Path, candidate.Path);
        var restored = new UserManager6CreateJournal(candidate.Path);
        if (condition == "stale-state") Assert.True(journal.TryBeginDispatch(id));
        else if (condition == "newer-state") Assert.True(restored.TryBeginDispatch(id));
        else
        {
            using var c = DatabaseStore.OpenExisting(candidate.Path);
            Execute(c, condition switch
            {
                "username" => "UPDATE voucher_reservations SET Username='002';",
                "plan" => "UPDATE plans SET Name='different';",
                "router" => "UPDATE routers SET Name='different';",
                "site" => "UPDATE sites SET Name='different';",
                _ => throw new InvalidOperationException()
            });
        }
        Assert.Throws<InvalidOperationException>(() =>
            UserManager6CreateJournal.RequireEquivalentForRestore(file.Path, candidate.Path));
    }

    [Fact]
    public void VersionFourMigrationPreservesReservationAndCreatesEmptyJournal()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        using (var c = DatabaseStore.Open(file.Path))
            RecreateLegacyFixture(c, 4);
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

    // Centralized synthetic legacy fixture construction. Keep the explicit schema
    // guard in sync with new migrations; never silently leave a newer table behind.
    internal static void RecreateLegacyFixture(SqliteConnection c, int version)
    {
        if (version is < 1 or > 4) throw new ArgumentOutOfRangeException(nameof(version));
        Assert.Equal(5, DatabaseStore.CurrentSchemaVersion);
        Assert.Equal(5L, Scalar(c, "PRAGMA user_version;"));
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "DROP TABLE um6_create_journal;";
        if (version < 4) cmd.CommandText += " DROP TABLE audit_events;";
        if (version < 3) cmd.CommandText += " DROP TABLE router_credentials;";
        if (version < 2) cmd.CommandText +=
            " DROP INDEX IX_voucher_batches_BackendId_PlanId; DROP INDEX IX_voucher_reservations_BackendId_BatchId;";
        cmd.CommandText += " PRAGMA user_version=" + version.ToString(System.Globalization.CultureInfo.InvariantCulture) + ";";
        cmd.ExecuteNonQuery();
        tx.Commit();

        cmd.Transaction = null;
        cmd.CommandText = "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%';";
        Assert.Equal(version >= 4 ? 8L : version == 3 ? 7L : 6L, (long)cmd.ExecuteScalar()!);
        Assert.Equal((long)version, Scalar(c, "PRAGMA user_version;"));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void EveryLegacyFixtureHasOnlyItsOwnSchemaAndUpgrades(int version)
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        using (var c = DatabaseStore.Open(file.Path)) RecreateLegacyFixture(c, version);
        using var upgraded = DatabaseStore.OpenExisting(file.Path);
        Assert.Equal((long)DatabaseStore.CurrentSchemaVersion, Scalar(upgraded, "PRAGMA user_version;"));
        Assert.Equal(1L, Scalar(upgraded, "SELECT count(*) FROM voucher_reservations;"));
        Assert.Equal(0L, Scalar(upgraded, "SELECT count(*) FROM um6_create_journal;"));
        Assert.Equal("001", new UserManager6CreateJournal(file.Path).Prepare(id, "admin").Username);
    }

    [Fact]
    public void ConflictingVersionFourJournalIsRejectedWithoutChangingExistingData()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        journal.Prepare(id, "admin");
        Assert.True(journal.TryBeginDispatch(id));
        using (var c = DatabaseStore.Open(file.Path)) Execute(c, "PRAGMA user_version=4;");
        Assert.Throws<SqliteException>(() => DatabaseStore.OpenExisting(file.Path));
        using var raw = file.OpenRaw();
        Assert.Equal(4L, Scalar(raw, "PRAGMA user_version;"));
        Assert.Equal(2L, Scalar(raw, "SELECT State FROM um6_create_journal;"));
        Assert.Equal("001", Scalar(raw, "SELECT Username FROM voucher_reservations;"));
        Assert.Equal("ok", Scalar(raw, "PRAGMA quick_check;"));
    }

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
