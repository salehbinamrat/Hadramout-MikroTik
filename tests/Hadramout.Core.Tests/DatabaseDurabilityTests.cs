using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
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
        Assert.Equal((long)DatabaseStore.CurrentSchemaVersion, Scalar(upgraded, "PRAGMA user_version;"));
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

    [Fact]
    public void RecoveryReviewIsRouterScopedAndPaginatesWithoutRearming()
    {
        using var file = new TestFile();
        Guid first = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        var initial = journal.Prepare(first, "admin");
        Guid[] additional = new Guid[4];
        using (var c = DatabaseStore.OpenExisting(file.Path))
        using (var db = Context(c))
        {
            var original = db.Reservations.Single();
            for (int i = 0; i < additional.Length; i++)
            {
                var reservation = new VoucherReservation
                {
                    BackendId = original.BackendId, BatchId = original.BatchId, Username = "extra-" + i
                };
                additional[i] = reservation.Id;
                db.Reservations.Add(reservation);
            }
            var router = new Router { SiteId = db.Sites.Single().Id, Name = "other-router" };
            var backend = new Backend { RouterId = router.Id, Kind = BackendKind.UserManager6 };
            var plan = new Plan { BackendId = backend.Id, Name = "day" };
            var batch = new VoucherBatch { BackendId = backend.Id, PlanId = plan.Id };
            var other = new VoucherReservation { BackendId = backend.Id, BatchId = batch.Id, Username = "001" };
            db.AddRange(router, backend, plan, batch, other);
            db.SaveChanges();
            journal.Prepare(other.Id, "admin");
            Assert.True(journal.TryBeginDispatch(other.Id));
            Assert.Equal(1L, journal.ReadCounts(router.Id).RequiresReview);
        }
        foreach (Guid id in additional) journal.Prepare(id, "admin");
        Assert.True(journal.TryBeginDispatch(first));
        Assert.True(journal.TryBeginDispatch(additional[0]));
        Assert.True(journal.TryMarkIndeterminate(additional[0]));
        Assert.True(journal.TryBeginDispatch(additional[1]));
        Assert.True(journal.TryMarkAcknowledged(additional[1]));
        Assert.True(journal.TryBeginDispatch(additional[2]));
        var counts = journal.ReadCounts(initial.RouterId);
        Assert.Equal(new UserManager6CreationCounts(1, 2, 1, 1), counts);
        Assert.Equal(4L, counts.RequiresReview);

        var page = journal.ReadReviewPage(initial.RouterId, pageSize: 2);
        Assert.Equal(2, page.Rows.Count);
        Assert.NotNull(page.NextAfterReservationId);
        var next = journal.ReadReviewPage(initial.RouterId, page.NextAfterReservationId, 2);
        Assert.Equal(2, next.Rows.Count);
        Assert.Null(next.NextAfterReservationId);
        var rows = page.Rows.Concat(next.Rows).ToArray();
        Assert.Equal(4, rows.Select(row => row.Entry.ReservationId).Distinct().Count());
        Assert.All(rows, row =>
        {
            Assert.Equal(initial.RouterId, row.Entry.RouterId);
            Assert.True(row.LocalIdentityMatches);
            Assert.False(journal.TryBeginDispatch(row.Entry.ReservationId));
        });
        Assert.DoesNotContain(rows, row => row.Entry.ReservationId == additional[3]);
        Assert.Equal(counts, journal.ReadCounts(initial.RouterId));
    }

    [Fact]
    public void RecoveryReviewReportsDriftInsteadOfHidingClaimedRow()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        var entry = journal.Prepare(id, "admin");
        Assert.True(journal.TryBeginDispatch(id));
        using (var c = DatabaseStore.OpenExisting(file.Path))
            Execute(c, "UPDATE voucher_reservations SET Username='changed';");
        var row = Assert.Single(journal.ReadReviewPage(entry.RouterId).Rows);
        Assert.Equal("001", row.Entry.Username);
        Assert.False(row.LocalIdentityMatches);
        Assert.Equal(UserManager6CreateState.DispatchStarted, row.Entry.State);
        Assert.False(journal.TryBeginDispatch(id));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(501)]
    public void RecoveryReviewRejectsUnboundedPages(int pageSize)
    {
        using var file = new TestFile();
        var journal = new UserManager6CreateJournal(file.Path);
        Assert.Throws<ArgumentOutOfRangeException>(() => journal.ReadReviewPage(Guid.NewGuid(), pageSize: pageSize));
    }

    [Fact]
    public void RecoveryReviewDoesNotCreateOrMigrateDatabase()
    {
        using var file = new TestFile();
        var journal = new UserManager6CreateJournal(file.Path);
        Assert.Throws<SqliteException>(() => journal.ReadCounts(Guid.NewGuid()));
        Assert.False(File.Exists(file.Path));
        using (var c = DatabaseStore.Open(file.Path)) RecreateLegacyFixture(c, 4);
        Assert.Throws<InvalidDataException>(() => journal.ReadReviewPage(Guid.NewGuid()));
        using var raw = file.OpenRaw();
        Assert.Equal(4L, Scalar(raw, "PRAGMA user_version;"));
    }

    [Fact]
    public void RecoveryReviewEmptyScopeIsNotAnErrorAndDoesNotCountPreparedAsUncertain()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        var entry = journal.Prepare(id, "admin");
        Assert.Empty(journal.ReadReviewPage(entry.RouterId).Rows);
        Assert.Null(journal.ReadReviewPage(entry.RouterId).NextAfterReservationId);
        Assert.Equal(new UserManager6CreationCounts(1, 0, 0, 0), journal.ReadCounts(entry.RouterId));
        Assert.Equal(new UserManager6CreationCounts(0, 0, 0, 0), journal.ReadCounts(Guid.NewGuid()));
    }

    [Fact]
    public void RouterTargetEnrollmentIsImmutableAndScoped()
    {
        using var file = new TestFile();
        SeedReservation(file.Path, BackendKind.UserManager6);
        Guid router;
        Guid other;
        using (var c = DatabaseStore.OpenExisting(file.Path))
        using (var db = Context(c))
        {
            router = db.Routers.Single().Id;
            var second = new Router { SiteId = db.Sites.Single().Id, Name = "other" };
            db.Routers.Add(second);
            db.SaveChanges();
            other = second.Id;
        }
        using var ca = CreateEnrollmentCa();
        byte[] root = ca.RawData;
        var store = new RouterTargetStore(file.Path);
        Assert.Null(store.Read(router));
        string pin = new('a', 64);
        store.Enroll(router, "Router.TEST.", 8729, "ROUTER.TEST", pin, root);
        var target = store.Read(router);
        Assert.NotNull(target);
        Assert.Equal("router.test", target.Host);
        Assert.Equal("router.test", target.CertificateName);
        Assert.Equal(pin.ToUpperInvariant(), target.LeafSha256);
        Assert.Equal(root, target.TrustedRootDer);
        Assert.Throws<SqliteException>(() => store.Enroll(router, "different.test", 8729, "router.test", pin, root));
        Assert.Throws<SqliteException>(() => store.Enroll(other, "different.test", 8729, "different.test", pin, root));
        Assert.Throws<SqliteException>(() => store.Enroll(other, "router.test", 8729, "different.test", new string('b',64), root));
        Assert.Throws<SqliteException>(() => store.Enroll(Guid.NewGuid(), "new.test", 8729, "new.test", new string('c',64), root));
        using var dbConnection = DatabaseStore.OpenExisting(file.Path);
        Assert.Throws<SqliteException>(() => Execute(dbConnection, "UPDATE router_targets SET Port=8730;"));
        Assert.Throws<SqliteException>(() => Execute(dbConnection, "DELETE FROM router_targets;"));
        Assert.Throws<SqliteException>(() => Execute(dbConnection, "INSERT OR REPLACE INTO router_targets SELECT * FROM router_targets;"));
        Assert.Null(store.Read(other));
    }

    [Theory]
    [InlineData("bad-host")]
    [InlineData("bad-port")]
    [InlineData("bad-pin")]
    [InlineData("empty-root")]
    public void RouterTargetRejectsInvalidEnrollment(string condition)
    {
        using var file = new TestFile();
        SeedReservation(file.Path, BackendKind.UserManager6);
        using var c = DatabaseStore.OpenExisting(file.Path);
        using var db = Context(c);
        Guid id = db.Routers.Single().Id;
        using var ca = CreateEnrollmentCa();
        var store = new RouterTargetStore(file.Path);
        Assert.ThrowsAny<ArgumentException>(() => store.Enroll(id,
            condition == "bad-host" ? "https://router.test" : "router.test",
            condition == "bad-port" ? 0 : 8729, "router.test",
            condition == "bad-pin" ? "invalid" : new string('a', 64),
            condition == "empty-root" ? [] : ca.RawData));
        Assert.Null(store.Read(id));
    }

    [Fact]
    public void RouterTargetRestoreRequiresIdenticalTrustRecords()
    {
        using var file = new TestFile();
        using var candidate = new TestFile();
        SeedReservation(file.Path, BackendKind.UserManager6);
        Guid id;
        using (var c = DatabaseStore.OpenExisting(file.Path))
        using (var db = Context(c)) id = db.Routers.Single().Id;
        DatabaseBackup.Create(file.Path, candidate.Path);
        using var ca = CreateEnrollmentCa();
        new RouterTargetStore(file.Path).Enroll(id, "router.test", 8729, "router.test", new string('a',64), ca.RawData);
        Assert.Throws<InvalidOperationException>(() => RouterTargetStore.RequireEquivalentForRestore(file.Path, candidate.Path));
        new RouterTargetStore(candidate.Path).Enroll(id, "router.test", 8729, "router.test", new string('a',64), ca.RawData);
        RouterTargetStore.RequireEquivalentForRestore(file.Path, candidate.Path);
    }

    private static System.Security.Cryptography.X509Certificates.X509Certificate2 CreateEnrollmentCa()
    {
        using var key = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=Enrollment test CA",
            key, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(true,false,0,true));
        using var issued = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(issued.RawData);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void BoundCreationIntentPersistsExactProfileAndOneShotClaim()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        var entry = journal.Prepare(id, "admin");
        Assert.Throws<InvalidOperationException>(() => journal.PrepareBoundIntent(id, "owner", "remote-day"));
        Assert.False(journal.TryBeginBoundDispatch(id));
        EnrollIntentTarget(file.Path, entry.RouterId);
        journal.PrepareBoundIntent(id, "owner", "remote-day");
        var reopened = new UserManager6CreateJournal(file.Path);
        var intent = reopened.ReadBoundIntent(id);
        Assert.NotNull(intent);
        Assert.Equal("day", intent.PlanName);
        Assert.Equal("owner", intent.ProfileOwner);
        Assert.Equal("remote-day", intent.ProfileName);
        Assert.Equal(new string('A',64), intent.LeafSha256);
        Assert.Throws<SqliteException>(() => reopened.PrepareBoundIntent(id, "owner", "other"));
        Assert.False(reopened.TryBeginDispatch(id));
        Assert.False(reopened.TryBeginBoundDispatch(id));
        Assert.Equal(UserManager6CreateState.Prepared, reopened.Read(id)!.State);
        new UserManager6VoucherSecretStore(file.Path).Save(id, "synthetic-secret"u8);
        Assert.True(reopened.TryBeginBoundDispatch(id));
        Assert.False(reopened.TryBeginBoundDispatch(id));
        Assert.True(reopened.TryMarkIndeterminate(id));
        Assert.False(reopened.TryBeginBoundDispatch(id));
        Assert.Equal(intent, reopened.ReadBoundIntent(id));
    }

    [Theory]
    [InlineData("username")]
    [InlineData("plan")]
    [InlineData("backend")]
    [SupportedOSPlatform("windows")]
    public void BoundCreationClaimRejectsLocalDrift(string condition)
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        var entry = journal.Prepare(id, "admin");
        EnrollIntentTarget(file.Path, entry.RouterId);
        journal.PrepareBoundIntent(id, "admin", "day");
        new UserManager6VoucherSecretStore(file.Path).Save(id, "synthetic-secret"u8);
        using (var c = DatabaseStore.OpenExisting(file.Path))
            Execute(c, condition switch
            {
                "username" => "UPDATE voucher_reservations SET Username='002';",
                "plan" => "UPDATE plans SET Name='changed';",
                "backend" => "UPDATE backends SET Kind=1;",
                _ => throw new InvalidOperationException()
            });
        Assert.False(journal.TryBeginBoundDispatch(id));
        Assert.False(journal.TryBeginDispatch(id));
        Assert.Equal(UserManager6CreateState.Prepared, journal.Read(id)!.State);
    }

    [Fact]
    public void BoundCreationIntentCannotBeReplacedOrDeleted()
    {
        using var file = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        var entry = journal.Prepare(id, "admin");
        EnrollIntentTarget(file.Path, entry.RouterId);
        journal.PrepareBoundIntent(id, "admin", "day");
        using var c = DatabaseStore.OpenExisting(file.Path);
        Assert.Throws<SqliteException>(() => Execute(c, "UPDATE um6_create_intents SET ProfileName='other';"));
        Assert.Throws<SqliteException>(() => Execute(c, "DELETE FROM um6_create_intents;"));
        Assert.Throws<SqliteException>(() => Execute(c, "INSERT OR REPLACE INTO um6_create_intents SELECT * FROM um6_create_intents;"));
        Assert.Equal("day", journal.ReadBoundIntent(id)!.ProfileName);
    }

    [Fact]
    public void RestoreRejectsMissingOrDifferentBoundIntentEvenWhenJournalMatches()
    {
        using var file = new TestFile();
        using var candidate = new TestFile();
        Guid id = SeedReservation(file.Path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(file.Path);
        var entry = journal.Prepare(id, "admin");
        EnrollIntentTarget(file.Path, entry.RouterId);
        DatabaseBackup.Create(file.Path, candidate.Path);
        journal.PrepareBoundIntent(id, "admin", "day");
        UserManager6CreateJournal.RequireEquivalentForRestore(file.Path, candidate.Path);
        Assert.Throws<InvalidOperationException>(() =>
            UserManager6CreateJournal.RequireEquivalentIntentsForRestore(file.Path, candidate.Path));
        new UserManager6CreateJournal(candidate.Path).PrepareBoundIntent(id, "admin", "other");
        Assert.Throws<InvalidOperationException>(() =>
            UserManager6CreateJournal.RequireEquivalentIntentsForRestore(file.Path, candidate.Path));
        using var identical = new TestFile();
        DatabaseBackup.Create(file.Path, identical.Path);
        UserManager6CreateJournal.RequireEquivalentIntentsForRestore(file.Path, identical.Path);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [SupportedOSPlatform("windows")]
    public void VoucherSecretRoundTripDistinguishesMissingAndExplicitEmpty(bool empty)
    {
        using var file = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        var store = new UserManager6VoucherSecretStore(file.Path);
        Assert.Null(store.Load(id));
        byte[] input = empty ? [] : "synthetic-voucher-password"u8.ToArray();
        store.Save(id, input);
        using var lease = store.Load(id);
        Assert.NotNull(lease);
        Assert.True(input.AsSpan().SequenceEqual(lease.Password.Span));
        var borrowed = lease.Password;
        lease.Dispose();
        Assert.All(borrowed.ToArray(), value => Assert.Equal((byte)0, value));
        Assert.Throws<ObjectDisposedException>(() => { _ = lease.Password; });
        using var c = DatabaseStore.OpenExisting(file.Path);
        byte[] envelope = (byte[])Scalar(c, "SELECT PasswordEnvelope FROM um6_voucher_secrets;");
        Assert.NotEmpty(envelope);
        if (!empty) Assert.False(envelope.AsSpan().IndexOf(input) >= 0);
        Assert.True(new UserManager6CreateJournal(file.Path).TryBeginBoundDispatch(id));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void VoucherSecretCannotBeReplacedDeletedOrSavedWithoutPreparedIntent()
    {
        using var file = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        var store = new UserManager6VoucherSecretStore(file.Path);
        Assert.Throws<SqliteException>(() => store.Save(Guid.NewGuid(), "synthetic"u8));
        Assert.Throws<ArgumentException>(() => store.Save(id, new byte[4097]));
        store.Save(id, "synthetic-original"u8);
        Assert.Throws<SqliteException>(() => store.Save(id, "synthetic-replacement"u8));
        using var c = DatabaseStore.OpenExisting(file.Path);
        Assert.Throws<SqliteException>(() => Execute(c, "UPDATE um6_voucher_secrets SET PasswordEnvelope=X'01';"));
        Assert.Throws<SqliteException>(() => Execute(c, "DELETE FROM um6_voucher_secrets;"));
        Assert.Throws<SqliteException>(() => Execute(c, "INSERT OR REPLACE INTO um6_voucher_secrets SELECT * FROM um6_voucher_secrets;"));
        Assert.True(new UserManager6CreateJournal(file.Path).TryBeginBoundDispatch(id));
        using var lease = store.Load(id);
        Assert.NotNull(lease);
        Assert.True(lease.Password.Span.SequenceEqual("synthetic-original"u8));
    }

    [Theory]
    [InlineData("corrupt")]
    [InlineData("other-reservation")]
    [InlineData("router-password-purpose")]
    [SupportedOSPlatform("windows")]
    public void InvalidVoucherSecretRollsBackClaimWithoutRearming(string condition)
    {
        using var file = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        byte[] envelope = condition switch
        {
            "other-reservation" => RouterCredentialProtector.Protect(Guid.NewGuid(), "um6-voucher-password/v1", "synthetic"u8),
            "router-password-purpose" => RouterCredentialProtector.Protect(id, "password", "synthetic"u8),
            _ => [1]
        };
        using (var c = DatabaseStore.OpenExisting(file.Path))
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "INSERT INTO um6_voucher_secrets VALUES($id,$envelope);";
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.Add("$envelope", SqliteType.Blob).Value = envelope;
            cmd.ExecuteNonQuery();
        }
        var journal = new UserManager6CreateJournal(file.Path);
        Assert.Throws<CryptographicException>(() => journal.TryBeginBoundDispatch(id));
        Assert.Equal(UserManager6CreateState.Prepared, journal.Read(id)!.State);
        Assert.False(journal.TryBeginDispatch(id));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void VoucherSecretRestoreCannotLoseOrChangeCiphertext()
    {
        using var file = new TestFile();
        using var candidate = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        DatabaseBackup.Create(file.Path, candidate.Path);
        new UserManager6VoucherSecretStore(file.Path).Save(id, "synthetic-one"u8);
        Assert.Throws<InvalidOperationException>(() =>
            UserManager6VoucherSecretStore.RequireEquivalentForRestore(file.Path, candidate.Path));
        new UserManager6VoucherSecretStore(candidate.Path).Save(id, "synthetic-two"u8);
        Assert.Throws<InvalidOperationException>(() =>
            UserManager6VoucherSecretStore.RequireEquivalentForRestore(file.Path, candidate.Path));
        using var identical = new TestFile();
        DatabaseBackup.Create(file.Path, identical.Path);
        UserManager6VoucherSecretStore.RequireEquivalentForRestore(file.Path, identical.Path);
    }

    [Theory]
    [InlineData("ack", 3, 4, 3, 4)]
    [InlineData("trap", 3, 3, 4, 4)]
    [InlineData("eof", 3, 3, 4, 4)]
    [InlineData("missing-profile", 1, 1, 0, 2)]
    [InlineData("existing", 2, 1, 1, 3)]
    [InlineData("lost-claim", 3, 2, 2, 3)]
    [SupportedOSPlatform("windows")]
    public async Task QualifiedCreationCoordinatesPreflightClaimAndResult(string condition, int completedReads,
        int stateValue, int outcomeValue, int commands)
    {
        var expectedState = (UserManager6CreateState)stateValue;
        var expectedOutcome = (UserManager6CoordinationOutcome)outcomeValue;
        using var file = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        new UserManager6VoucherSecretStore(file.Path).Save(id, "synthetic-voucher"u8);
        var journal = new UserManager6CreateJournal(file.Path);
        using var replies = new MemoryStream();
        await WriteReplyAsync(replies, "!re", "=version=6.49.19");
        await WriteReplyAsync(replies, "!done");
        if (completedReads >= 2 || condition != "missing-profile")
            await WriteReplyAsync(replies, "!re", "=owner=admin", "=name=day");
        await WriteReplyAsync(replies, "!done");
        if (condition != "missing-profile")
        {
            if (condition == "existing") await WriteReplyAsync(replies, "!re", "=customer=other", "=username=001");
            await WriteReplyAsync(replies, "!done");
        }
        if (condition == "ack") await WriteReplyAsync(replies, "!done", "=ret=*1");
        if (condition == "trap") await WriteReplyAsync(replies, "!trap", "=message=synthetic");

        // Observe the durable state at the actual start of add-command transmission.
        // Inject a competing claim just as the username lookup is sent.
        using var stream = new QualificationExchange(replies.ToArray(), word =>
        {
            if (word == "/tool/user-manager/user/print" && condition == "lost-claim")
                Assert.True(journal.TryBeginBoundDispatch(id));
            if (word == "/tool/user-manager/user/add")
                Assert.Equal(UserManager6CreateState.DispatchStarted, journal.Read(id)!.State);
        });
        var outcome = await UserManager6CreateCoordinator.ExecuteForQualificationAsync(file.Path, id, stream);
        Assert.Equal(expectedOutcome, outcome);
        Assert.Equal(expectedState, journal.Read(id)!.State);
        using var sent = new MemoryStream(stream.ToArray());
        var recorded = new List<string[]>();
        while (sent.Position != sent.Length)
            recorded.Add((await RouterOsWireCodec.ReadSentenceAsync(sent, CancellationToken.None))
                .Select(word => Encoding.UTF8.GetString(word)).ToArray());
        Assert.Equal(commands, recorded.Count);
        Assert.Equal("/system/resource/print", recorded[0][0]);
        Assert.Equal("/tool/user-manager/profile/print", recorded[1][0]);
        if (commands >= 3) Assert.Equal("/tool/user-manager/user/print", recorded[2][0]);
        if (commands == 4)
        {
            Assert.Equal(new[] { "/tool/user-manager/user/add", "=customer=admin", "=username=001",
                "=password=synthetic-voucher", "=disabled=yes", "=comment=hmk-create:" + id.ToString("N") }, recorded[3]);
        }
        if (expectedState != UserManager6CreateState.Prepared)
        {
            long length = stream.Length;
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                UserManager6CreateCoordinator.ExecuteForQualificationAsync(file.Path, id, stream));
            Assert.Equal(length, stream.Length);
        }
    }

    [Theory]
    [InlineData("malformed")]
    [InlineData("control")]
    [SupportedOSPlatform("windows")]
    public void ClaimRejectsNonTransmittablePasswordWithoutConsumingReservation(string condition)
    {
        using var file = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        new UserManager6VoucherSecretStore(file.Path).Save(id, condition == "malformed" ? new byte[] { 255 } : new byte[] { 0 });
        var journal = new UserManager6CreateJournal(file.Path);
        Assert.Throws<ArgumentException>(() => journal.TryBeginBoundDispatch(id));
        Assert.Equal(UserManager6CreateState.Prepared, journal.Read(id)!.State);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task QualifiedCreationInterruptedBeforePreflightCompletionNeverClaims()
    {
        using var file = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        new UserManager6VoucherSecretStore(file.Path).Save(id, "synthetic"u8);
        using var stream = new QualificationExchange([], _ => { });
        await Assert.ThrowsAsync<EndOfStreamException>(() =>
            UserManager6CreateCoordinator.ExecuteForQualificationAsync(file.Path, id, stream));
        Assert.Equal(UserManager6CreateState.Prepared, new UserManager6CreateJournal(file.Path).Read(id)!.State);
    }

    [Theory]
    [InlineData("match")]
    [InlineData("no-returned-id")]
    [InlineData("absent")]
    [InlineData("wrong-id")]
    [InlineData("bad-id")]
    [InlineData("wrong-customer")]
    [InlineData("wrong-username")]
    [InlineData("wrong-marker")]
    [InlineData("enabled")]
    [InlineData("missing-disabled")]
    [InlineData("duplicate")]
    [InlineData("trap")]
    [InlineData("wrong-version")]
    public async Task QualifiedDisabledCreationReadbackRequiresExactCompletedEvidence(string condition)
    {
        Guid id = Guid.NewGuid();
        string marker = "hmk-create:" + id.ToString("N");
        using var replies = new MemoryStream();
        await WriteReplyAsync(replies, "!re", condition == "wrong-version" ? "=version=7.20.1" : "=version=6.49.19");
        await WriteReplyAsync(replies, "!done");
        var row = new List<string> { "!re",
            condition == "wrong-id" ? "=.id=*2" : condition == "bad-id" ? "=.id=*Z" : "=.id=*1",
            condition == "wrong-customer" ? "=customer=other" : "=customer=admin",
            condition == "wrong-username" ? "=username=002" : "=username=001",
            "=comment=" + (condition == "wrong-marker" ? "different" : marker) };
        if (condition != "missing-disabled")
            row.Add(condition == "enabled" ? "=disabled=no" : "=disabled=yes");
        if (condition == "trap")
            await WriteReplyAsync(replies, "!trap", "=message=synthetic");
        else if (condition != "wrong-version")
        {
            if (condition != "absent") await WriteReplyAsync(replies, row.ToArray());
            if (condition == "duplicate") await WriteReplyAsync(replies, row.ToArray());
            await WriteReplyAsync(replies, "!done");
        }
        using var stream = new QualificationExchange(replies.ToArray(), _ => { });
        var receipt = new UserManager6CreateWireReceipt(UserManager6CreateWireOutcome.Acknowledged,
            condition == "no-returned-id" ? null : "*1");
        if (condition is "match" or "no-returned-id" or "absent")
        {
            var result = await RouterOsSession.ReadUm6DisabledCreationObservationAsync(
                stream, id, "admin", "001", receipt, CancellationToken.None);
            if (condition == "absent") Assert.Null(result);
            else
            {
                Assert.NotNull(result);
                Assert.Equal("*1", result.RemoteId);
                Assert.Equal(condition == "match", result.ReturnedIdMatched);
            }
        }
        else if (condition == "wrong-version")
            await Assert.ThrowsAsync<NotSupportedException>(() => RouterOsSession.ReadUm6DisabledCreationObservationAsync(
                stream, id, "admin", "001", receipt, CancellationToken.None));
        else
            await Assert.ThrowsAsync<InvalidDataException>(() => RouterOsSession.ReadUm6DisabledCreationObservationAsync(
                stream, id, "admin", "001", receipt, CancellationToken.None));
        using var sent = new MemoryStream(stream.ToArray());
        var version = await RouterOsWireCodec.ReadSentenceAsync(sent, CancellationToken.None);
        Assert.Equal("/system/resource/print", Encoding.UTF8.GetString(version[0]));
        if (condition != "wrong-version")
        {
            var query = await RouterOsWireCodec.ReadSentenceAsync(sent, CancellationToken.None);
            Assert.Equal(new[] { "/tool/user-manager/user/print",
                "=.proplist=.id,customer,username,disabled,comment", "?username=001" },
                query.Select(word => Encoding.UTF8.GetString(word)).ToArray());
        }
        Assert.Equal(sent.Length, sent.Position);
    }

    [Theory]
    [InlineData(false, null)]
    [InlineData(true, "*Z")]
    public async Task QualifiedDisabledCreationReadbackRejectsInvalidReceiptBeforeAnyCommand(bool acknowledged, string? remoteId)
    {
        using var stream = new QualificationExchange([], _ => { });
        var receipt = new UserManager6CreateWireReceipt(acknowledged
            ? UserManager6CreateWireOutcome.Acknowledged : UserManager6CreateWireOutcome.Indeterminate, remoteId);
        await Assert.ThrowsAsync<InvalidOperationException>(() => RouterOsSession.ReadUm6DisabledCreationObservationAsync(
            stream, Guid.NewGuid(), "admin", "001", receipt, CancellationToken.None));
        Assert.Equal(0L, stream.Length);
    }

    [Fact]
    public async Task QualifiedDisabledCreationReadbackDoesNotAcceptIncompleteReply()
    {
        Guid id = Guid.NewGuid();
        using var replies = new MemoryStream();
        await WriteReplyAsync(replies, "!re", "=version=6.49.19");
        await WriteReplyAsync(replies, "!done");
        await WriteReplyAsync(replies, "!re", "=.id=*1", "=customer=admin", "=username=001",
            "=disabled=yes", "=comment=hmk-create:" + id.ToString("N"));
        using var stream = new QualificationExchange(replies.ToArray(), _ => { });
        await Assert.ThrowsAsync<EndOfStreamException>(() => RouterOsSession.ReadUm6DisabledCreationObservationAsync(
            stream, id, "admin", "001", new(UserManager6CreateWireOutcome.Acknowledged, "*1"), CancellationToken.None));
    }

    private static ValueTask WriteReplyAsync(Stream stream, params string[] words) =>
        RouterOsWireCodec.WriteSentenceAsync(stream,
            words.Select(word => (ReadOnlyMemory<byte>)Encoding.UTF8.GetBytes(word)).ToArray(), CancellationToken.None);

    private sealed class QualificationExchange(byte[] replies, Action<string> onWord) : MemoryStream
    {
        private readonly MemoryStream input = new(replies);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            input.ReadAsync(buffer, cancellationToken);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Span.StartsWith("/"u8)) onWord(Encoding.UTF8.GetString(buffer.Span));
            return base.WriteAsync(buffer, cancellationToken);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) input.Dispose();
            base.Dispose(disposing);
        }
    }

    [Theory]
    [InlineData("match")]
    [InlineData("bare")]
    [InlineData("absent")]
    [InlineData("mismatch")]
    [InlineData("uncertain")]
    [SupportedOSPlatform("windows")]
    public async Task QualifiedCreationPersistsAcknowledgementBeforeOptionalReadback(string condition)
    {
        using var file = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        new UserManager6VoucherSecretStore(file.Path).Save(id, "synthetic"u8);
        var journal = new UserManager6CreateJournal(file.Path);
        using var replies = new MemoryStream();
        await WriteReplyAsync(replies, "!re", "=version=6.49.19");
        await WriteReplyAsync(replies, "!done");
        await WriteReplyAsync(replies, "!re", "=owner=admin", "=name=day");
        await WriteReplyAsync(replies, "!done");
        await WriteReplyAsync(replies, "!done");
        if (condition == "uncertain") await WriteReplyAsync(replies, "!trap", "=message=synthetic");
        else
        {
            if (condition == "bare") await WriteReplyAsync(replies, "!done");
            else await WriteReplyAsync(replies, "!done", "=ret=*1");
            await WriteReplyAsync(replies, "!re", "=version=6.49.19");
            await WriteReplyAsync(replies, "!done");
            if (condition != "absent")
                await WriteReplyAsync(replies, "!re", condition == "mismatch" ? "=.id=*2" : "=.id=*1",
                    "=customer=admin", "=username=001", "=disabled=yes", "=comment=hmk-create:" + id.ToString("N"));
            await WriteReplyAsync(replies, "!done");
        }
        int versionReads = 0, adds = 0;
        using var stream = new QualificationExchange(replies.ToArray(), word =>
        {
            if (word == "/tool/user-manager/user/add") adds++;
            if (word == "/system/resource/print" && ++versionReads == 2)
            {
                Assert.Equal(UserManager6CreateState.Acknowledged, journal.Read(id)!.State);
                Assert.NotNull(journal.ReadCreationEvidence(id));
                Assert.Null(journal.ReadCreationEvidence(id)!.ObservedId);
            }
        });
        if (condition == "mismatch")
            await Assert.ThrowsAsync<InvalidDataException>(() => UserManager6CreateCoordinator.ExecuteForQualificationAsync(
                file.Path, id, stream, observeAfterAcknowledgement: true));
        else
        {
            var result = await UserManager6CreateCoordinator.ExecuteForQualificationAsync(
                file.Path, id, stream, observeAfterAcknowledgement: true);
            Assert.Equal(condition == "uncertain" ? UserManager6CoordinationOutcome.Indeterminate :
                UserManager6CoordinationOutcome.Acknowledged, result);
        }
        Assert.Equal(1, adds);
        Assert.Equal(condition == "uncertain" ? 1 : 2, versionReads);
        var stored = new UserManager6CreateJournal(file.Path).ReadCreationEvidence(id);
        if (condition == "uncertain") Assert.Null(stored);
        else
        {
            Assert.NotNull(stored);
            Assert.Equal(condition == "bare" ? null : "*1", stored.ReturnedId);
            Assert.Equal(condition is "match" or "bare" ? "*1" : null, stored.ObservedId);
            Assert.Equal(UserManager6CreateState.Acknowledged, journal.Read(id)!.State);
        }
        Assert.False(journal.TryBeginBoundDispatch(id));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void CreationEvidenceIsImmutableAndRestoreCannotLoseIt()
    {
        using var file = new TestFile();
        using var before = new TestFile();
        using var after = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        new UserManager6VoucherSecretStore(file.Path).Save(id, "synthetic"u8);
        var journal = new UserManager6CreateJournal(file.Path);
        Assert.True(journal.TryBeginBoundDispatch(id));
        Assert.True(journal.TryRecordAcknowledgement(id, new(UserManager6CreateWireOutcome.Acknowledged, "*1")));
        Assert.False(journal.TryRecordAcknowledgement(id, new(UserManager6CreateWireOutcome.Acknowledged, "*2")));
        Assert.Throws<InvalidOperationException>(() => journal.RecordDisabledObservation(id, new("*2", true)));
        Assert.Throws<InvalidOperationException>(() => journal.RecordDisabledObservation(id, new("*1", false)));
        // Create consistent snapshots using SQLite's backup API rather than copying WAL files.
        using (var c = DatabaseStore.Open(file.Path))
        using (var destination = before.OpenRaw()) c.BackupDatabase(destination);
        journal.RecordDisabledObservation(id, new("*1", true));
        Assert.Throws<SqliteException>(() => journal.RecordDisabledObservation(id, new("*1", true)));
        using (var c = DatabaseStore.Open(file.Path))
        {
            Assert.Throws<SqliteException>(() => Execute(c, "UPDATE um6_create_evidence SET RemoteId='*2';"));
            Assert.Throws<SqliteException>(() => Execute(c, "DELETE FROM um6_create_evidence;"));
            Assert.Throws<SqliteException>(() => Execute(c, "INSERT OR REPLACE INTO um6_create_evidence SELECT * FROM um6_create_evidence;"));
            using var destination = after.OpenRaw();
            c.BackupDatabase(destination);
        }
        Assert.Throws<InvalidOperationException>(() => UserManager6CreateJournal.RequireEquivalentEvidenceForRestore(file.Path, before.Path));
        Assert.Throws<InvalidOperationException>(() => UserManager6CreateJournal.RequireEquivalentEvidenceForRestore(before.Path, file.Path));
        UserManager6CreateJournal.RequireEquivalentEvidenceForRestore(file.Path, after.Path);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void FailedEvidenceInsertRollsBackAcknowledgementAndLegacyAckIsNotBackfilled()
    {
        using var file = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        new UserManager6VoucherSecretStore(file.Path).Save(id, "synthetic"u8);
        var journal = new UserManager6CreateJournal(file.Path);
        Assert.True(journal.TryBeginBoundDispatch(id));
        using (var c = DatabaseStore.Open(file.Path))
            Execute(c, "CREATE TRIGGER synthetic_evidence_failure BEFORE INSERT ON um6_create_evidence BEGIN SELECT RAISE(ABORT,'synthetic'); END;");
        Assert.Throws<SqliteException>(() => journal.TryRecordAcknowledgement(id,
            new(UserManager6CreateWireOutcome.Acknowledged, "*1")));
        Assert.Equal(UserManager6CreateState.DispatchStarted, journal.Read(id)!.State);
        Assert.Null(journal.ReadCreationEvidence(id));
        // The previous state-only API is retained for existing synthetic legacy tests.
        Assert.True(journal.TryMarkAcknowledged(id));
        Assert.Null(journal.ReadCreationEvidence(id));
        Assert.Throws<InvalidOperationException>(() => journal.RecordDisabledObservation(id, new("*1", false)));
        Assert.False(journal.TryBeginBoundDispatch(id));
    }

    [Theory]
    [InlineData("started")]
    [InlineData("indeterminate")]
    [InlineData("legacy-ack")]
    [InlineData("ack")]
    [SupportedOSPlatform("windows")]
    public void RecoveryEvidenceRetainsOriginalStateAndNeverFabricatesReceipt(string state)
    {
        using var file = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        new UserManager6VoucherSecretStore(file.Path).Save(id, "synthetic"u8);
        var journal = new UserManager6CreateJournal(file.Path);
        Assert.True(journal.TryBeginBoundDispatch(id));
        if (state == "indeterminate") Assert.True(journal.TryMarkIndeterminate(id));
        if (state == "legacy-ack") Assert.True(journal.TryMarkAcknowledged(id));
        if (state == "ack") Assert.True(journal.TryRecordAcknowledgement(id, new(UserManager6CreateWireOutcome.Acknowledged, "*1")));
        var prior = journal.ReadBoundRecoveryScope(id);
        Assert.False(journal.TryRecordRecoveryObservation(new(prior, null)));
        Assert.True(journal.TryRecordRecoveryObservation(new(prior, new("*1", prior.ExpectedRemoteId is not null))));
        var stored = journal.ReadBoundRecoveryScope(id);
        Assert.NotNull(stored.Recovery);
        Assert.Equal(prior.State, stored.Recovery.StateAtObservation);
        Assert.Equal("*1", stored.ExpectedRemoteId);
        Assert.Equal(prior.Evidence, stored.Evidence);
        Assert.Equal(prior.State, journal.Read(id)!.State);
        Assert.False(journal.TryRecordRecoveryObservation(new(stored, null)));
        Assert.False(journal.TryRecordRecoveryObservation(new(stored, new("*1", true))));
        Assert.Throws<InvalidOperationException>(() => journal.TryRecordRecoveryObservation(new(stored, new("*2", true))));
        Assert.Throws<InvalidOperationException>(() => journal.TryRecordRecoveryObservation(new(prior, new("*1", prior.ExpectedRemoteId is not null))));
        Assert.False(journal.TryBeginBoundDispatch(id));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void RecoveryEvidenceRejectsLateConflictingAcknowledgementAndCannotBeRolledBack()
    {
        using var file = new TestFile();
        using var earlier = new TestFile();
        using var identical = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        new UserManager6VoucherSecretStore(file.Path).Save(id, "synthetic"u8);
        var journal = new UserManager6CreateJournal(file.Path);
        Assert.True(journal.TryBeginBoundDispatch(id));
        using (var c = DatabaseStore.Open(file.Path))
        using (var destination = earlier.OpenRaw()) c.BackupDatabase(destination);
        var scope = journal.ReadBoundRecoveryScope(id);
        Assert.True(journal.TryRecordRecoveryObservation(new(scope, new("*1", false))));
        Assert.Throws<SqliteException>(() => journal.TryRecordAcknowledgement(id,
            new(UserManager6CreateWireOutcome.Acknowledged, "*2")));
        Assert.Equal(UserManager6CreateState.DispatchStarted, journal.Read(id)!.State);
        Assert.Null(journal.ReadCreationEvidence(id));
        using (var c = DatabaseStore.Open(file.Path))
        {
            Assert.Throws<SqliteException>(() => Execute(c, "UPDATE um6_recovery_evidence SET RemoteId='*2';"));
            Assert.Throws<SqliteException>(() => Execute(c, "DELETE FROM um6_recovery_evidence;"));
            Assert.Throws<SqliteException>(() => Execute(c, "INSERT OR REPLACE INTO um6_recovery_evidence SELECT * FROM um6_recovery_evidence;"));
            using var destination = identical.OpenRaw();
            c.BackupDatabase(destination);
        }
        Assert.Throws<InvalidOperationException>(() => UserManager6CreateJournal.RequireEquivalentRecoveryForRestore(file.Path, earlier.Path));
        Assert.Throws<InvalidOperationException>(() => UserManager6CreateJournal.RequireEquivalentRecoveryForRestore(earlier.Path, file.Path));
        UserManager6CreateJournal.RequireEquivalentRecoveryForRestore(file.Path, identical.Path);
        Assert.True(journal.TryRecordAcknowledgement(id, new(UserManager6CreateWireOutcome.Acknowledged, "*1")));
        Assert.Equal(UserManager6CreateState.DispatchStarted, journal.ReadBoundRecoveryScope(id).Recovery!.StateAtObservation);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void RecoveryEvidenceRejectsScopeDriftBeforePersistence()
    {
        using var file = new TestFile();
        Guid id = SeedSecretIntent(file.Path);
        new UserManager6VoucherSecretStore(file.Path).Save(id, "synthetic"u8);
        var journal = new UserManager6CreateJournal(file.Path);
        Assert.True(journal.TryBeginBoundDispatch(id));
        var scope = journal.ReadBoundRecoveryScope(id);
        Assert.True(journal.TryMarkIndeterminate(id));
        Assert.Throws<InvalidOperationException>(() => journal.TryRecordRecoveryObservation(new(scope, new("*1", false))));
        Assert.Null(journal.ReadBoundRecoveryScope(id).Recovery);
    }

    private static Guid SeedSecretIntent(string path)
    {
        Guid id = SeedReservation(path, BackendKind.UserManager6);
        var journal = new UserManager6CreateJournal(path);
        var entry = journal.Prepare(id, "admin");
        EnrollIntentTarget(path, entry.RouterId);
        journal.PrepareBoundIntent(id, "admin", "day");
        return id;
    }

    private static void EnrollIntentTarget(string path, Guid routerId)
    {
        using var ca = CreateEnrollmentCa();
        new RouterTargetStore(path).Enroll(routerId, "router.test", 8729, "router.test",
            new string('A',64), ca.RawData);
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
        if (version is < 1 or > 9) throw new ArgumentOutOfRangeException(nameof(version));
        Assert.Equal(10, DatabaseStore.CurrentSchemaVersion);
        Assert.Equal(10L, Scalar(c, "PRAGMA user_version;"));
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "DROP TRIGGER um6_recovery_consistency_guard; DROP TABLE um6_recovery_evidence;";
        if (version < 9) cmd.CommandText += " DROP TABLE um6_create_evidence;";
        if (version < 8) cmd.CommandText += " DROP TABLE um6_voucher_secrets;";
        if (version < 7) cmd.CommandText += " DROP TABLE um6_create_intents;";
        if (version < 6) cmd.CommandText += " DROP TABLE router_targets;";
        if (version < 5) cmd.CommandText += " DROP TABLE um6_create_journal;";
        if (version < 4) cmd.CommandText += " DROP TABLE audit_events;";
        if (version < 3) cmd.CommandText += " DROP TABLE router_credentials;";
        if (version < 2) cmd.CommandText +=
            " DROP INDEX IX_voucher_batches_BackendId_PlanId; DROP INDEX IX_voucher_reservations_BackendId_BatchId;";
        cmd.CommandText += " PRAGMA user_version=" + version.ToString(System.Globalization.CultureInfo.InvariantCulture) + ";";
        cmd.ExecuteNonQuery();
        tx.Commit();

        cmd.Transaction = null;
        cmd.CommandText = "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%';";
        Assert.Equal(version == 9 ? 13L : version == 8 ? 12L : version == 7 ? 11L : version == 6 ? 10L : version == 5 ? 9L : version == 4 ? 8L : version == 3 ? 7L : 6L, (long)cmd.ExecuteScalar()!);
        Assert.Equal((long)version, Scalar(c, "PRAGMA user_version;"));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
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
