using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

/// <summary>Opens an owned local database with durable settings and atomic schema upgrades.</summary>
public static class DatabaseStore
{
    public const int CurrentSchemaVersion = 9;
    public const int ApplicationId = 0x484D4B54;

    public static SqliteConnection Open(string path) => OpenCore(path, SqliteOpenMode.ReadWriteCreate);

    internal static SqliteConnection OpenExisting(string path) => OpenCore(path, SqliteOpenMode.ReadWrite);

    private static SqliteConnection OpenCore(string path, SqliteOpenMode mode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
            throw new ArgumentException("An absolute database path is required.", nameof(path));

        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = mode,
            ForeignKeys = true,
            Pooling = false,
            DefaultTimeout = 10
        }.ToString());
        try
        {
            connection.Open();
            Execute(connection, null, "PRAGMA synchronous=FULL;");
            Execute(connection, null, "PRAGMA recursive_triggers=ON;");
            Upgrade(connection, allowInitialize: mode == SqliteOpenMode.ReadWriteCreate);

            // Journal mode is persistent; changing it is not permitted inside a transaction.
            using var journal = connection.CreateCommand();
            journal.CommandText = "PRAGMA journal_mode=WAL;";
            if (!string.Equals(journal.ExecuteScalar() as string, "wal", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The database does not support WAL.");
            Execute(connection, null, "PRAGMA synchronous=FULL;");
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private static void Upgrade(SqliteConnection connection, bool allowInitialize)
    {
        // An immediate write transaction serializes schema initialization across processes.
        using var tx = connection.BeginTransaction(deferred: false);
        var version = ReadInt(connection, tx, "PRAGMA user_version;");
        var applicationId = ReadInt(connection, tx, "PRAGMA application_id;");

        if (version == 0)
        {
            if (!allowInitialize || applicationId != 0 || ReadInt(connection, tx,
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%';") != 0)
                throw new InvalidOperationException("An unrecognized unversioned database must not be overwritten.");

            Execute(connection, tx, SchemaV1);
            Execute(connection, tx, "PRAGMA application_id=0x484D4B54; PRAGMA user_version=1;");
            version = 1;
        }
        else if (applicationId != ApplicationId)
        {
            throw new InvalidOperationException("Database application identity does not match.");
        }

        if (version < 1 || version > CurrentSchemaVersion)
            throw new InvalidOperationException("Unsupported database schema version.");

        if (version == 1)
        {
            Execute(connection, tx, SchemaV2);
            Execute(connection, tx, "PRAGMA user_version=2;");
            version = 2;
        }

        if (version == 2)
        {
            Execute(connection, tx, SchemaV3);
            Execute(connection, tx, "PRAGMA user_version=3;");
            version = 3;
        }

        if (version == 3)
        {
            Execute(connection, tx, SchemaV4);
            Execute(connection, tx, "PRAGMA user_version=4;");
            version = 4;
        }

        if (version == 4)
        {
            Execute(connection, tx, SchemaV5);
            Execute(connection, tx, "PRAGMA user_version=5;");
            version = 5;
        }

        if (version == 5)
        {
            Execute(connection, tx, SchemaV6);
            Execute(connection, tx, "PRAGMA user_version=6;");
            version = 6;
        }

        if (version == 6)
        {
            Execute(connection, tx, SchemaV7);
            Execute(connection, tx, "PRAGMA user_version=7;");
            version = 7;
        }

        if (version == 7)
        {
            Execute(connection, tx, SchemaV8);
            Execute(connection, tx, "PRAGMA user_version=8;");
            version = 8;
        }

        if (version == 8)
        {
            Execute(connection, tx, SchemaV9);
            Execute(connection, tx, "PRAGMA user_version=9;");
            version = 9;
        }

        if (version != CurrentSchemaVersion)
            throw new InvalidOperationException("Incomplete database migration.");
        tx.Commit();
    }

    private static int ReadInt(SqliteConnection connection, SqliteTransaction tx, string sql)
    {
        using var command = connection.CreateCommand();
        command.Transaction = tx;
        command.CommandText = sql;
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static void Execute(SqliteConnection connection, SqliteTransaction? tx, string sql)
    {
        using var command = connection.CreateCommand();
        command.Transaction = tx;
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    // Frozen migration, not regenerated from the current EF model.
    private const string SchemaV1 = """
        CREATE TABLE sites (
            Id TEXT NOT NULL PRIMARY KEY,
            Name TEXT COLLATE BINARY NOT NULL,
            CONSTRAINT ck_site_name CHECK (length(trim(Name)) BETWEEN 1 AND 128)
        );
        CREATE UNIQUE INDEX IX_sites_Name ON sites(Name);
        CREATE TABLE routers (
            Id TEXT NOT NULL PRIMARY KEY,
            SiteId TEXT NOT NULL REFERENCES sites(Id) ON DELETE RESTRICT,
            Name TEXT COLLATE BINARY NOT NULL,
            CONSTRAINT ck_router_name CHECK (length(trim(Name)) BETWEEN 1 AND 128)
        );
        CREATE UNIQUE INDEX IX_routers_SiteId_Name ON routers(SiteId, Name);
        CREATE TABLE backends (
            Id TEXT NOT NULL PRIMARY KEY,
            RouterId TEXT NOT NULL REFERENCES routers(Id) ON DELETE RESTRICT,
            Kind INTEGER NOT NULL,
            CONSTRAINT ck_backend_kind CHECK (Kind IN (1,2,3,4))
        );
        CREATE UNIQUE INDEX IX_backends_RouterId_Kind ON backends(RouterId, Kind);
        CREATE TABLE plans (
            Id TEXT NOT NULL PRIMARY KEY,
            BackendId TEXT NOT NULL REFERENCES backends(Id) ON DELETE RESTRICT,
            Name TEXT COLLATE BINARY NOT NULL,
            UNIQUE (BackendId, Id),
            CONSTRAINT ck_plan_name CHECK (length(trim(Name)) BETWEEN 1 AND 128)
        );
        CREATE UNIQUE INDEX IX_plans_BackendId_Name ON plans(BackendId, Name);
        CREATE TABLE voucher_batches (
            Id TEXT NOT NULL PRIMARY KEY,
            BackendId TEXT NOT NULL,
            PlanId TEXT NOT NULL,
            UNIQUE (BackendId, Id),
            FOREIGN KEY (BackendId, PlanId) REFERENCES plans(BackendId, Id) ON DELETE RESTRICT
        );
        CREATE TABLE voucher_reservations (
            Id TEXT NOT NULL PRIMARY KEY,
            BackendId TEXT NOT NULL,
            BatchId TEXT NOT NULL,
            Username TEXT COLLATE BINARY NOT NULL,
            FOREIGN KEY (BackendId, BatchId) REFERENCES voucher_batches(BackendId, Id) ON DELETE RESTRICT,
            CONSTRAINT ck_voucher_username CHECK (length(Username) BETWEEN 1 AND 128 AND Username = trim(Username))
        );
        CREATE UNIQUE INDEX IX_voucher_reservations_BackendId_Username ON voucher_reservations(BackendId, Username);
        """;

    // Index-only migration: accelerate FK checks and lookup of batches and reservations.
    private const string SchemaV2 = """
        CREATE INDEX IX_voucher_batches_BackendId_PlanId ON voucher_batches(BackendId, PlanId);
        CREATE INDEX IX_voucher_reservations_BackendId_BatchId ON voucher_reservations(BackendId, BatchId);
        """;

    // Only encrypted envelopes are stored. No plaintext credential column.
    private const string SchemaV3 = """
        CREATE TABLE router_credentials (
            RouterId TEXT NOT NULL PRIMARY KEY REFERENCES routers(Id) ON DELETE RESTRICT,
            UsernameEnvelope BLOB NOT NULL CHECK (typeof(UsernameEnvelope)='blob' AND length(UsernameEnvelope)>0),
            PasswordEnvelope BLOB NOT NULL CHECK (typeof(PasswordEnvelope)='blob' AND length(PasswordEnvelope)>0)
        );
        """;

    private const string SchemaV4 = """
        CREATE TABLE audit_events (
            Id TEXT NOT NULL PRIMARY KEY,
            OccurredUtc TEXT NOT NULL,
            Kind INTEGER NOT NULL CHECK (Kind IN (1,2,3,4)),
            SubjectId TEXT,
            CHECK ((Kind IN (1,2) AND SubjectId IS NOT NULL)
                OR (Kind IN (3,4) AND SubjectId IS NULL))
        );
        CREATE INDEX IX_audit_events_OccurredUtc ON audit_events(OccurredUtc, Id);
        CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'Audit events are append-only'); END;
        CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'Audit events are append-only'); END;
        """;

    // Durable one-shot dispatch claims. Acknowledged is NOT confirmed/printable.
    private const string SchemaV5 = """
        CREATE TABLE um6_create_journal (
            ReservationId TEXT NOT NULL PRIMARY KEY REFERENCES voucher_reservations(Id) ON DELETE RESTRICT,
            BackendId TEXT NOT NULL REFERENCES backends(Id) ON DELETE RESTRICT,
            RouterId TEXT NOT NULL REFERENCES routers(Id) ON DELETE RESTRICT,
            Customer TEXT COLLATE BINARY NOT NULL CHECK (length(Customer) BETWEEN 1 AND 128 AND Customer=trim(Customer)),
            Username TEXT COLLATE BINARY NOT NULL CHECK (length(Username) BETWEEN 1 AND 128 AND Username=trim(Username)),
            State INTEGER NOT NULL CHECK (State IN (1,2,3,4)),
            UNIQUE(RouterId, Customer, Username)
        );
        CREATE TRIGGER um6_create_insert_guard BEFORE INSERT ON um6_create_journal
        WHEN NEW.State != 1 OR NOT EXISTS (
            SELECT 1 FROM voucher_reservations v JOIN backends b ON b.Id=v.BackendId
            WHERE v.Id=NEW.ReservationId AND v.BackendId=NEW.BackendId
              AND b.RouterId=NEW.RouterId AND b.Kind=2 AND v.Username=NEW.Username)
        BEGIN SELECT RAISE(ABORT,'Invalid UM6 creation reservation'); END;
        CREATE TRIGGER um6_create_update_guard BEFORE UPDATE ON um6_create_journal
        WHEN NEW.ReservationId IS NOT OLD.ReservationId OR NEW.BackendId IS NOT OLD.BackendId
          OR NEW.RouterId IS NOT OLD.RouterId OR NEW.Customer IS NOT OLD.Customer
          OR NEW.Username IS NOT OLD.Username OR NOT (
            (OLD.State=1 AND NEW.State=2) OR (OLD.State=2 AND NEW.State IN (3,4)))
        BEGIN SELECT RAISE(ABORT,'Invalid UM6 creation transition'); END;
        CREATE TRIGGER um6_create_no_delete BEFORE DELETE ON um6_create_journal
        BEGIN SELECT RAISE(ABORT,'UM6 creation evidence is retained'); END;
        """;

    // Explicit locally provisioned trust configuration. No automatic enrollment or rotation.
    private const string SchemaV6 = """
        CREATE TABLE router_targets (
            RouterId TEXT NOT NULL PRIMARY KEY REFERENCES routers(Id) ON DELETE RESTRICT,
            Host TEXT COLLATE BINARY NOT NULL CHECK (length(Host) BETWEEN 1 AND 253),
            Port INTEGER NOT NULL CHECK (Port BETWEEN 1 AND 65535),
            CertificateName TEXT COLLATE BINARY NOT NULL CHECK (length(CertificateName) BETWEEN 1 AND 253),
            LeafSha256 TEXT COLLATE BINARY NOT NULL UNIQUE CHECK (length(LeafSha256)=64 AND LeafSha256 NOT GLOB '*[^0-9A-F]*'),
            TrustedRootDer BLOB NOT NULL CHECK (typeof(TrustedRootDer)='blob' AND length(TrustedRootDer) BETWEEN 1 AND 65536),
            UNIQUE(Host,Port)
        );
        CREATE TRIGGER router_target_no_update BEFORE UPDATE ON router_targets
        BEGIN SELECT RAISE(ABORT,'Explicit target rotation is not implemented'); END;
        CREATE TRIGGER router_target_no_delete BEFORE DELETE ON router_targets
        BEGIN SELECT RAISE(ABORT,'Router target evidence is retained'); END;
        """;

    // Durable explicit profile and target intent. Not proof of remote assignment.
    private const string SchemaV7 = """
        CREATE TABLE um6_create_intents (
            ReservationId TEXT NOT NULL PRIMARY KEY REFERENCES um6_create_journal(ReservationId) ON DELETE RESTRICT,
            BatchId TEXT NOT NULL REFERENCES voucher_batches(Id) ON DELETE RESTRICT,
            PlanId TEXT NOT NULL REFERENCES plans(Id) ON DELETE RESTRICT,
            PlanName TEXT COLLATE BINARY NOT NULL CHECK(length(PlanName) BETWEEN 1 AND 128),
            LeafSha256 TEXT COLLATE BINARY NOT NULL CHECK(length(LeafSha256)=64 AND LeafSha256 NOT GLOB '*[^0-9A-F]*'),
            ProfileOwner TEXT COLLATE BINARY NOT NULL CHECK(length(ProfileOwner) BETWEEN 1 AND 128 AND ProfileOwner=trim(ProfileOwner)),
            ProfileName TEXT COLLATE BINARY NOT NULL CHECK(length(ProfileName) BETWEEN 1 AND 128 AND ProfileName=trim(ProfileName))
        );
        CREATE TRIGGER um6_intent_insert_guard BEFORE INSERT ON um6_create_intents
        WHEN NOT EXISTS (
            SELECT 1 FROM um6_create_journal j
            JOIN voucher_reservations v ON v.Id=j.ReservationId AND v.BackendId=j.BackendId AND v.Username=j.Username
            JOIN backends b ON b.Id=j.BackendId AND b.RouterId=j.RouterId AND b.Kind=2
            JOIN voucher_batches batch ON batch.Id=v.BatchId AND batch.BackendId=j.BackendId
            JOIN plans p ON p.Id=batch.PlanId AND p.BackendId=j.BackendId
            JOIN router_targets t ON t.RouterId=j.RouterId
            WHERE j.ReservationId=NEW.ReservationId AND j.State=1
              AND batch.Id=NEW.BatchId AND p.Id=NEW.PlanId AND p.Name=NEW.PlanName
              AND t.LeafSha256=NEW.LeafSha256)
        BEGIN SELECT RAISE(ABORT,'Invalid bound creation intent'); END;
        CREATE TRIGGER um6_intent_no_update BEFORE UPDATE ON um6_create_intents
        BEGIN SELECT RAISE(ABORT,'Creation intent is immutable'); END;
        CREATE TRIGGER um6_intent_no_delete BEFORE DELETE ON um6_create_intents
        BEGIN SELECT RAISE(ABORT,'Creation intent is retained'); END;
        """;

    // Explicit encrypted password (including intentionally empty password).
    private const string SchemaV8 = """
        CREATE TABLE um6_voucher_secrets (
            ReservationId TEXT NOT NULL PRIMARY KEY REFERENCES um6_create_intents(ReservationId) ON DELETE RESTRICT,
            PasswordEnvelope BLOB NOT NULL CHECK(typeof(PasswordEnvelope)='blob' AND length(PasswordEnvelope) BETWEEN 1 AND 20513)
        );
        CREATE TRIGGER um6_secret_insert_guard BEFORE INSERT ON um6_voucher_secrets
        WHEN NOT EXISTS (
            SELECT 1 FROM um6_create_intents i JOIN um6_create_journal j ON j.ReservationId=i.ReservationId
            WHERE i.ReservationId=NEW.ReservationId AND j.State=1)
        BEGIN SELECT RAISE(ABORT,'Prepared creation intent required'); END;
        CREATE TRIGGER um6_secret_no_update BEFORE UPDATE ON um6_voucher_secrets
        BEGIN SELECT RAISE(ABORT,'Voucher secret is immutable'); END;
        CREATE TRIGGER um6_secret_no_delete BEFORE DELETE ON um6_voucher_secrets
        BEGIN SELECT RAISE(ABORT,'Voucher secret evidence is retained'); END;
        """;

    // Separate immutable acknowledgement and matching disabled readback evidence.
    // Neither changes the journal's non-rearmable acknowledgement state.
    private const string SchemaV9 = """
        CREATE TABLE um6_create_evidence (
            ReservationId TEXT NOT NULL REFERENCES um6_create_intents(ReservationId) ON DELETE RESTRICT,
            Kind INTEGER NOT NULL CHECK(Kind IN (1,2)),
            RemoteId TEXT COLLATE BINARY CHECK(RemoteId IS NULL OR (
                typeof(RemoteId)='text' AND length(RemoteId) BETWEEN 2 AND 33 AND
                substr(RemoteId,1,1)='*' AND substr(RemoteId,2) NOT GLOB '*[^0-9a-fA-F]*')),
            CHECK(Kind=1 OR RemoteId IS NOT NULL),
            PRIMARY KEY(ReservationId,Kind)
        );
        CREATE TRIGGER um6_evidence_insert_guard BEFORE INSERT ON um6_create_evidence
        WHEN NOT EXISTS (
            SELECT 1 FROM um6_create_journal j
            JOIN um6_create_intents i ON i.ReservationId=j.ReservationId
            JOIN voucher_reservations v ON v.Id=j.ReservationId AND v.BackendId=j.BackendId AND v.Username=j.Username
            JOIN backends b ON b.Id=j.BackendId AND b.RouterId=j.RouterId AND b.Kind=2
            JOIN voucher_batches batch ON batch.Id=v.BatchId AND batch.Id=i.BatchId AND batch.BackendId=j.BackendId
            JOIN plans p ON p.Id=batch.PlanId AND p.Id=i.PlanId AND p.BackendId=j.BackendId AND p.Name=i.PlanName
            JOIN router_targets t ON t.RouterId=j.RouterId AND t.LeafSha256=i.LeafSha256
            JOIN um6_voucher_secrets secret ON secret.ReservationId=j.ReservationId
            WHERE j.ReservationId=NEW.ReservationId AND j.State=4)
        OR (NEW.Kind=2 AND NOT EXISTS (
            SELECT 1 FROM um6_create_evidence ack WHERE ack.ReservationId=NEW.ReservationId
              AND ack.Kind=1 AND (ack.RemoteId IS NULL OR ack.RemoteId=NEW.RemoteId)))
        BEGIN SELECT RAISE(ABORT,'Invalid UM6 creation evidence'); END;
        CREATE TRIGGER um6_evidence_no_update BEFORE UPDATE ON um6_create_evidence
        BEGIN SELECT RAISE(ABORT,'Creation evidence is immutable'); END;
        CREATE TRIGGER um6_evidence_no_delete BEFORE DELETE ON um6_create_evidence
        BEGIN SELECT RAISE(ABORT,'Creation evidence is retained'); END;
        """;
}
