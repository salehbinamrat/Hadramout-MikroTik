using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Hadramout.Infrastructure;

/// <summary>Opens an owned local database with durable settings and atomic schema upgrades.</summary>
public static class DatabaseStore
{
    public const int CurrentSchemaVersion = 4;
    public const int ApplicationId = 0x484D4B54;

    public static SqliteConnection Open(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
            throw new ArgumentException("An absolute database path is required.", nameof(path));

        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            ForeignKeys = true,
            Pooling = false,
            DefaultTimeout = 10
        }.ToString());
        try
        {
            connection.Open();
            Execute(connection, null, "PRAGMA synchronous=FULL;");
            Upgrade(connection);

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

    private static void Upgrade(SqliteConnection connection)
    {
        // An immediate write transaction serializes schema initialization across processes.
        using var tx = connection.BeginTransaction(deferred: false);
        var version = ReadInt(connection, tx, "PRAGMA user_version;");
        var applicationId = ReadInt(connection, tx, "PRAGMA application_id;");

        if (version == 0)
        {
            if (applicationId != 0 || ReadInt(connection, tx,
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
}
