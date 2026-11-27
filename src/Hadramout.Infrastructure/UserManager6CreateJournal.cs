using Microsoft.Data.Sqlite;
using System.Runtime.Versioning;

namespace Hadramout.Infrastructure;

internal enum UserManager6CreateState { Prepared = 1, DispatchStarted = 2, Indeterminate = 3, Acknowledged = 4 }

internal sealed record UserManager6CreateEntry(Guid ReservationId, Guid BackendId, Guid RouterId,
    string Customer, string Username, UserManager6CreateState State);

internal sealed record UserManager6CreateIntent(Guid ReservationId, Guid BatchId, Guid PlanId,
    string PlanName, string LeafSha256, string ProfileOwner, string ProfileName);

internal sealed record UserManager6PreflightScope(Guid ReservationId, Guid RouterId,
    string LeafSha256, string ProfileOwner, string ProfileName, string Username, string Customer);

// Null record means no durable acknowledgement; null ID is a bare acknowledgement.
internal sealed record UserManager6StoredCreationEvidence(string? ReturnedId, string? ObservedId);

// Snapshot of the immutable intent and current retained evidence. No secret lease.
internal sealed record UserManager6RecoveryScope(Guid ReservationId, Guid RouterId,
    string LeafSha256, string Customer, string Username, UserManager6CreateState State,
    UserManager6StoredCreationEvidence? Evidence, UserManager6StoredRecoveryEvidence? Recovery = null)
{
    internal string? ExpectedRemoteId => Recovery?.RemoteId ?? Evidence?.ObservedId ?? Evidence?.ReturnedId;
}

internal sealed record UserManager6StoredRecoveryEvidence(UserManager6CreateState StateAtObservation, string RemoteId);

internal sealed record UserManager6RecoveryObservation(UserManager6RecoveryScope Scope,
    UserManager6DisabledCreationObservation? VisibleDisabledAccount);

internal sealed record UserManager6ProfileLinkScope(UserManager6RecoveryScope Creation,
    string ProfileOwner, string ProfileName);

internal enum UserManager6ProfileLinkReadState { AccountNotVisible, ProfileNotVisible, BothVisible, AccountProfileUnknown, AccountProfileAlreadyVisible }

internal sealed record UserManager6ProfileLinkReadEvidence(UserManager6ProfileLinkReadState State,
    UserManager6DisabledCreationObservation? Account, UserManager6Profile? Profile, string? ActualProfile = null);

internal enum UserManager6ProfileLinkState { DispatchStarted = 2, Indeterminate = 3, Acknowledged = 4 }
internal sealed record UserManager6ProfileLinkEntry(Guid ReservationId, string RemoteId, UserManager6ProfileLinkState State);

internal sealed record UserManager6ProfileLinkReviewScope(UserManager6ProfileLinkScope Intent,
    UserManager6ProfileLinkEntry Entry);
internal enum UserManager6ProfileLinkReviewState
{
    AccountNotVisible, ActualProfileUnknown, EmptyProfileReported, OtherProfileReported,
    IntendedNameProfileNotVisible, IntendedNameAndOwnerVisible
}
internal sealed record UserManager6ProfileLinkReviewEvidence(UserManager6ProfileLinkReviewScope Scope,
    UserManager6ProfileLinkReviewState State, UserManager6DisabledCreationObservation? Account,
    string? ActualProfile, UserManager6Profile? Profile);

internal sealed record UserManager6CreationReviewRow(UserManager6CreateEntry Entry, bool LocalIdentityMatches);
internal sealed record UserManager6CreationReviewPage(IReadOnlyList<UserManager6CreationReviewRow> Rows,
    Guid? NextAfterReservationId);
internal sealed record UserManager6CreationCounts(long Prepared, long DispatchStarted, long Indeterminate,
    long Acknowledged)
{
    // Acknowledged operations also require verification; none are printable.
    internal long RequiresReview => checked(DispatchStarted + Indeterminate + Acknowledged);
}

// Local foundation only. No network I/O, passwords, or automatic resend.
// A claim is committed before any future caller may attempt remote dispatch.
internal sealed class UserManager6CreateJournal(string databasePath)
{
    internal UserManager6CreateEntry Prepare(Guid reservationId, string customer)
    {
        ValidateId(reservationId);
        UserManager6Records.ValidateKey(customer, nameof(customer));
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            SELECT v.BackendId,b.RouterId,v.Username FROM voucher_reservations v
            JOIN backends b ON b.Id=v.BackendId WHERE v.Id=$id AND b.Kind=2;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        Guid backend, router;
        string username;
        using (var reader = cmd.ExecuteReader())
        {
            if (!reader.Read()) throw new InvalidOperationException("A local UM6 reservation is required.");
            backend = reader.GetGuid(0);
            router = reader.GetGuid(1);
            username = reader.GetString(2);
        }
        UserManager6Records.ValidateKey(username, nameof(username));
        cmd.CommandText = """
            INSERT INTO um6_create_journal(ReservationId,BackendId,RouterId,Customer,Username,State)
            VALUES($id,$backend,$router,$customer,$username,1);
            """;
        cmd.Parameters.AddWithValue("$backend", backend);
        cmd.Parameters.AddWithValue("$router", router);
        cmd.Parameters.AddWithValue("$customer", customer);
        cmd.Parameters.AddWithValue("$username", username);
        cmd.ExecuteNonQuery();
        tx.Commit();
        return new(reservationId, backend, router, customer, username, UserManager6CreateState.Prepared);
    }

    internal UserManager6CreateEntry? Read(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = OpenReadOnly();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT BackendId,RouterId,Customer,Username,State FROM um6_create_journal WHERE ReservationId=$id;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? new(reservationId, reader.GetGuid(0), reader.GetGuid(1),
            reader.GetString(2), reader.GetString(3), (UserManager6CreateState)reader.GetInt32(4)) : null;
    }

    // Read-only local evidence. A claimed operation stays uncertain after a crash.
    // No network requests or inferred remote state; caller must not use this as dispatch authorization.
    internal UserManager6CreationReviewPage ReadReviewPage(Guid routerId,
        Guid? afterReservationId = null, int pageSize = 100)
    {
        ValidateId(routerId);
        if (afterReservationId.HasValue) ValidateId(afterReservationId.Value);
        if (pageSize is < 1 or > 500) throw new ArgumentOutOfRangeException(nameof(pageSize));
        using var c = OpenReadOnly();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT j.ReservationId,j.BackendId,j.RouterId,j.Customer,j.Username,j.State,
                   CASE WHEN v.Id IS NOT NULL AND v.BackendId=j.BackendId AND v.Username=j.Username
                        AND b.Kind=2 AND b.RouterId=j.RouterId
                        AND batch.BackendId=j.BackendId AND p.BackendId=j.BackendId
                        AND r.Id IS NOT NULL AND s.Id IS NOT NULL THEN 1 ELSE 0 END
            FROM um6_create_journal j
            LEFT JOIN voucher_reservations v ON v.Id=j.ReservationId
            LEFT JOIN backends b ON b.Id=j.BackendId
            LEFT JOIN voucher_batches batch ON batch.Id=v.BatchId
            LEFT JOIN plans p ON p.Id=batch.PlanId
            LEFT JOIN routers r ON r.Id=j.RouterId
            LEFT JOIN sites s ON s.Id=r.SiteId
            WHERE j.RouterId=$router AND j.State IN (2,3,4)
              AND ($after IS NULL OR j.ReservationId COLLATE BINARY > $after)
            ORDER BY j.ReservationId COLLATE BINARY LIMIT $limit;
            """;
        cmd.Parameters.AddWithValue("$router", routerId);
        cmd.Parameters.AddWithValue("$after", (object?)afterReservationId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$limit", pageSize + 1);
        using var reader = cmd.ExecuteReader();
        var rows = new List<UserManager6CreationReviewRow>(pageSize);
        bool hasMore = false;
        while (reader.Read())
        {
            if (rows.Count == pageSize) { hasMore = true; break; }
            var entry = new UserManager6CreateEntry(reader.GetGuid(0), reader.GetGuid(1), reader.GetGuid(2),
                reader.GetString(3), reader.GetString(4), (UserManager6CreateState)reader.GetInt32(5));
            rows.Add(new(entry, reader.GetInt32(6) == 1));
        }
        return new(rows.AsReadOnly(), hasMore ? rows[^1].Entry.ReservationId : null);
    }

    internal UserManager6CreationCounts ReadCounts(Guid routerId)
    {
        ValidateId(routerId);
        using var c = OpenReadOnly();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT count(CASE WHEN State=1 THEN 1 END),count(CASE WHEN State=2 THEN 1 END),
                   count(CASE WHEN State=3 THEN 1 END),count(CASE WHEN State=4 THEN 1 END)
            FROM um6_create_journal WHERE RouterId=$router;
            """;
        cmd.Parameters.AddWithValue("$router", routerId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) throw new InvalidDataException("Missing creation counts.");
        return new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3));
    }

    private SqliteConnection OpenReadOnly()
    {
        if (!Path.IsPathFullyQualified(databasePath))
            throw new ArgumentException("An absolute database path is required.", nameof(databasePath));
        var connection = DatabaseBackup.OpenRaw(databasePath, SqliteOpenMode.ReadOnly);
        try
        {
            DatabaseBackup.RequireIdentity(connection);
            return connection;
        }
        catch { connection.Dispose(); throw; }
    }

    // Attach an explicitly selected remote profile to a still-prepared local journal row.
    // No remote proof or password is stored, and no command is sent.
    internal void PrepareBoundIntent(Guid reservationId, string profileOwner, string profileName)
    {
        ValidateId(reservationId);
        UserManager6Records.ValidateKey(profileOwner, nameof(profileOwner));
        UserManager6Records.ValidateKey(profileName, nameof(profileName));
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO um6_create_intents(ReservationId,BatchId,PlanId,PlanName,LeafSha256,ProfileOwner,ProfileName)
            SELECT j.ReservationId,batch.Id,p.Id,p.Name,t.LeafSha256,$owner,$profile
            FROM um6_create_journal j
            JOIN voucher_reservations v ON v.Id=j.ReservationId AND v.BackendId=j.BackendId AND v.Username=j.Username
            JOIN backends b ON b.Id=j.BackendId AND b.RouterId=j.RouterId AND b.Kind=2
            JOIN voucher_batches batch ON batch.Id=v.BatchId AND batch.BackendId=j.BackendId
            JOIN plans p ON p.Id=batch.PlanId AND p.BackendId=j.BackendId
            JOIN router_targets t ON t.RouterId=j.RouterId
            WHERE j.ReservationId=$id AND j.State=1;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        cmd.Parameters.AddWithValue("$owner", profileOwner);
        cmd.Parameters.AddWithValue("$profile", profileName);
        if (cmd.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("A prepared journal and enrolled matching target are required.");
        tx.Commit();
    }

    internal UserManager6CreateIntent? ReadBoundIntent(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = OpenReadOnly();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT BatchId,PlanId,PlanName,LeafSha256,ProfileOwner,ProfileName
            FROM um6_create_intents WHERE ReservationId=$id;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? new(reservationId, reader.GetGuid(0), reader.GetGuid(1),
            reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5)) : null;
    }

    // Consistent local read snapshot; no dispatch claim or mutation.
    [SupportedOSPlatform("windows")]
    internal UserManager6PreflightScope ReadPreparedPreflightScope(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = OpenReadOnly();
        using var tx = c.BeginTransaction(deferred: true);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            SELECT j.RouterId,i.LeafSha256,i.ProfileOwner,i.ProfileName,j.Username,j.Customer
            FROM um6_create_journal j
            JOIN um6_create_intents i ON i.ReservationId=j.ReservationId
            JOIN voucher_reservations v ON v.Id=j.ReservationId AND v.BackendId=j.BackendId AND v.Username=j.Username
            JOIN backends b ON b.Id=j.BackendId AND b.RouterId=j.RouterId AND b.Kind=2
            JOIN voucher_batches batch ON batch.Id=v.BatchId AND batch.Id=i.BatchId AND batch.BackendId=j.BackendId
            JOIN plans p ON p.Id=batch.PlanId AND p.Id=i.PlanId AND p.BackendId=j.BackendId AND p.Name=i.PlanName
            JOIN router_targets t ON t.RouterId=j.RouterId AND t.LeafSha256=i.LeafSha256
            WHERE j.ReservationId=$id AND j.State=1;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        UserManager6PreflightScope scope;
        using (var reader = cmd.ExecuteReader())
        {
            if (!reader.Read()) throw new InvalidOperationException("A matching prepared creation intent is required.");
            scope = new(reservationId, reader.GetGuid(0), reader.GetString(1), reader.GetString(2),
                reader.GetString(3), reader.GetString(4), reader.GetString(5));
        }
        using var secret = UserManager6VoucherSecretStore.Load(c, tx, reservationId)
            ?? throw new InvalidOperationException("Voucher password has not been configured.");
        tx.Commit();
        return scope;
    }

    // Read a consistent local scope for a non-rearmable bound operation.
    // Legacy unbound entries and drifted relationships are not eligible for network review.
    internal UserManager6RecoveryScope ReadBoundRecoveryScope(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = OpenReadOnly();
        using var tx = c.BeginTransaction(deferred: true);
        var scope = ReadBoundRecoveryScope(c, tx, reservationId);
        tx.Commit();
        return scope;
    }

    private static UserManager6RecoveryScope ReadBoundRecoveryScope(SqliteConnection c,
        SqliteTransaction tx, Guid reservationId)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            SELECT j.RouterId,i.LeafSha256,j.Customer,j.Username,j.State,
                   ack.Kind,ack.RemoteId,observed.RemoteId,recovery.StateAtObservation,recovery.RemoteId
            FROM um6_create_journal j
            JOIN um6_create_intents i ON i.ReservationId=j.ReservationId
            JOIN voucher_reservations v ON v.Id=j.ReservationId AND v.BackendId=j.BackendId AND v.Username=j.Username
            JOIN backends b ON b.Id=j.BackendId AND b.RouterId=j.RouterId AND b.Kind=2
            JOIN voucher_batches batch ON batch.Id=v.BatchId AND batch.Id=i.BatchId AND batch.BackendId=j.BackendId
            JOIN plans p ON p.Id=batch.PlanId AND p.Id=i.PlanId AND p.BackendId=j.BackendId AND p.Name=i.PlanName
            JOIN router_targets t ON t.RouterId=j.RouterId AND t.LeafSha256=i.LeafSha256
            JOIN um6_voucher_secrets secret ON secret.ReservationId=j.ReservationId
            LEFT JOIN um6_create_evidence ack ON ack.ReservationId=j.ReservationId AND ack.Kind=1
            LEFT JOIN um6_create_evidence observed ON observed.ReservationId=j.ReservationId AND observed.Kind=2
            LEFT JOIN um6_recovery_evidence recovery ON recovery.ReservationId=j.ReservationId
            WHERE j.ReservationId=$id AND j.State IN (2,3,4);
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        UserManager6RecoveryScope scope;
        using (var r = cmd.ExecuteReader())
        {
            if (!r.Read()) throw new InvalidOperationException("Matching bound non-rearmable creation required.");
            var state = (UserManager6CreateState)r.GetInt32(4);
            string? returned = r.IsDBNull(6) ? null : r.GetString(6);
            string? observed = r.IsDBNull(7) ? null : r.GetString(7);
            bool hasAck = !r.IsDBNull(5);
            if ((hasAck && state != UserManager6CreateState.Acknowledged) ||
                (!hasAck && observed is not null) ||
                (returned is not null && !UserManager6Records.IsOpaqueRemoteId(returned)) ||
                (observed is not null && (!UserManager6Records.IsOpaqueRemoteId(observed) ||
                    (returned is not null && returned != observed))))
                throw new InvalidDataException("Inconsistent retained creation evidence.");
            UserManager6StoredRecoveryEvidence? recovery = null;
            if (!r.IsDBNull(8))
            {
                var at = (UserManager6CreateState)r.GetInt32(8);
                string remoteId = r.GetString(9);
                if ((at != state && at != UserManager6CreateState.DispatchStarted) ||
                    !UserManager6Records.IsOpaqueRemoteId(remoteId) ||
                    (returned is not null && returned != remoteId) ||
                    (observed is not null && observed != remoteId))
                    throw new InvalidDataException("Inconsistent retained recovery evidence.");
                recovery = new(at, remoteId);
            }
            scope = new(reservationId, r.GetGuid(0), r.GetString(1), r.GetString(2),
                r.GetString(3), state, hasAck ? new(returned, observed) : null, recovery);
        }
        return scope;
    }

    // Require historical positive disabled-account evidence, not merely an add receipt.
    // Read the bound profile intent and account scope in one local snapshot.
    internal UserManager6ProfileLinkScope ReadProfileLinkScope(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = OpenReadOnly();
        using var tx = c.BeginTransaction(deferred: true);
        var scope = ReadProfileLinkScope(c, tx, reservationId);
        tx.Commit();
        return scope;
    }

    private static UserManager6ProfileLinkScope ReadProfileLinkScope(SqliteConnection c,
        SqliteTransaction tx, Guid reservationId)
    {
        var creation = ReadBoundRecoveryScope(c, tx, reservationId);
        if (creation.Recovery is null && creation.Evidence?.ObservedId is null)
            throw new InvalidOperationException("Prior exact disabled-account evidence required.");
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT ProfileOwner,ProfileName FROM um6_create_intents WHERE ReservationId=$id;";
        cmd.Parameters.AddWithValue("$id", reservationId);
        UserManager6ProfileLinkScope scope;
        using (var r = cmd.ExecuteReader())
        {
            if (!r.Read()) throw new InvalidOperationException("Bound profile intent required.");
            string owner = r.GetString(0), name = r.GetString(1);
            UserManager6Records.ValidateKey(owner, nameof(owner));
            UserManager6Records.ValidateKey(name, nameof(name));
            scope = new(creation, owner, name);
        }
        return scope;
    }

    // Local qualification claim only. A future dispatcher must obtain fresh
    // same-session preflight and hold the managed generation and exclusive session.
    // No remote command is implemented here. Do not claim a still-in-flight creation.
    internal bool TryClaimProfileLink(UserManager6ProfileLinkScope scope, UserManager6ProfileLinkReadEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(evidence);
        Guid id = scope.Creation.ReservationId;
        ValidateId(id);
        string? remoteId = scope.Creation.ExpectedRemoteId;
        if (scope.Creation.State is not (UserManager6CreateState.Indeterminate or UserManager6CreateState.Acknowledged) ||
            !UserManager6Records.IsOpaqueRemoteId(remoteId) ||
            evidence.State != UserManager6ProfileLinkReadState.BothVisible || evidence.ActualProfile != string.Empty ||
            evidence.Account is null || !evidence.Account.ReturnedIdMatched || evidence.Account.RemoteId != remoteId ||
            evidence.Profile is null || evidence.Profile.Owner != scope.ProfileOwner || evidence.Profile.Name != scope.ProfileName)
            throw new InvalidOperationException("Exact account and intended profile evidence required.");

        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        if (ReadProfileLinkScope(c, tx, id) != scope)
            throw new InvalidOperationException("Profile link scope changed before claim.");
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO um6_profile_link_journal(ReservationId,RemoteId,State)
            VALUES($id,$remote,2) ON CONFLICT(ReservationId) DO NOTHING;
            """;
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$remote", remoteId!);
        bool claimed = cmd.ExecuteNonQuery() == 1;
        tx.Commit();
        return claimed;
    }

    internal UserManager6ProfileLinkEntry? ReadProfileLinkEntry(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = OpenReadOnly();
        using var tx = c.BeginTransaction(deferred: true);
        var entry = ReadProfileLinkEntry(c, tx, reservationId);
        tx.Commit();
        return entry;
    }

    private static UserManager6ProfileLinkEntry? ReadProfileLinkEntry(SqliteConnection c,
        SqliteTransaction tx, Guid reservationId)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT RemoteId,State FROM um6_profile_link_journal WHERE ReservationId=$id;";
        cmd.Parameters.AddWithValue("$id", reservationId);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        string remoteId = r.GetString(0);
        var state = (UserManager6ProfileLinkState)r.GetInt32(1);
        if (!UserManager6Records.IsOpaqueRemoteId(remoteId) || !Enum.IsDefined(state))
            throw new InvalidDataException("Invalid retained profile link entry.");
        return new(reservationId, remoteId, state);
    }

    // Capture both immutable intent and non-rearmable link attempt in one snapshot.
    internal UserManager6ProfileLinkReviewScope ReadProfileLinkReviewScope(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = OpenReadOnly();
        using var tx = c.BeginTransaction(deferred: true);
        var intent = ReadProfileLinkScope(c, tx, reservationId);
        var entry = ReadProfileLinkEntry(c, tx, reservationId)
            ?? throw new InvalidOperationException("Existing profile link claim required.");
        if (intent.Creation.State is not (UserManager6CreateState.Indeterminate or UserManager6CreateState.Acknowledged) ||
            entry.RemoteId != intent.Creation.ExpectedRemoteId)
            throw new InvalidOperationException("Profile link identity no longer matches.");
        tx.Commit();
        return new(intent, entry);
    }

    // Acknowledgement is not confirmed assignment. Neither terminal state can be replayed.
    internal bool TryRecordProfileLinkResult(Guid reservationId, UserManager6ProfileLinkState outcome)
    {
        ValidateId(reservationId);
        if (outcome is not (UserManager6ProfileLinkState.Acknowledged or UserManager6ProfileLinkState.Indeterminate))
            throw new ArgumentOutOfRangeException(nameof(outcome));
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "UPDATE um6_profile_link_journal SET State=$state WHERE ReservationId=$id AND State=2;";
        cmd.Parameters.AddWithValue("$id", reservationId);
        cmd.Parameters.AddWithValue("$state", (int)outcome);
        bool recorded = cmd.ExecuteNonQuery() == 1;
        tx.Commit();
        return recorded;
    }

    internal static void RequireEquivalentProfileLinksForRestore(string currentPath, string candidatePath)
    {
        using var current = DatabaseBackup.OpenRaw(currentPath, SqliteOpenMode.ReadOnly);
        using var candidate = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(current);
        DatabaseBackup.RequireIdentity(candidate);
        using var a = current.CreateCommand();
        using var b = candidate.CreateCommand();
        const string query = """
            SELECT ReservationId,RemoteId,State FROM um6_profile_link_journal
            ORDER BY ReservationId COLLATE BINARY;
            """;
        a.CommandText = query;
        b.CommandText = query;
        using var left = a.ExecuteReader();
        using var right = b.ExecuteReader();
        while (true)
        {
            bool hasLeft = left.Read(), hasRight = right.Read();
            if (hasLeft != hasRight) throw RestoreConflict();
            if (!hasLeft) return;
            for (int i = 0; i < 3; i++)
                if (!Equals(left.GetValue(i), right.GetValue(i))) throw RestoreConflict();
        }
    }

    // Persist only positive readback evidence. Revalidate the whole scope inside
    // the same immediate transaction as insertion, closing the local TOCTOU gap.
    // The first positive observation remains immutable; a later absence never clears it.
    internal bool TryRecordRecoveryObservation(UserManager6RecoveryObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        var scope = observation.Scope;
        ValidateId(scope.ReservationId);
        var visible = observation.VisibleDisabledAccount;
        if (visible is null) return false;
        if (!UserManager6Records.IsOpaqueRemoteId(visible.RemoteId) ||
            (scope.ExpectedRemoteId is not null && scope.ExpectedRemoteId != visible.RemoteId) ||
            visible.ReturnedIdMatched != (scope.ExpectedRemoteId is not null))
            throw new InvalidOperationException("Recovery observation does not match retained identity.");

        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        if (ReadBoundRecoveryScope(c, tx, scope.ReservationId) != scope)
            throw new InvalidOperationException("Local creation evidence changed before recovery persistence.");
        if (scope.Recovery is not null) return false;
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO um6_recovery_evidence(ReservationId,StateAtObservation,RemoteId)
            VALUES($id,$state,$remote);
            """;
        cmd.Parameters.AddWithValue("$id", scope.ReservationId);
        cmd.Parameters.AddWithValue("$state", (int)scope.State);
        cmd.Parameters.AddWithValue("$remote", visible.RemoteId);
        cmd.ExecuteNonQuery();
        tx.Commit();
        return true;
    }

    internal static void RequireEquivalentRecoveryForRestore(string currentPath, string candidatePath)
    {
        using var current = DatabaseBackup.OpenRaw(currentPath, SqliteOpenMode.ReadOnly);
        using var candidate = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(current);
        DatabaseBackup.RequireIdentity(candidate);
        using var a = current.CreateCommand();
        using var b = candidate.CreateCommand();
        const string query = """
            SELECT ReservationId,StateAtObservation,RemoteId FROM um6_recovery_evidence
            ORDER BY ReservationId COLLATE BINARY;
            """;
        a.CommandText = query;
        b.CommandText = query;
        using var left = a.ExecuteReader();
        using var right = b.ExecuteReader();
        while (true)
        {
            bool hasLeft = left.Read(), hasRight = right.Read();
            if (hasLeft != hasRight) throw RestoreConflict();
            if (!hasLeft) return;
            for (int i = 0; i < 3; i++)
                if (!Equals(left.GetValue(i), right.GetValue(i))) throw RestoreConflict();
        }
    }

    // A local claim only. Never use the legacy unbound claim for remote dispatch.
    internal bool TryBeginDispatch(Guid reservationId) =>
        Transition(reservationId, UserManager6CreateState.Prepared, UserManager6CreateState.DispatchStarted);

    // Compare immutable intent with current local relationships atomically before claiming.
    // Remote checks, protected voucher credentials and authorization are still required.
    [SupportedOSPlatform("windows")]
    internal bool TryBeginBoundDispatch(Guid reservationId)
    {
        using var secret = TryClaimBoundSecret(reservationId);
        return secret is not null;
    }

    // Transfer the decrypted, immutable secret only AFTER the one-shot claim commits.
    // No remote operation may be attempted if validation or commit fails.
    [SupportedOSPlatform("windows")]
    internal UserManager6VoucherSecretLease? TryClaimBoundSecret(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            UPDATE um6_create_journal SET State=2 WHERE ReservationId=$id AND State=1
            AND EXISTS (
                SELECT 1 FROM um6_create_intents i
                JOIN voucher_reservations v ON v.Id=i.ReservationId
                JOIN backends b ON b.Id=v.BackendId
                JOIN voucher_batches batch ON batch.Id=v.BatchId
                JOIN plans p ON p.Id=batch.PlanId
                JOIN router_targets t ON t.RouterId=b.RouterId
                WHERE i.ReservationId=um6_create_journal.ReservationId
                  AND v.BackendId=um6_create_journal.BackendId AND v.Username=um6_create_journal.Username
                  AND b.RouterId=um6_create_journal.RouterId AND b.Kind=2
                  AND batch.Id=i.BatchId AND batch.BackendId=v.BackendId
                  AND p.Id=i.PlanId AND p.BackendId=v.BackendId AND p.Name=i.PlanName
                  AND t.LeafSha256=i.LeafSha256);
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        if (cmd.ExecuteNonQuery() != 1) return null;
        // The update is still uncommitted. A missing or invalid secret rolls it back.
        var secret = UserManager6VoucherSecretStore.Load(c, tx, reservationId);
        if (secret is null) return null;
        try
        {
            UserManager6CreateWire.ValidatePassword(secret.Password.Span);
            tx.Commit();
            return secret;
        }
        catch { secret.Dispose(); throw; }
    }

    internal bool TryMarkIndeterminate(Guid reservationId) =>
        Transition(reservationId, UserManager6CreateState.DispatchStarted, UserManager6CreateState.Indeterminate);

    internal bool TryMarkAcknowledged(Guid reservationId) =>
        Transition(reservationId, UserManager6CreateState.DispatchStarted, UserManager6CreateState.Acknowledged);

    // Acknowledgement and its optional returned ID are committed together. Existing
    // legacy state=4 rows are deliberately not backfilled with fabricated receipts.
    internal bool TryRecordAcknowledgement(Guid reservationId, UserManager6CreateWireReceipt receipt)
    {
        ValidateId(reservationId);
        ArgumentNullException.ThrowIfNull(receipt);
        if (receipt.Outcome != UserManager6CreateWireOutcome.Acknowledged ||
            (receipt.ReturnedId is not null && !UserManager6Records.IsOpaqueRemoteId(receipt.ReturnedId)))
            throw new ArgumentException("Valid acknowledgement evidence required.", nameof(receipt));

        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "UPDATE um6_create_journal SET State=4 WHERE ReservationId=$id AND State=2;";
        cmd.Parameters.AddWithValue("$id", reservationId);
        if (cmd.ExecuteNonQuery() != 1) return false;
        // Trigger validates the current bound relationships and the retained secret.
        // Failure rolls back BOTH the acknowledgement and the evidence insert.
        InsertEvidence(c, tx, reservationId, 1, receipt.ReturnedId);
        tx.Commit();
        return true;
    }

    // Only a caller that completed the exact qualification read may submit this
    // observation. The immutable acknowledgement and current local scope must agree.
    internal void RecordDisabledObservation(Guid reservationId, UserManager6DisabledCreationObservation observation)
    {
        ValidateId(reservationId);
        ArgumentNullException.ThrowIfNull(observation);
        if (!UserManager6Records.IsOpaqueRemoteId(observation.RemoteId))
            throw new ArgumentException("Valid observed identity required.", nameof(observation));
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT RemoteId FROM um6_create_evidence WHERE ReservationId=$id AND Kind=1;";
        cmd.Parameters.AddWithValue("$id", reservationId);
        object? returned = cmd.ExecuteScalar();
        if (returned is null || (returned is string known &&
                !string.Equals(known, observation.RemoteId, StringComparison.Ordinal)) ||
            observation.ReturnedIdMatched != (returned is string))
            throw new InvalidOperationException("Observation does not match retained acknowledgement.");
        InsertEvidence(c, tx, reservationId, 2, observation.RemoteId);
        tx.Commit();
    }

    internal UserManager6StoredCreationEvidence? ReadCreationEvidence(Guid reservationId)
    {
        ValidateId(reservationId);
        using var c = OpenReadOnly();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT ack.RemoteId, observed.RemoteId
            FROM um6_create_evidence ack LEFT JOIN um6_create_evidence observed
              ON observed.ReservationId=ack.ReservationId AND observed.Kind=2
            WHERE ack.ReservationId=$id AND ack.Kind=1;
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        using var r = cmd.ExecuteReader();
        return r.Read() ? new(r.IsDBNull(0) ? null : r.GetString(0),
            r.IsDBNull(1) ? null : r.GetString(1)) : null;
    }

    private static void InsertEvidence(SqliteConnection c, SqliteTransaction tx, Guid reservationId,
        int kind, string? remoteId)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO um6_create_evidence(ReservationId,Kind,RemoteId) VALUES($id,$kind,$remote);";
        cmd.Parameters.AddWithValue("$id", reservationId);
        cmd.Parameters.AddWithValue("$kind", kind);
        cmd.Parameters.AddWithValue("$remote", (object?)remoteId ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    // Restore must preserve all evidence exactly, including bare acknowledgement
    // versus no receipt. No merge, inference or replay.
    internal static void RequireEquivalentEvidenceForRestore(string currentPath, string candidatePath)
    {
        using var current = DatabaseBackup.OpenRaw(currentPath, SqliteOpenMode.ReadOnly);
        using var candidate = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(current);
        DatabaseBackup.RequireIdentity(candidate);
        using var a = current.CreateCommand();
        using var b = candidate.CreateCommand();
        const string query = """
            SELECT ReservationId,Kind,RemoteId FROM um6_create_evidence
            ORDER BY ReservationId COLLATE BINARY,Kind;
            """;
        a.CommandText = query;
        b.CommandText = query;
        using var left = a.ExecuteReader();
        using var right = b.ExecuteReader();
        while (true)
        {
            bool hasLeft = left.Read(), hasRight = right.Read();
            if (hasLeft != hasRight) throw RestoreConflict();
            if (!hasLeft) return;
            for (int i = 0; i < 3; i++)
                if (!Equals(left.GetValue(i), right.GetValue(i))) throw RestoreConflict();
        }
    }

    private bool Transition(Guid reservationId, UserManager6CreateState expected, UserManager6CreateState next)
    {
        ValidateId(reservationId);
        using var c = DatabaseStore.OpenExisting(databasePath);
        using var tx = c.BeginTransaction(deferred: false);
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            UPDATE um6_create_journal SET State=$next WHERE ReservationId=$id AND State=$expected
              AND ($expected<>1 OR NOT EXISTS (SELECT 1 FROM um6_create_intents i WHERE i.ReservationId=um6_create_journal.ReservationId))
              AND EXISTS (SELECT 1 FROM voucher_reservations v JOIN backends b ON b.Id=v.BackendId
                WHERE v.Id=um6_create_journal.ReservationId AND v.BackendId=um6_create_journal.BackendId
                  AND b.RouterId=um6_create_journal.RouterId AND b.Kind=2 AND v.Username=um6_create_journal.Username);
            """;
        cmd.Parameters.AddWithValue("$id", reservationId);
        cmd.Parameters.AddWithValue("$expected", (int)expected);
        cmd.Parameters.AddWithValue("$next", (int)next);
        bool changed = cmd.ExecuteNonQuery() == 1;
        tx.Commit();
        return changed;
    }

    private static void ValidateId(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("A reservation identity is required.", nameof(id));
    }

    // Conservative cross-generation reconciliation: only identical creation histories
    // with matching local target relationships may switch generations. No union or replay.
    // Caller must hold the exclusive managed gate and quiesce all writers.
    internal static void RequireEquivalentForRestore(string currentPath, string candidatePath)
    {
        using var current = DatabaseBackup.OpenRaw(currentPath, SqliteOpenMode.ReadOnly);
        using var candidate = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(current);
        DatabaseBackup.RequireIdentity(candidate);
        using var left = current.CreateCommand();
        using var right = candidate.CreateCommand();
        // LEFT JOIN is intentional: an inconsistent relationship must not hide a journal row.
        const string query = """
            SELECT j.ReservationId,j.BackendId,j.RouterId,j.Customer,j.Username,j.State,
                   v.BatchId,p.Id,p.Name,r.SiteId,r.Name,s.Name,
                   CASE WHEN v.Id IS NOT NULL AND v.BackendId=j.BackendId AND v.Username=j.Username
                       AND b.Kind=2 AND b.RouterId=j.RouterId
                       AND batch.Id IS NOT NULL AND batch.BackendId=j.BackendId
                       AND p.Id IS NOT NULL AND p.BackendId=j.BackendId
                       AND r.Id IS NOT NULL AND s.Id IS NOT NULL THEN 1 ELSE 0 END
            FROM um6_create_journal j
            LEFT JOIN voucher_reservations v ON v.Id=j.ReservationId
            LEFT JOIN backends b ON b.Id=j.BackendId
            LEFT JOIN voucher_batches batch ON batch.Id=v.BatchId
            LEFT JOIN plans p ON p.Id=batch.PlanId
            LEFT JOIN routers r ON r.Id=j.RouterId
            LEFT JOIN sites s ON s.Id=r.SiteId
            ORDER BY j.ReservationId COLLATE BINARY;
            """;
        left.CommandText = query;
        right.CommandText = query;
        using var a = left.ExecuteReader();
        using var b = right.ExecuteReader();
        while (true)
        {
            bool hasA = a.Read(), hasB = b.Read();
            if (hasA != hasB) throw RestoreConflict();
            if (!hasA) return;
            if (a.GetInt32(12) != 1 || b.GetInt32(12) != 1) throw RestoreConflict();
            for (int i = 0; i < 12; i++)
                if (a.IsDBNull(i) || b.IsDBNull(i) || !Equals(a.GetValue(i), b.GetValue(i)))
                    throw RestoreConflict();
        }
    }

    // Preserve exact immutable intent evidence, even on still-prepared rows.
    internal static void RequireEquivalentIntentsForRestore(string currentPath, string candidatePath)
    {
        using var current = DatabaseBackup.OpenRaw(currentPath, SqliteOpenMode.ReadOnly);
        using var candidate = DatabaseBackup.OpenRaw(candidatePath, SqliteOpenMode.ReadOnly);
        DatabaseBackup.RequireIdentity(current);
        DatabaseBackup.RequireIdentity(candidate);
        using var a = current.CreateCommand();
        using var b = candidate.CreateCommand();
        const string query = """
            SELECT ReservationId,BatchId,PlanId,PlanName,LeafSha256,ProfileOwner,ProfileName
            FROM um6_create_intents ORDER BY ReservationId COLLATE BINARY;
            """;
        a.CommandText = query;
        b.CommandText = query;
        using var left = a.ExecuteReader();
        using var right = b.ExecuteReader();
        while (true)
        {
            bool hasLeft = left.Read(), hasRight = right.Read();
            if (hasLeft != hasRight) throw RestoreConflict();
            if (!hasLeft) return;
            for (int i = 0; i < 7; i++)
                if (left.IsDBNull(i) || right.IsDBNull(i) || !Equals(left.GetValue(i), right.GetValue(i)))
                    throw RestoreConflict();
        }
    }

    private static InvalidOperationException RestoreConflict() =>
        new("UM6 creation evidence or its local target differs; restore requires explicit reconciliation.");
}
