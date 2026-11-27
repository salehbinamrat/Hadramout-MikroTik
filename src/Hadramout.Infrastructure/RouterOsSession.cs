using System.Security.Authentication;
using System.Security.Cryptography;
using Hadramout.Core;

namespace Hadramout.Infrastructure;

// One authenticated session, one in-flight command. No automatic retry or mutation API.
internal sealed class RouterOsSession : IDisposable
{
    private RouterOsTlsTransport? transport;
    private int busy;

    private RouterOsSession(RouterOsTlsTransport transport) => this.transport = transport;

    // Caller owns the input buffers and must keep them stable until this task completes.
    internal static Task<RouterOsSession> ConnectAsync(string host, string certificateName,
        ReadOnlyMemory<byte> username, ReadOnlyMemory<byte> password, int port = 8729,
        TimeSpan? timeout = null, ReadOnlyMemory<byte> trustedRootDer = default,
        CancellationToken cancellationToken = default) =>
        ConnectCoreAsync(host, certificateName, username, password, port, timeout, trustedRootDer,
            cancellationToken, expectedLeafSha256: null);

    // Explicit pin-required path for future verified target operations. No downgrade
    // to the ordinary read connection when pin validation fails.
    internal static Task<RouterOsSession> ConnectPinnedAsync(string host, string certificateName,
        string expectedLeafSha256, ReadOnlyMemory<byte> username, ReadOnlyMemory<byte> password,
        int port = 8729, TimeSpan? timeout = null, ReadOnlyMemory<byte> trustedRootDer = default,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedLeafSha256);
        return ConnectCoreAsync(host, certificateName, username, password, port, timeout, trustedRootDer,
            cancellationToken, expectedLeafSha256);
    }

    private static async Task<RouterOsSession> ConnectCoreAsync(string host, string certificateName,
        ReadOnlyMemory<byte> username, ReadOnlyMemory<byte> password, int port, TimeSpan? timeout,
        ReadOnlyMemory<byte> trustedRootDer, CancellationToken cancellationToken, string? expectedLeafSha256)
    {
        if (username.Length is < 1 or > 4096 || password.Length > 4096)
            throw new ArgumentException("RouterOS credential length is invalid.");
        TimeSpan limit = ValidateTimeout(timeout);
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(limit);
        RouterOsTlsTransport? connection = null;
        try
        {
            connection = await RouterOsTlsTransport.ConnectAsync(host, certificateName, port, limit,
                trustedRootDer, deadline.Token, expectedLeafSha256).ConfigureAwait(false);
            byte[] nameWord = new byte[6 + username.Length];
            byte[] passwordWord = new byte[10 + password.Length];
            try
            {
                "=name="u8.CopyTo(nameWord);
                username.Span.CopyTo(nameWord.AsSpan(6));
                "=password="u8.CopyTo(passwordWord);
                password.Span.CopyTo(passwordWord.AsSpan(10));
                await RouterOsWireCodec.WriteSentenceAsync(connection.Stream,
                    ["/login"u8.ToArray(), nameWord, passwordWord], deadline.Token).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nameWord);
                CryptographicOperations.ZeroMemory(passwordWord);
            }

            byte[][] reply = await RouterOsWireCodec.ReadSentenceAsync(connection.Stream, deadline.Token)
                .ConfigureAwait(false);
            try
            {
                // Post-v6.43 success is a bare !done. A challenge, trap, data or
                // an unexpected attribute must never be interpreted as authentication.
                if (reply.Length != 1 || !reply[0].AsSpan().SequenceEqual("!done"u8))
                    throw new AuthenticationException("RouterOS login was rejected or returned an unsupported reply.");
            }
            finally { ClearWords(reply); }

            deadline.Token.ThrowIfCancellationRequested();
            var session = new RouterOsSession(connection);
            connection = null; // ownership transferred only after authenticated completion
            return session;
        }
        catch (Exception ex) when (deadline.IsCancellationRequested)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new TimeoutException("RouterOS connection and login deadline exceeded.", ex);
        }
        finally { connection?.Dispose(); }
    }

    internal Task<string> ReadVersionAsync(TimeSpan? timeout = null,
        CancellationToken cancellationToken = default) =>
        WithReadSessionAsync(ReadVersionCoreAsync, timeout, cancellationToken);

    // Both reads share a session gate and a single deadline. Not an atomic remote snapshot.
    internal Task<RouterOsInventory> DiscoverAsync(TimeSpan? timeout = null,
        CancellationToken cancellationToken = default) =>
        WithReadSessionAsync(async (stream, token) =>
        {
            string version = await ReadVersionCoreAsync(stream, token).ConfigureAwait(false);
            if (RouterOsInventory.ClassifyVersion(version) == RouterOsFamily.Unsupported)
                return RouterOsInventory.Classify(version, [], inventoryRead: false);
            var packages = await ReadCommandAsync(stream,
                ["/system/package/print"u8.ToArray(), "=.proplist=name,version,disabled,scheduled"u8.ToArray()],
                RouterOsInventory.ParsePackage, 256, token).ConfigureAwait(false);
            return RouterOsInventory.Classify(version, packages, inventoryRead: true);
        }, timeout, cancellationToken);

    // Probe one account menu per call. A rejected or terminated command invalidates this
    // session; probing a different menu then requires a new authenticated connection.
    internal Task<RouterOsServiceProbe> ProbeServiceAsync(BackendKind backend, TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(backend)) throw new ArgumentOutOfRangeException(nameof(backend));
        return WithReadSessionAsync(async (stream, token) =>
        {
            string version = await ReadVersionCoreAsync(stream, token).ConfigureAwait(false);
            var family = RouterOsInventory.ClassifyVersion(version);
            if (family == RouterOsFamily.Unsupported ||
                (backend == BackendKind.UserManager6 && family != RouterOsFamily.V6) ||
                (backend == BackendKind.UserManager7 && family != RouterOsFamily.V7))
                return new RouterOsServiceProbe(backend, family, RouterOsServiceProbeState.NotApplicable);

            // Fixed allowlist only. PPP secrets filtered to PPPoE; no credentials or rows requested.
            ReadOnlyMemory<byte>[] command = backend switch
            {
                BackendKind.UserManager6 => ["/tool/user-manager/user/print"u8.ToArray(), "=count-only="u8.ToArray()],
                BackendKind.UserManager7 => ["/user-manager/user/print"u8.ToArray(), "=count-only="u8.ToArray()],
                BackendKind.Hotspot => ["/ip/hotspot/user/print"u8.ToArray(), "=count-only="u8.ToArray()],
                BackendKind.Pppoe => ["/ppp/secret/print"u8.ToArray(), "=count-only="u8.ToArray(),
                    "?service=pppoe"u8.ToArray(), "?service=any"u8.ToArray(), "?#|"u8.ToArray()],
                _ => throw new ArgumentOutOfRangeException(nameof(backend))
            };
            await RouterOsWireCodec.WriteSentenceAsync(stream, command, token).ConfigureAwait(false);
            var reply = await RouterOsReplyReader.ReadAsync(stream, _ => 0, 1, token, countOnly: true)
                .ConfigureAwait(false);
            if (reply.Outcome == RouterOsReplyOutcome.Completed)
                return new RouterOsServiceProbe(backend, family, RouterOsServiceProbeState.Readable,
                    reply.CompletionCount ?? throw new InvalidDataException("Missing RouterOS count."));
            Dispose();
            return new RouterOsServiceProbe(backend, family,
                reply.Outcome == RouterOsReplyOutcome.Rejected ? RouterOsServiceProbeState.Rejected :
                RouterOsServiceProbeState.ConnectionTerminated, TrapCategory: reply.TrapCategory);
        }, timeout, cancellationToken);
    }

    internal Task<UserManager6Account?> FindUserManager6AccountAsync(string customer, string username,
        TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        UserManager6Records.ValidateKey(customer, nameof(customer));
        UserManager6Records.ValidateKey(username, nameof(username));
        return WithReadSessionAsync<UserManager6Account?>(async (stream, token) =>
        {
            await RequireUserManager6FamilyAsync(stream, token).ConfigureAwait(false);
            var rows = await ReadCommandAsync(stream,
                ["/tool/user-manager/user/print"u8.ToArray(),
                    "=.proplist=customer,username,disabled,actual-profile,download-used,upload-used,uptime-used,active,incomplete,last-seen,active-sessions"u8.ToArray(),
                    UserManager6Records.Query("customer", customer), UserManager6Records.Query("username", username)],
                words => UserManager6Records.ParseAccount(words, customer, username), 1, token).ConfigureAwait(false);
            return rows.Count == 0 ? null : rows[0];
        }, timeout, cancellationToken);
    }

    internal Task<UserManager6Profile?> FindUserManager6ProfileAsync(string owner, string name,
        TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        UserManager6Records.ValidateKey(owner, nameof(owner));
        UserManager6Records.ValidateKey(name, nameof(name));
        return WithReadSessionAsync<UserManager6Profile?>(async (stream, token) =>
        {
            await RequireUserManager6FamilyAsync(stream, token).ConfigureAwait(false);
            var rows = await ReadCommandAsync(stream,
                ["/tool/user-manager/profile/print"u8.ToArray(),
                    "=.proplist=owner,name,validity,starts-at"u8.ToArray(),
                    UserManager6Records.Query("owner", owner), UserManager6Records.Query("name", name)],
                words => UserManager6Records.ParseProfile(words, owner, name), 1, token).ConfigureAwait(false);
            return rows.Count == 0 ? null : rows[0];
        }, timeout, cancellationToken);
    }

    internal Task<UserManager6Limitation?> FindUserManager6LimitationAsync(string owner, string name,
        TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        UserManager6Records.ValidateKey(owner, nameof(owner));
        UserManager6Records.ValidateKey(name, nameof(name));
        return WithReadSessionAsync<UserManager6Limitation?>(async (stream, token) =>
        {
            await RequireUserManager6FamilyAsync(stream, token).ConfigureAwait(false);
            var rows = await ReadCommandAsync(stream,
                ["/tool/user-manager/profile/limitation/print"u8.ToArray(),
                    "=.proplist=owner,name,download-limit,upload-limit,transfer-limit,uptime-limit,rate-limit-rx,rate-limit-tx"u8.ToArray(),
                    UserManager6Records.Query("owner", owner), UserManager6Records.Query("name", name)],
                words => UserManager6Records.ParseLimitation(words, owner, name), 1, token).ConfigureAwait(false);
            return rows.Count == 0 ? null : rows[0];
        }, timeout, cancellationToken);
    }

    // Completed read observations only; no reservation or write authorization.
    internal Task<UserManager6PreflightEvidence> ReadUserManager6CreationPreflightAsync(
        string owner, string profile, string username, TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        UserManager6Records.ValidateKey(owner, nameof(owner));
        UserManager6Records.ValidateKey(profile, nameof(profile));
        UserManager6Records.ValidateKey(username, nameof(username));
        return WithReadSessionAsync((stream, token) => ReadUm6PreflightCoreAsync(stream, owner, profile, username, token),
            timeout, cancellationToken);
    }

    // Shared completed-read protocol; caller owns exclusive authenticated stream.
    internal static async Task<UserManager6PreflightEvidence> ReadUm6PreflightCoreAsync(
        Stream stream, string owner, string profile, string username, CancellationToken token)
    {
        UserManager6Records.ValidateKey(owner, nameof(owner));
        UserManager6Records.ValidateKey(profile, nameof(profile));
        UserManager6Records.ValidateKey(username, nameof(username));
        await RequireUserManager6FamilyAsync(stream, token).ConfigureAwait(false);
        var profiles = await ReadUniqueVisibleUm6ProfileAsync(stream, owner, profile, token).ConfigureAwait(false);
        if (profiles.Count == 0)
            return new UserManager6PreflightEvidence(UserManager6PreflightState.ProfileNotVisible, null, null);
        // No customer filter: any visible same-name account blocks creation.
        var customers = await ReadCommandAsync(stream,
            ["/tool/user-manager/user/print"u8.ToArray(),
                "=.proplist=customer,username"u8.ToArray(),
                UserManager6Records.Query("username", username)],
            words => UserManager6Records.ParseVisibleUsernameCustomer(words, username), 1, token).ConfigureAwait(false);
        return customers.Count == 0
            ? new UserManager6PreflightEvidence(UserManager6PreflightState.NoVisibleUsernameMatch, profiles[0], null)
            : new UserManager6PreflightEvidence(UserManager6PreflightState.UsernameAlreadyVisible, profiles[0], customers[0]);
    }

    // First verify a unique visible profile name and its owner. Legacy mapping rows
    // expose profile names but not owners; return explicitly non-authoritative evidence.
    internal Task<UserManager6ProfileMappingEvidence?> ReadUserManager6ProfileMappingAsync(
        string owner, string name, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        UserManager6Records.ValidateKey(owner, nameof(owner));
        UserManager6Records.ValidateKey(name, nameof(name));
        return WithReadSessionAsync<UserManager6ProfileMappingEvidence?>(async (stream, token) =>
        {
            await RequireUserManager6FamilyAsync(stream, token).ConfigureAwait(false);
            // Do not filter by owner here: that could hide a visible same-name collision.
            // Only the expected owner's exact row may pass the projector.
            var profiles = await ReadUniqueVisibleUm6ProfileAsync(stream, owner, name, token).ConfigureAwait(false);
            if (profiles.Count == 0) return null;
            var links = await ReadCommandAsync(stream,
                ["/tool/user-manager/profile/profile-limitation/print"u8.ToArray(),
                    "=.proplist=profile,limitation,from-time,till-time,weekdays"u8.ToArray(),
                    UserManager6Records.Query("profile", name)],
                words => UserManager6Records.ParseProfileLink(words, name), 32, token).ConfigureAwait(false);
            return new UserManager6ProfileMappingEvidence(profiles[0], links);
        }, timeout, cancellationToken);
    }

    // Qualification only. Call on an exclusively held, authenticated stream after
    // an acknowledged creation exchange. Never reconnect, retry, mutate or mark a
    // journal confirmed here; an absent row is only absence of visible evidence.
    internal static async Task<UserManager6DisabledCreationObservation?> ReadUm6DisabledCreationObservationAsync(
        Stream stream, Guid reservationId, string customer, string username,
        UserManager6CreateWireReceipt receipt, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(receipt);
        if (reservationId == Guid.Empty)
            throw new ArgumentException("Reservation identity required.", nameof(reservationId));
        UserManager6Records.ValidateKey(customer, nameof(customer));
        UserManager6Records.ValidateKey(username, nameof(username));
        if (receipt.Outcome != UserManager6CreateWireOutcome.Acknowledged ||
            (receipt.ReturnedId is not null && !UserManager6Records.IsOpaqueRemoteId(receipt.ReturnedId)))
            throw new InvalidOperationException("A valid acknowledged creation receipt is required.");
        return await ReadUm6DisabledIdentityCoreAsync(stream, reservationId, customer, username,
            receipt.ReturnedId, token).ConfigureAwait(false);
    }

    // Recovery has no fabricated acknowledgement: use only the retained expected ID, if any.
    internal Task<UserManager6DisabledCreationObservation?> ReadUm6RecoveryObservationAsync(
        UserManager6RecoveryScope scope, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return WithReadSessionAsync((stream, token) => ReadUm6DisabledIdentityCoreAsync(stream,
            scope.ReservationId, scope.Customer, scope.Username, scope.ExpectedRemoteId, token),
            timeout, cancellationToken);
    }

    // Read only, on one exclusive authenticated session. This is not evidence of
    // an assigned profile or permission to perform an add/activate/enable command.
    internal Task<UserManager6ProfileLinkReadEvidence> ReadUm6ProfileLinkPreflightAsync(
        UserManager6ProfileLinkScope scope, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        var creation = scope.Creation;
        UserManager6Records.ValidateKey(scope.ProfileOwner, nameof(scope.ProfileOwner));
        UserManager6Records.ValidateKey(scope.ProfileName, nameof(scope.ProfileName));
        if ((creation.Recovery is null && creation.Evidence?.ObservedId is null) ||
            !UserManager6Records.IsOpaqueRemoteId(creation.ExpectedRemoteId))
            throw new InvalidOperationException("Prior exact disabled-account evidence required.");
        return WithReadSessionAsync<UserManager6ProfileLinkReadEvidence>(async (stream, token) =>
        {
            await RequireUserManager6FamilyAsync(stream, token).ConfigureAwait(false);
            var accounts = await ReadCommandAsync(stream,
                ["/tool/user-manager/user/print"u8.ToArray(),
                    "=.proplist=.id,customer,username,disabled,comment,actual-profile"u8.ToArray(),
                    UserManager6Records.Query("username", creation.Username)],
                words => UserManager6Records.ParseProfileLinkAccount(words, creation.ReservationId,
                    creation.Customer, creation.Username, creation.ExpectedRemoteId!), 1, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (accounts.Count == 0)
                return new(UserManager6ProfileLinkReadState.AccountNotVisible, null, null);
            var (account, actualProfile) = accounts[0];
            // Missing/whitespace is unknown, never an empty-profile observation.
            // Any named profile (even the intended one) blocks a new link claim.
            if (actualProfile != string.Empty)
                return new(string.IsNullOrWhiteSpace(actualProfile)
                    ? UserManager6ProfileLinkReadState.AccountProfileUnknown
                    : UserManager6ProfileLinkReadState.AccountProfileAlreadyVisible, account, null, actualProfile);
            var profiles = await ReadUniqueVisibleUm6ProfileAsync(stream,
                scope.ProfileOwner, scope.ProfileName, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            return profiles.Count == 0
                ? new(UserManager6ProfileLinkReadState.ProfileNotVisible, account, null, actualProfile)
                : new(UserManager6ProfileLinkReadState.BothVisible, account, profiles[0], actualProfile);
        }, timeout, cancellationToken);
    }

    private static async Task<UserManager6DisabledCreationObservation?> ReadUm6DisabledIdentityCoreAsync(
        Stream stream, Guid reservationId, string customer, string username, string? expectedId,
        CancellationToken token)
    {
        if (reservationId == Guid.Empty) throw new ArgumentException("Reservation identity required.", nameof(reservationId));
        UserManager6Records.ValidateKey(customer, nameof(customer));
        UserManager6Records.ValidateKey(username, nameof(username));
        if (expectedId is not null && !UserManager6Records.IsOpaqueRemoteId(expectedId))
            throw new ArgumentException("Invalid expected RouterOS identity.", nameof(expectedId));
        token.ThrowIfCancellationRequested();
        await RequireUserManager6FamilyAsync(stream, token).ConfigureAwait(false);
        // Global visible username match, not a customer-filtered query that could
        // conceal a conflicting account. More than one row fails closed.
        var rows = await ReadCommandAsync(stream,
            ["/tool/user-manager/user/print"u8.ToArray(),
                "=.proplist=.id,customer,username,disabled,comment"u8.ToArray(),
                UserManager6Records.Query("username", username)],
            words => UserManager6Records.ParseDisabledCreationObservation(words,
                reservationId, customer, username, expectedId), 1, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        return rows.Count == 0 ? null : rows[0];
    }

    private static Task<IReadOnlyList<UserManager6Profile>> ReadUniqueVisibleUm6ProfileAsync(
        Stream stream, string owner, string name, CancellationToken token) =>
        ReadCommandAsync(stream,
            ["/tool/user-manager/profile/print"u8.ToArray(),
                "=.proplist=owner,name,validity,starts-at"u8.ToArray(),
                UserManager6Records.Query("name", name)],
            words => UserManager6Records.ParseProfile(words, owner, name), 1, token);

    private static async Task RequireUserManager6FamilyAsync(Stream stream, CancellationToken token)
    {
        string version = await ReadVersionCoreAsync(stream, token).ConfigureAwait(false);
        if (RouterOsInventory.ClassifyVersion(version) != RouterOsFamily.V6)
            throw new NotSupportedException("User Manager v6 requires a supported RouterOS v6 release.");
    }

    private async Task<T> WithReadSessionAsync<T>(Func<Stream, CancellationToken, Task<T>> read,
        TimeSpan? timeout, CancellationToken cancellationToken)
    {
        TimeSpan limit = ValidateTimeout(timeout);
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.CompareExchange(ref busy, 1, 0) != 0)
            throw new InvalidOperationException("A RouterOS command is already running.");
        try
        {
            RouterOsTlsTransport connection = Volatile.Read(ref transport)
                ?? throw new ObjectDisposedException(nameof(RouterOsSession));
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(limit);
            try
            {
                T result = await read(connection.Stream, deadline.Token).ConfigureAwait(false);
                deadline.Token.ThrowIfCancellationRequested();
                return result;
            }
            catch (Exception ex)
            {
                Dispose();
                if (deadline.IsCancellationRequested)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new TimeoutException("RouterOS read command deadline exceeded.", ex);
                }
                throw;
            }
        }
        finally { Volatile.Write(ref busy, 0); }
    }

    private static async Task<string> ReadVersionCoreAsync(Stream stream, CancellationToken token)
    {
        var rows = await ReadCommandAsync(stream,
            ["/system/resource/print"u8.ToArray(), "=.proplist=version"u8.ToArray()],
            words => RouterOsInventory.ReadAscii(words, "version", 128, required: true)!, 1, token)
            .ConfigureAwait(false);
        if (rows.Count != 1 || string.IsNullOrWhiteSpace(rows[0]))
            throw new InvalidDataException("RouterOS version response must contain exactly one valid row.");
        return rows[0];
    }

    private static async Task<IReadOnlyList<T>> ReadCommandAsync<T>(Stream stream,
        IReadOnlyList<ReadOnlyMemory<byte>> command, Func<byte[][], T> project,
        int maxRows, CancellationToken token)
    {
        await RouterOsWireCodec.WriteSentenceAsync(stream, command, token).ConfigureAwait(false);
        var reply = await RouterOsReplyReader.ReadAsync(stream, project, maxRows, token).ConfigureAwait(false);
        if (reply.Outcome != RouterOsReplyOutcome.Completed)
            throw new InvalidDataException(reply.Outcome == RouterOsReplyOutcome.Rejected
                ? "RouterOS rejected the read command." : "RouterOS closed the command session.");
        return reply.Rows;
    }

    private static TimeSpan ValidateTimeout(TimeSpan? timeout)
    {
        TimeSpan limit = timeout ?? TimeSpan.FromSeconds(15);
        if (limit <= TimeSpan.Zero || limit > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        return limit;
    }

    private static void ClearWords(byte[][] words)
    {
        foreach (byte[] word in words) CryptographicOperations.ZeroMemory(word);
    }

    public void Dispose() => Interlocked.Exchange(ref transport, null)?.Dispose();
}
