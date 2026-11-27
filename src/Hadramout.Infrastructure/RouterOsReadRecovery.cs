using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Hadramout.Core;

namespace Hadramout.Infrastructure;

// Recovery is intentionally exposed only for known read-only operations.
// Never replay an authentication failure, protocol failure or mutation.
internal static class RouterOsReadRecovery
{
    private static readonly RouterOsReadAdmission Admission = new(8);
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMilliseconds(250);

    internal static Task<string> ReadVersionAsync(string host, string certificateName,
        ReadOnlyMemory<byte> username, ReadOnlyMemory<byte> password, int port = 8729,
        TimeSpan? timeout = null, ReadOnlyMemory<byte> trustedRootDer = default,
        CancellationToken cancellationToken = default) =>
        ReadAsync(host, certificateName, username, password, port, timeout, trustedRootDer,
            (session, token) => session.ReadVersionAsync(timeout, token), cancellationToken);

    internal static Task<RouterOsInventory> DiscoverAsync(string host, string certificateName,
        ReadOnlyMemory<byte> username, ReadOnlyMemory<byte> password, int port = 8729,
        TimeSpan? timeout = null, ReadOnlyMemory<byte> trustedRootDer = default,
        CancellationToken cancellationToken = default) =>
        ReadAsync(host, certificateName, username, password, port, timeout, trustedRootDer,
            (session, token) => session.DiscoverAsync(timeout, token), cancellationToken);

    internal static Task<RouterOsServiceProbe> ProbeServiceAsync(BackendKind backend,
        string host, string certificateName, ReadOnlyMemory<byte> username, ReadOnlyMemory<byte> password,
        int port = 8729, TimeSpan? timeout = null, ReadOnlyMemory<byte> trustedRootDer = default,
        CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(backend)) throw new ArgumentOutOfRangeException(nameof(backend));
        return ReadAsync(host, certificateName, username, password, port, timeout, trustedRootDer,
            (session, token) => session.ProbeServiceAsync(backend, timeout, token), cancellationToken);
    }

    internal static Task<UserManager6Account?> FindUserManager6AccountAsync(string customer, string username,
        string host, string certificateName, ReadOnlyMemory<byte> login, ReadOnlyMemory<byte> password,
        int port = 8729, TimeSpan? timeout = null, ReadOnlyMemory<byte> trustedRootDer = default,
        CancellationToken cancellationToken = default)
    {
        UserManager6Records.ValidateKey(customer, nameof(customer));
        UserManager6Records.ValidateKey(username, nameof(username));
        return ReadAsync(host, certificateName, login, password, port, timeout, trustedRootDer,
            (session, token) => session.FindUserManager6AccountAsync(customer, username, timeout, token),
            cancellationToken);
    }

    internal static Task<UserManager6Profile?> FindUserManager6ProfileAsync(string owner, string name,
        string host, string certificateName, ReadOnlyMemory<byte> login, ReadOnlyMemory<byte> password,
        int port = 8729, TimeSpan? timeout = null, ReadOnlyMemory<byte> trustedRootDer = default,
        CancellationToken cancellationToken = default)
    {
        UserManager6Records.ValidateKey(owner, nameof(owner));
        UserManager6Records.ValidateKey(name, nameof(name));
        return ReadAsync(host, certificateName, login, password, port, timeout, trustedRootDer,
            (session, token) => session.FindUserManager6ProfileAsync(owner, name, timeout, token),
            cancellationToken);
    }

    internal static Task<UserManager6Limitation?> FindUserManager6LimitationAsync(string owner, string name,
        string host, string certificateName, ReadOnlyMemory<byte> login, ReadOnlyMemory<byte> password,
        int port = 8729, TimeSpan? timeout = null, ReadOnlyMemory<byte> trustedRootDer = default,
        CancellationToken cancellationToken = default)
    {
        UserManager6Records.ValidateKey(owner, nameof(owner));
        UserManager6Records.ValidateKey(name, nameof(name));
        return ReadAsync(host, certificateName, login, password, port, timeout, trustedRootDer,
            (session, token) => session.FindUserManager6LimitationAsync(owner, name, timeout, token),
            cancellationToken);
    }

    internal static Task<UserManager6ProfileMappingEvidence?> ReadUserManager6ProfileMappingAsync(
        string owner, string name, string host, string certificateName, ReadOnlyMemory<byte> login,
        ReadOnlyMemory<byte> password, int port = 8729, TimeSpan? timeout = null,
        ReadOnlyMemory<byte> trustedRootDer = default, CancellationToken cancellationToken = default)
    {
        UserManager6Records.ValidateKey(owner, nameof(owner));
        UserManager6Records.ValidateKey(name, nameof(name));
        return ReadAsync(host, certificateName, login, password, port, timeout, trustedRootDer,
            (session, token) => session.ReadUserManager6ProfileMappingAsync(owner, name, timeout, token),
            cancellationToken);
    }

    // Only known reads can enter the bound path. The caller must keep its managed
    // database session alive and quiesce configuration/credential edits during the operation.
    [SupportedOSPlatform("windows")]
    internal static Task<string> ReadBoundVersionAsync(string databasePath, Guid routerId,
        TimeSpan? timeout = null, CancellationToken cancellationToken = default) =>
        ReadBoundAsync(databasePath, routerId, timeout,
            (session, token) => session.ReadVersionAsync(timeout, token), cancellationToken);

    [SupportedOSPlatform("windows")]
    internal static Task<UserManager6Account?> FindBoundUserManager6AccountAsync(string databasePath,
        Guid routerId, string customer, string username, TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        UserManager6Records.ValidateKey(customer, nameof(customer));
        UserManager6Records.ValidateKey(username, nameof(username));
        return ReadBoundAsync(databasePath, routerId, timeout,
            (session, token) => session.FindUserManager6AccountAsync(customer, username, timeout, token),
            cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    internal static Task<UserManager6PreflightEvidence> ReadPreparedUm6PreflightAsync(
        string databasePath, Guid reservationId, TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var scope = new UserManager6CreateJournal(databasePath).ReadPreparedPreflightScope(reservationId);
        return ReadBoundAsync(databasePath, scope.RouterId, timeout,
            (session, token) => session.ReadUserManager6CreationPreflightAsync(
                scope.ProfileOwner, scope.ProfileName, scope.Username, timeout, token),
            cancellationToken, requiredPin: scope.LeafSha256);
    }

    // Read-only recovery; no mutation, no inferred acknowledgement and no replay.
    // Caller must hold the managed generation and quiesce creation/configuration changes.
    [SupportedOSPlatform("windows")]
    internal static async Task<UserManager6RecoveryObservation> ReadBoundUm6RecoveryAsync(
        string databasePath, Guid reservationId, TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var journal = new UserManager6CreateJournal(databasePath);
        var scope = journal.ReadBoundRecoveryScope(reservationId);
        var observed = await ReadBoundAsync(databasePath, scope.RouterId, timeout,
            (session, token) => session.ReadUm6RecoveryObservationAsync(scope, timeout, token),
            cancellationToken, requiredPin: scope.LeafSha256).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (journal.ReadBoundRecoveryScope(reservationId) != scope)
            throw new InvalidOperationException("Local creation evidence changed during review.");
        return new(scope, observed);
    }

    // Explicit review action; the only router operation remains the pinned read.
    // Do not promote journal state, synthesize an acknowledgement or authorize activation.
    [SupportedOSPlatform("windows")]
    internal static async Task<bool> RecordBoundUm6RecoveryAsync(string databasePath,
        Guid reservationId, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        var observation = await ReadBoundUm6RecoveryAsync(databasePath, reservationId, timeout,
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return new UserManager6CreateJournal(databasePath).TryRecordRecoveryObservation(observation);
    }

    [SupportedOSPlatform("windows")]
    private static async Task<T> ReadBoundAsync<T>(string databasePath, Guid routerId, TimeSpan? timeout,
        Func<RouterOsSession, CancellationToken, Task<T>> operation, CancellationToken cancellationToken,
        string? requiredPin = null)
    {
        TimeSpan limit = timeout ?? TimeSpan.FromSeconds(15);
        if (limit <= TimeSpan.Zero || limit > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        cancellationToken.ThrowIfCancellationRequested();
        var target = new RouterTargetStore(databasePath).Read(routerId)
            ?? throw new InvalidOperationException("Router target is not enrolled.");
        if (requiredPin is not null && !string.Equals(requiredPin, target.LeafSha256, StringComparison.Ordinal))
            throw new InvalidOperationException("Prepared creation target no longer matches.");
        cancellationToken.ThrowIfCancellationRequested();
        using var credential = new RouterCredentialStore(databasePath).LoadReadOnly(routerId)
            ?? throw new InvalidOperationException("Router credentials are not configured.");
        cancellationToken.ThrowIfCancellationRequested();
        return await ReadAsync(target.Host, target.CertificateName, credential.UsernameMemory,
            credential.PasswordMemory, target.Port, limit, target.TrustedRootDer, operation,
            cancellationToken, expectedLeafSha256: target.LeafSha256).ConfigureAwait(false);
    }

    private static async Task<T> ReadAsync<T>(string host, string certificateName,
        ReadOnlyMemory<byte> username, ReadOnlyMemory<byte> password, int port,
        TimeSpan? timeout, ReadOnlyMemory<byte> trustedRootDer,
        Func<RouterOsSession, CancellationToken, Task<T>> operation, CancellationToken cancellationToken,
        string? expectedLeafSha256 = null)
    {
        TimeSpan limit = timeout ?? TimeSpan.FromSeconds(15);
        if (limit <= TimeSpan.Zero || limit > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        cancellationToken.ThrowIfCancellationRequested();
        // Hold admission across the complete operation, including reconnect and delay.
        using var admission = Admission.Acquire(host, port, cancellationToken);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(limit);
        try
        {
            for (int attempt = 0; ; attempt++)
            {
                deadline.Token.ThrowIfCancellationRequested();
                // Outside the read-retry catch: TLS, login and initial connection failures
                // are terminal even if they happen while establishing a replacement session.
                using (var session = expectedLeafSha256 is null
                    ? await RouterOsSession.ConnectAsync(host, certificateName,
                        username, password, port, limit, trustedRootDer, deadline.Token).ConfigureAwait(false)
                    : await RouterOsSession.ConnectPinnedAsync(host, certificateName, expectedLeafSha256,
                        username, password, port, limit, trustedRootDer, deadline.Token).ConfigureAwait(false))
                {
                    try
                    {
                        T result = await operation(session, deadline.Token).ConfigureAwait(false);
                        deadline.Token.ThrowIfCancellationRequested();
                        return result;
                    }
                    catch (Exception ex) when (attempt == 0 && !deadline.IsCancellationRequested &&
                        IsTransientReadDisconnect(ex))
                    {
                        // The session also closes itself after a failed read. Leave its scope
                        // before reconnecting. Partial rows are never returned or reused.
                    }
                }
                await Task.Delay(RetryDelay, deadline.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (deadline.IsCancellationRequested)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new TimeoutException("RouterOS read recovery deadline exceeded.", ex);
        }
    }

    // Only explicit end-of-stream or narrowly classified socket disconnects.
    // An arbitrary IOException (including TLS errors) is not a retry signal.
    internal static bool IsTransientReadDisconnect(Exception error)
    {
        if (error is EndOfStreamException) return true;
        SocketException? socket = error switch
        {
            SocketException direct => direct,
            IOException { InnerException: SocketException inner } => inner,
            _ => null
        };
        return socket?.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted
            or SocketError.NetworkReset or SocketError.Shutdown;
    }
}

internal enum RouterOsReadBusyReason { EndpointBusy, CapacityReached }

internal sealed class RouterOsReadBusyException(RouterOsReadBusyReason reason)
    : InvalidOperationException("RouterOS read admission limit reached.")
{
    internal RouterOsReadBusyReason Reason { get; } = reason;
}

// No queued waiters, no unbounded per-router state. A lease covers one complete
// logical read and its possible reconnect. Host aliases are not resolved here.
internal sealed class RouterOsReadAdmission(int capacity)
{
    private readonly int limit = capacity is >= 1 and <= 64 ? capacity :
        throw new ArgumentOutOfRangeException(nameof(capacity));
    private readonly object sync = new();
    private readonly HashSet<(string Host, int Port)> active = [];

    internal IDisposable Acquire(string host, int port, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        var key = (NormalizeHost(host), port);
        lock (sync)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (active.Contains(key))
                throw new RouterOsReadBusyException(RouterOsReadBusyReason.EndpointBusy);
            if (active.Count >= limit)
                throw new RouterOsReadBusyException(RouterOsReadBusyReason.CapacityReached);
            var lease = new Lease(this, key);
            active.Add(key);
            return lease;
        }
    }

    internal static string NormalizeHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || host != host.Trim() ||
            Uri.CheckHostName(host) == UriHostNameType.Unknown)
            throw new ArgumentException("A DNS name or IP address is required.", nameof(host));
        if (IPAddress.TryParse(host, out var address))
            return (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
        return new IdnMapping().GetAscii(host.TrimEnd('.')).ToLowerInvariant();
    }

    private void Release((string Host, int Port) key)
    {
        lock (sync) active.Remove(key);
    }

    private sealed class Lease(RouterOsReadAdmission owner, (string Host, int Port) key) : IDisposable
    {
        private RouterOsReadAdmission? admission = owner;
        public void Dispose() => Interlocked.Exchange(ref admission, null)?.Release(key);
    }
}
