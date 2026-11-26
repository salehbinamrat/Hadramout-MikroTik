using System.Net.Sockets;
using Hadramout.Core;

namespace Hadramout.Infrastructure;

// Recovery is intentionally exposed only for known read-only operations.
// Never replay an authentication failure, protocol failure or mutation.
internal static class RouterOsReadRecovery
{
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

    private static async Task<T> ReadAsync<T>(string host, string certificateName,
        ReadOnlyMemory<byte> username, ReadOnlyMemory<byte> password, int port,
        TimeSpan? timeout, ReadOnlyMemory<byte> trustedRootDer,
        Func<RouterOsSession, CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        TimeSpan limit = timeout ?? TimeSpan.FromSeconds(15);
        if (limit <= TimeSpan.Zero || limit > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(limit);
        try
        {
            for (int attempt = 0; ; attempt++)
            {
                deadline.Token.ThrowIfCancellationRequested();
                // Outside the read-retry catch: TLS, login and initial connection failures
                // are terminal even if they happen while establishing a replacement session.
                using (var session = await RouterOsSession.ConnectAsync(host, certificateName,
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
