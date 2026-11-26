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
    internal static async Task<RouterOsSession> ConnectAsync(string host, string certificateName,
        ReadOnlyMemory<byte> username, ReadOnlyMemory<byte> password, int port = 8729,
        TimeSpan? timeout = null, ReadOnlyMemory<byte> trustedRootDer = default,
        CancellationToken cancellationToken = default)
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
                trustedRootDer, deadline.Token).ConfigureAwait(false);
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
                    "=.proplist=customer,username,disabled,actual-profile,download-used,upload-used,uptime-used"u8.ToArray(),
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
