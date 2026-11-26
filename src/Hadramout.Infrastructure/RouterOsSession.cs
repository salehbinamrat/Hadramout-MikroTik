using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;

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

    // First bounded read-only command. General command adapters are added separately.
    internal async Task<string> ReadVersionAsync(TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
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
                await RouterOsWireCodec.WriteSentenceAsync(connection.Stream,
                    ["/system/resource/print"u8.ToArray(), "=.proplist=version"u8.ToArray()], deadline.Token)
                    .ConfigureAwait(false);
                var reply = await RouterOsReplyReader.ReadAsync(connection.Stream, ParseVersion,
                    maxRows: 1, deadline.Token).ConfigureAwait(false);
                if (reply.Outcome != RouterOsReplyOutcome.Completed || reply.Rows.Count != 1)
                    throw new InvalidDataException(reply.Outcome switch
                    {
                        RouterOsReplyOutcome.Rejected => "RouterOS rejected the version command.",
                        RouterOsReplyOutcome.Fatal => "RouterOS closed the command session.",
                        _ => "RouterOS version response must contain exactly one row."
                    });
                deadline.Token.ThrowIfCancellationRequested();
                return reply.Rows[0];
            }
            catch (Exception ex)
            {
                // Do not reuse a stream with an uncertain command boundary.
                Dispose();
                if (deadline.IsCancellationRequested)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new TimeoutException("RouterOS version command deadline exceeded.", ex);
                }
                throw;
            }
        }
        finally { Volatile.Write(ref busy, 0); }
    }

    private static string ParseVersion(byte[][] words)
    {
        string? version = null;
        foreach (byte[] word in words.Skip(1))
        {
            if (!word.AsSpan().StartsWith("=version="u8)) continue;
            if (version is not null || word.Length is < 10 or > 137)
                throw new InvalidDataException("Invalid RouterOS version field.");
            for (int j = 9; j < word.Length; j++)
                if (word[j] is < 0x20 or > 0x7E)
                    throw new InvalidDataException("Invalid RouterOS version encoding.");
            version = Encoding.ASCII.GetString(word, 9, word.Length - 9);
            if (string.IsNullOrWhiteSpace(version))
                throw new InvalidDataException("Empty RouterOS version.");
        }
        return version ?? throw new InvalidDataException("Missing RouterOS version field.");
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
