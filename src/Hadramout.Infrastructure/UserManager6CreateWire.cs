using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;

namespace Hadramout.Infrastructure;

internal enum UserManager6CreateWireOutcome { Acknowledged, Indeterminate }
internal sealed record UserManager6CreateWireReceipt(UserManager6CreateWireOutcome Outcome, string? ReturnedId);

// Isolated protocol primitive, not a production dispatcher. Caller must supply an
// authenticated, exclusively held, qualified session and a committed durable claim.
// No retry or other command; even a trap is not proof of no side effect.
// Caller owns and must close the stream on any uncertain outcome/exception.
internal sealed class UserManager6CreateWire(Stream stream)
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private int started;

    internal async Task<UserManager6CreateWireReceipt> CreateDisabledOnceAsync(Guid reservationId,
        string customer, string username, ReadOnlyMemory<byte> password, CancellationToken cancellationToken)
    {
        if (reservationId == Guid.Empty) throw new ArgumentException("Reservation identity required.", nameof(reservationId));
        UserManager6Records.ValidateKey(customer, nameof(customer));
        UserManager6Records.ValidateKey(username, nameof(username));
        ValidatePassword(password.Span);
        cancellationToken.ThrowIfCancellationRequested();
        if (!stream.CanRead || !stream.CanWrite)
            throw new ArgumentException("A duplex RouterOS stream is required.");
        if (Interlocked.CompareExchange(ref started, 1, 0) != 0)
            throw new InvalidOperationException("This creation exchange cannot be repeated.");

        byte[] passwordWord = new byte[10 + password.Length];
        try
        {
            "=password="u8.CopyTo(passwordWord);
            password.Span.CopyTo(passwordWord.AsSpan(10));
            await RouterOsWireCodec.WriteSentenceAsync(stream,
                ["/tool/user-manager/user/add"u8.ToArray(),
                    Utf8.GetBytes("=customer=" + customer),
                    Utf8.GetBytes("=username=" + username),
                    passwordWord, "=disabled=yes"u8.ToArray(),
                    Utf8.GetBytes("=comment=hmk-create:" + reservationId.ToString("N"))],
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (IsUncertainTransportFailure(error))
        {
            return Uncertain();
        }
        finally { CryptographicOperations.ZeroMemory(passwordWord); }

        try
        {
            byte[][] words = await RouterOsWireCodec.ReadSentenceAsync(stream, cancellationToken).ConfigureAwait(false);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ParseCompletion(words);
            }
            finally
            {
                foreach (byte[] word in words) CryptographicOperations.ZeroMemory(word);
            }
        }
        catch (Exception error) when (IsUncertainTransportFailure(error))
        {
            return Uncertain();
        }
    }

    private static UserManager6CreateWireReceipt ParseCompletion(byte[][] words)
    {
        // Accept only a bare completion or a single bounded opaque RouterOS ID.
        // Never interpret trap text, a data row, or a following completion as success.
        if (words.Length == 0 || !words[0].AsSpan().SequenceEqual("!done"u8)) return Uncertain();
        if (words.Length == 1) return new(UserManager6CreateWireOutcome.Acknowledged, null);
        if (words.Length != 2 || !words[1].AsSpan().StartsWith("=ret=*"u8) ||
            words[1].Length is < 7 or > 38) return Uncertain();
        foreach (byte value in words[1].AsSpan(6))
            if (value is not (>= (byte)'0' and <= (byte)'9') and
                not (>= (byte)'A' and <= (byte)'F') and not (>= (byte)'a' and <= (byte)'f'))
                return Uncertain();
        return new(UserManager6CreateWireOutcome.Acknowledged, Encoding.ASCII.GetString(words[1], 5, words[1].Length - 5));
    }

    private static void ValidatePassword(ReadOnlySpan<byte> value)
    {
        // Explicit empty supported locally. Nonempty values must be valid UTF-8;
        // reject ASCII control bytes instead of transmitting ambiguous values.
        if (value.Length > 4096) throw new ArgumentException("Voucher password exceeds supported length.");
        foreach (byte item in value)
            if (item < 32 || item == 127) throw new ArgumentException("Invalid voucher password encoding.");
        try { _ = Utf8.GetCharCount(value); }
        catch (DecoderFallbackException) { throw new ArgumentException("Invalid voucher password encoding."); }
    }

    private static bool IsUncertainTransportFailure(Exception error) =>
        error is IOException or InvalidDataException or SocketException or AuthenticationException
            or OperationCanceledException or ObjectDisposedException;

    private static UserManager6CreateWireReceipt Uncertain() =>
        new(UserManager6CreateWireOutcome.Indeterminate, null);
}
